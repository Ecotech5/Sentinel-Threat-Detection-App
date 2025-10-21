import os
import re
import json
import requests
from datetime import datetime
from dotenv import load_dotenv
import ipaddress

load_dotenv()

VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
URLSCAN_API_KEY = os.getenv("URLSCAN_API_KEY")
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")

# --- Utility Functions ---
def normalize_url(url: str) -> str:
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    return url.strip()

def extract_domain(url: str) -> str:
    return re.sub(r"https?://(www\.)?", "", url).split("/")[0]

def extract_ip(domain: str):
    try:
        ip = ipaddress.ip_address(domain)
        return str(ip)
    except ValueError:
        return None


# --- Main Analysis ---
def analyze_url(url: str, run_apis=True):
    url = normalize_url(url)
    domain = extract_domain(url)
    ip = extract_ip(domain)

    result = {
        "url": url,
        "normalized": url,
        "domain": domain,
        "timestamp": datetime.utcnow().isoformat(),
        "heuristics": [],
        "api_findings": [],
        "risk_score": 0,
    }

    # --- Heuristic Rules ---
    if any(word in domain.lower() for word in ["login", "verify", "secure", "update"]):
        result["heuristics"].append({"rule": "Suspicious keyword in domain", "points": 3})
        result["risk_score"] += 3

    if len(domain) > 30:
        result["heuristics"].append({"rule": "Long domain name", "points": 2})
        result["risk_score"] += 2

    if "-" in domain:
        result["heuristics"].append({"rule": "Domain contains hyphen (possible impersonation)", "points": 2})
        result["risk_score"] += 2

    if not url.startswith("https://"):
        result["heuristics"].append({"rule": "Unsecured HTTP connection", "points": 2})
        result["risk_score"] += 2

    # --- External API Integrations ---
    if run_apis:
        result["api_findings"].append(check_virustotal(url))
        result["api_findings"].append(check_urlscan(url))
        if ip:  # only check AbuseIPDB if it's an IP
            result["api_findings"].append(check_abuseipdb(ip))

    # --- Threat Intelligence Summary ---
    vt_data = next((x for x in result["api_findings"] if x["api"] == "VirusTotal"), None)
    if vt_data and vt_data.get("raw") and "stats" in vt_data["raw"]:
        stats = vt_data["raw"]["stats"]
        positives = stats.get("malicious", 0)
        if positives > 0:
            result["heuristics"].append({
                "rule": f"Flagged by {positives} VirusTotal engines",
                "points": positives * 2
            })
            result["risk_score"] += positives * 2

    abuse_data = next((x for x in result["api_findings"] if x["api"] == "AbuseIPDB"), None)
    if abuse_data and abuse_data.get("raw"):
        confidence = abuse_data["raw"].get("abuseConfidenceScore", 0)
        if confidence > 50:
            result["heuristics"].append({
                "rule": f"AbuseIPDB confidence score {confidence}",
                "points": confidence // 10
            })
            result["risk_score"] += confidence // 10

    # --- Verdict ---
    if result["risk_score"] < 5:
        verdict = "SAFE"
    elif result["risk_score"] < 10:
        verdict = "SUSPICIOUS"
    else:
        verdict = "MALICIOUS"

    result["verdict"] = verdict
    return result


# --- VirusTotal API ---
def check_virustotal(url: str):
    if not VIRUSTOTAL_API_KEY:
        return {"api": "VirusTotal", "message": "No API key", "raw": None}

    vt_url = "https://www.virustotal.com/api/v3/urls"
    try:
        resp = requests.post(vt_url, headers={"x-apikey": VIRUSTOTAL_API_KEY}, data={"url": url})
        if resp.status_code == 200:
            url_id = resp.json()["data"]["id"]
            report = requests.get(
                f"https://www.virustotal.com/api/v3/analyses/{url_id}",
                headers={"x-apikey": VIRUSTOTAL_API_KEY}
            )
            if report.status_code == 200:
                data = report.json()
                stats = data.get("data", {}).get("attributes", {}).get("stats", {})
                return {"api": "VirusTotal", "message": "OK", "raw": {"stats": stats}}
        return {"api": "VirusTotal", "message": f"Response {resp.status_code}", "raw": None}
    except Exception as e:
        return {"api": "VirusTotal", "message": f"Request failed: {e}", "raw": None}


# --- URLScan API ---
def check_urlscan(url: str):
    if not URLSCAN_API_KEY:
        return {"api": "URLScan", "message": "No API key", "raw": None}

    try:
        headers = {"API-Key": URLSCAN_API_KEY, "Content-Type": "application/json"}
        payload = {"url": url}
        resp = requests.post("https://urlscan.io/api/v1/scan/", headers=headers, json=payload)
        if resp.status_code in (200, 201):
            return {"api": "URLScan", "message": "OK", "raw": resp.json()}
        return {"api": "URLScan", "message": f"Response {resp.status_code}", "raw": None}
    except Exception as e:
        return {"api": "URLScan", "message": f"Request failed: {e}", "raw": None}


# --- AbuseIPDB API ---
def check_abuseipdb(ip: str):
    if not ABUSEIPDB_API_KEY:
        return {"api": "AbuseIPDB", "message": "No API key", "raw": None}

    try:
        headers = {"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"}
        url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90"
        resp = requests.get(url, headers=headers)

        if resp.status_code == 200:
            data = resp.json().get("data", {})
            return {"api": "AbuseIPDB", "message": "OK", "raw": data}
        return {"api": "AbuseIPDB", "message": f"Response {resp.status_code}", "raw": None}
    except Exception as e:
        return {"api": "AbuseIPDB", "message": f"Request failed: {e}", "raw": None}


def result_to_json(result, indent=2):
    return json.dumps(result, indent=indent)
