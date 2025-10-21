# core/analyzer.py
from __future__ import annotations
import os
import re
import time
import json
import socket
import logging
from datetime import datetime
from typing import Dict, Any, Optional, List

import requests
from requests.exceptions import RequestException
from dotenv import load_dotenv

from .utils import normalize_url, extract_domain, extract_ip, clamp_int

load_dotenv()

VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "") or None
URLSCAN_API_KEY = os.getenv("URLSCAN_API_KEY", "") or None
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "") or None

MAX_TIMEOUT = 12

logger = logging.getLogger("sentinel.analyzer")
if not logger.handlers:
    h = logging.StreamHandler()
    h.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
    logger.addHandler(h)
logger.setLevel(os.getenv("SENTINEL_LOG_LEVEL", "INFO"))


# ---------- Heuristics ----------
SUSPICIOUS_TLDS = (".xyz", ".top", ".info", ".tk", ".ml", ".ga", ".cf")
SENSITIVE_TERMS = ("login", "signin", "account", "verify", "secure", "update", "bank", "password")
COMMON_BRANDS = ("paypal", "google", "facebook", "apple", "amazon", "microsoft", "chase", "linkedin", "dropbox")


def _basic_heuristics(url: str, domain: str) -> (List[Dict[str, Any]], int):
    findings = []
    score = 0

    # IP address as host
    host = domain.split(":")[0]
    try:
        import ipaddress
        ipaddress.ip_address(host)
        findings.append({"text": "Host is an IP address", "points": 3})
        score += 3
    except Exception:
        pass

    # suspicious tld
    for t in SUSPICIOUS_TLDS:
        if domain.endswith(t):
            findings.append({"text": f"Suspicious TLD: {t}", "points": 2})
            score += 2
            break

    # brand impersonation (conservative)
    for brand in COMMON_BRANDS:
        if brand in domain and domain != f"{brand}.com":
            findings.append({"text": f"Brand token '{brand}' in domain (possible impersonation)", "points": 3})
            score += 3
            break

    # sensitive terms
    for s in SENSITIVE_TERMS:
        if s in url.lower():
            findings.append({"text": f"Sensitive keyword in URL: {s}", "points": 2})
            score += 2
            break

    # punycode
    if "xn--" in domain:
        findings.append({"text": "Punycode / IDN detected", "points": 2})
        score += 2

    # length/dashes
    base = domain.split(".")[0]
    if len(base) <= 3 and not base.isalpha():
        findings.append({"text": "Very short or non-alphabetic domain label", "points": 2})
        score += 2

    if url.lower().startswith("http://"):
        findings.append({"text": "Uses HTTP (not HTTPS)", "points": 2})
        score += 2

    return findings, score


# ---------- VirusTotal ----------
def _virustotal_check(url: str) -> Dict[str, Any]:
    if not VIRUSTOTAL_API_KEY:
        return {"api": "VirusTotal", "message": "Skipped (no API key)", "raw": None}
    try:
        # submit url
        resp = requests.post("https://www.virustotal.com/api/v3/urls",
                             headers={"x-apikey": VIRUSTOTAL_API_KEY},
                             data={"url": url},
                             timeout=MAX_TIMEOUT)
        # handle typical codes
        if resp.status_code not in (200, 201):
            return {"api": "VirusTotal", "message": f"Response {resp.status_code}", "raw": None}
        url_id = resp.json()["data"]["id"]
        # small delay and fetch analysis
        time.sleep(1.2)
        report = requests.get(f"https://www.virustotal.com/api/v3/analyses/{url_id}",
                              headers={"x-apikey": VIRUSTOTAL_API_KEY}, timeout=MAX_TIMEOUT)
        if report.status_code != 200:
            return {"api": "VirusTotal", "message": f"Report {report.status_code}", "raw": None}
        data = report.json()
        # attempt to extract stats
        attrs = data.get("data", {}).get("attributes", {})
        stats = attrs.get("stats") or attrs.get("last_analysis_stats") or {}
        rep = attrs.get("reputation")
        categories = attrs.get("categories") or {}
        return {"api": "VirusTotal", "message": "OK", "raw": {"stats": stats, "reputation": rep, "categories": categories}}
    except RequestException as e:
        logger.debug("VirusTotal request failed: %s", e)
        return {"api": "VirusTotal", "message": f"Request failed: {e}", "raw": None}
    except Exception as e:
        logger.exception("VirusTotal error")
        return {"api": "VirusTotal", "message": str(e), "raw": None}


# ---------- URLScan ----------
def _urlscan_check(url: str) -> Dict[str, Any]:
    if not URLSCAN_API_KEY:
        return {"api": "URLScan", "message": "Skipped (no API key)", "raw": None}
    try:
        headers = {"API-Key": URLSCAN_API_KEY, "Content-Type": "application/json"}
        resp = requests.post("https://urlscan.io/api/v1/scan/", headers=headers, json={"url": url}, timeout=MAX_TIMEOUT)
        if resp.status_code in (200, 201):
            return {"api": "URLScan", "message": "OK", "raw": resp.json()}
        return {"api": "URLScan", "message": f"Response {resp.status_code}", "raw": None}
    except RequestException as e:
        logger.debug("URLScan request failed: %s", e)
        return {"api": "URLScan", "message": f"Request failed: {e}", "raw": None}
    except Exception as e:
        logger.exception("URLScan error")
        return {"api": "URLScan", "message": str(e), "raw": None}


# ---------- AbuseIPDB ----------
def _abuseipdb_check(ip: str) -> Dict[str, Any]:
    if not ABUSEIPDB_API_KEY:
        return {"api": "AbuseIPDB", "message": "Skipped (no API key)", "raw": None, "points": 0}
    try:
        url = "https://api.abuseipdb.com/api/v2/check"
        headers = {"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"}
        params = {"ipAddress": ip, "maxAgeInDays": 90}
        resp = requests.get(url, headers=headers, params=params, timeout=MAX_TIMEOUT)
        if resp.status_code != 200:
            return {"api": "AbuseIPDB", "message": f"Response {resp.status_code}", "raw": None, "points": 0}
        data = resp.json().get("data", {})
        score = data.get("abuseConfidenceScore", 0)
        reports = data.get("totalReports", 0)
        cats = data.get("categories", [])
        # convert categories numeric bitmask to approximated labels (AbuseIPDB category mapping)
        # For now store raw categories (integers)
        points = min(8, score // 12)  # scale to 0..8
        return {"api": "AbuseIPDB", "message": f"{reports} reports | score {score}", "raw": data, "points": points}
    except RequestException as e:
        logger.debug("AbuseIPDB failed: %s", e)
        return {"api": "AbuseIPDB", "message": f"Request failed: {e}", "raw": None, "points": 0}
    except Exception as e:
        logger.exception("AbuseIPDB error")
        return {"api": "AbuseIPDB", "message": str(e), "raw": None, "points": 0}


# ---------- Orchestrator ----------
def analyze(url: str, run_apis: bool = True, include_urlscan: bool = True, include_abuseipdb: bool = True) -> Dict[str, Any]:
    """
    Run heuristics + optional APIs. Returns a structured dict with:
      url, normalized, domain, timestamp, heuristics, api_findings, risk_score (0..10), verdict, intelligence
    """
    normalized = normalize_url(url)
    domain = extract_domain(normalized)
    timestamp = datetime.utcnow().isoformat() + "Z"

    heuristics, heuristic_score = _basic_heuristics(normalized, domain)

    api_findings = []
    intelligence = {"positives": 0, "total": 0, "reputation": None, "categories": []}
    abuse_points = 0

    # run APIs concurrently? currently sequential but resilient
    if run_apis:
        vt = _virustotal_check(normalized)
        api_findings.append(vt)
        if vt.get("raw") and vt["raw"].get("stats"):
            stats = vt["raw"]["stats"]
            positives = int(stats.get("malicious", 0))
            total = sum(int(v or 0) for v in stats.values())
            intelligence["positives"] = positives
            intelligence["total"] = total
            intelligence["reputation"] = vt["raw"].get("reputation")
            cats = vt["raw"].get("categories")
            if isinstance(cats, dict):
                intelligence["categories"] = list(cats.values())
            else:
                intelligence["categories"] = cats or []

        if include_urlscan:
            us = _urlscan_check(normalized)
            api_findings.append(us)

        # AbuseIPDB: attempt to resolve domain -> IP (no reverse DNS) and then check
        if include_abuseipdb:
            ip = None
            try:
                ip = socket.gethostbyname(domain)
            except Exception:
                ip = None
            if ip:
                abuse = _abuseipdb_check(ip)
                api_findings.append(abuse)
                abuse_points = abuse.get("points", 0)

    # combine scores
    vt_points = min(intelligence.get("positives", 0) * 2, 8)
    score = heuristic_score + vt_points + abuse_points
    score = clamp_int(score, 0, 10)

    if score <= 3:
        verdict = "SAFE"
    elif score <= 6:
        verdict = "SUSPICIOUS"
    else:
        verdict = "MALICIOUS"

    result = {
        "url": url,
        "normalized": normalized,
        "domain": domain,
        "timestamp": timestamp,
        "heuristics": heuristics,
        "heuristic_score": heuristic_score,
        "api_findings": api_findings,
        "risk_score": score,
        "verdict": verdict,
        "intelligence": intelligence,
    }
    return result


def result_to_json(res: dict, indent: int = 2) -> str:
    return json.dumps(res, indent=indent, default=str)
