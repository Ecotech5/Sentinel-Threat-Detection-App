import re
import ipaddress

def normalize_url(url: str) -> str:
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    return url.strip()

def extract_domain(url: str) -> str:
    return re.sub(r"https?://(www\.)?", "", url).split("/")[0]

def extract_ip(domain: str) -> str | None:
    try:
        ip = ipaddress.ip_address(domain)
        return str(ip)
    except ValueError:
        return None

def clamp_int(value: int, min_value: int, max_value: int) -> int:
    return max(min_value, min(value, max_value))
