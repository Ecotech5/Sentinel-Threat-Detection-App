# core/utils.py
import re
import ipaddress
from typing import Optional

def normalize_url(url: str) -> str:
    if not isinstance(url, str) or not url.strip():
        raise ValueError("Empty URL")
    u = url.strip()
    if not u.startswith(("http://", "https://")):
        u = "https://" + u
    return u

def extract_domain(url: str) -> str:
    # remove scheme and path
    u = re.sub(r"^https?://", "", url, flags=re.I)
    return u.split("/")[0].lower()

def extract_ip(host: str) -> Optional[str]:
    try:
        # if host is IP, return it, else try resolve numeric (no DNS resolution here)
        ipaddress.ip_address(host)
        return host
    except Exception:
        return None

def clamp_int(v: int, lo=0, hi=10) -> int:
    return max(lo, min(hi, int(v)))
