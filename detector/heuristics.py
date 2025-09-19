import ipaddress
import re
from urllib.parse import urlparse, parse_qs


SUSPICIOUS_TLDS = {
    "tk", "ml", "ga", "cf", "gq", "xyz", "top", "work", "click", "club"
}

SHORTENERS = {
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd", "buff.ly", "cutt.ly",
}

PHISH_KEYWORDS = {
    "login", "verify", "update", "secure", "account", "confirm", "bank", "paypal",
    "billing", "unlock", "limited", "urgent", "win", "free", "gift", "bonus",
}


def _is_ip_address(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def _count_subdomains(host: str) -> int:
    return max(0, host.count("."))


def _has_hex_or_encoding(path_query: str) -> bool:
    return bool(re.search(r"%[0-9a-fA-F]{2}", path_query))


def _is_punycode(host: str) -> bool:
    # Any label that starts with xn-- indicates punycode (IDN), often used for lookalikes
    return any(part.startswith("xn--") for part in host.split("."))


def _digit_ratio(host: str) -> float:
    if not host:
        return 0.0
    digits = sum(ch.isdigit() for ch in host)
    return digits / max(1, len(host))


def _query_param_count(parsed) -> int:
    try:
        return sum(len(v) for v in parse_qs(parsed.query, keep_blank_values=True).values())
    except Exception:
        return 0


def analyze_url(url: str) -> dict:
    original_input = url
    working_url = url.strip()

    score = 0
    reasons = []

    # Normalize: leading '@' or similar pasted prefixes (e.g., copied from chat apps)
    leading_ats = 0
    while working_url.startswith("@"):
        leading_ats += 1
        working_url = working_url[1:]
    if leading_ats > 0:
        reasons.append("Leading '@' detected and stripped")

    parsed = urlparse(working_url)
    host = parsed.hostname or ""
    path_query = (parsed.path or "") + ("?" + parsed.query if parsed.query else "")

    # Rule: uses HTTP (not HTTPS)
    if parsed.scheme.lower() != "https":
        score += 10
        reasons.append("Not using HTTPS")

    # Rule: IP address as host
    if _is_ip_address(host):
        score += 25
        reasons.append("Host is an IP address")

    # Rule: contains '@' after scheme/host (often used to obscure real host)
    scheme_sep = working_url.find("://")
    start_idx = scheme_sep + 3 if scheme_sep != -1 else 0
    if "@" in working_url[start_idx:]:
        score += 20
        reasons.append("Contains '@' symbol")

    # Rule: long URL
    if len(url) > 80:
        score += 10
        reasons.append("URL length is long")
    if len(url) > 120:
        score += 10
        reasons.append("URL length is very long")

    # Rule: many subdomains
    sub_count = _count_subdomains(host)
    if sub_count >= 3:
        score += 12
        reasons.append("Too many subdomains")
    if sub_count >= 5:
        score += 8
        reasons.append("Excessive subdomains")

    # Rule: suspicious TLD
    tld_match = re.search(r"\.([a-zA-Z0-9-]{2,})$", host)
    if tld_match and tld_match.group(1).lower() in SUSPICIOUS_TLDS:
        score += 15
        reasons.append("Suspicious TLD")

    # Rule: hyphens in domain
    if "-" in host:
        score += 8
        reasons.append("Hyphens in domain")

    # Rule: punycode / IDN lookalike potential
    if _is_punycode(host):
        score += 20
        reasons.append("Punycode domain (possible lookalike)")

    # Rule: digit-heavy domain labels
    dr = _digit_ratio(host)
    if dr >= 0.3:
        score += 10
        reasons.append("Digit-heavy domain")

    # Rule: long domain name
    if len(host) >= 30:
        score += 5
        reasons.append("Long domain name")

    # Rule: unusual port
    if parsed.port and parsed.port not in {80, 443}:
        score += 5
        reasons.append("Unusual port")

    # Rule: URL shortener domains
    if host.lower() in SHORTENERS:
        score += 20
        reasons.append("Known URL shortener")

    # Rule: phishing-related keywords
    keyword_hits = [kw for kw in PHISH_KEYWORDS if kw in url.lower()]
    if keyword_hits:
        score += min(20, 5 * len(keyword_hits))
        reasons.append("Suspicious keywords: " + ", ".join(sorted(set(keyword_hits))))

    # Rule: encoded characters
    if _has_hex_or_encoding(path_query):
        score += 5
        reasons.append("Encoded characters in path/query")

    # Rule: many query params
    qp_count = _query_param_count(parsed)
    if qp_count >= 5:
        score += 5
        reasons.append("Many query parameters")

    # Normalize to 0..100
    score = max(0, min(100, score))

    if score >= 60:
        label = "phishing"
    elif score >= 25:
        label = "suspicious"
    else:
        label = "no_risk_detected"

    return {
        "input": url,
        "host": host,
        "score": score,
        "label": label,
        "reasons": reasons,
    }


