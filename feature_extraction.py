"""
feature_extraction.py
Extracts lexical + structural features directly from a URL string.
No network calls required — every feature is computed from the URL text
itself, so the exact same function is used to build the training set
and to score a URL live. That guarantees train/predict consistency.
"""
import math
import re
from urllib.parse import urlparse

SHORTENERS = (
    r"bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|"
    r"is\.gd|cli\.gs|tiny\.cc|url4\.eu|su\.pr|snipurl\.com|short\.to|"
    r"budurl\.com|kl\.am|wp\.me|rubyurl\.com|bit\.do|lnkd\.in|db\.tt|"
    r"qr\.ae|adf\.ly|cur\.lv|v\.gd|po\.st"
)

SUSPICIOUS_WORDS = (
    "login", "verify", "secure", "account", "update", "confirm", "signin",
    "sign-in", "banking", "bank", "password", "credential", "wallet",
    "unlock", "suspend", "webscr", "alert", "recover", "billing",
)

SUSPICIOUS_TLDS = (
    "tk", "ml", "ga", "cf", "gq", "xyz", "top", "icu", "click", "work",
    "loan", "win", "men", "date", "review", "country", "stream", "download",
)

FEATURE_ORDER = [
    "url_length", "hostname_length", "path_length", "num_dots",
    "num_hyphens", "num_at", "num_digits", "num_subdomains",
    "num_special_chars", "has_ip", "has_https", "is_shortener",
    "has_suspicious_word", "has_suspicious_tld", "digit_ratio", "entropy",
]


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    length = len(s)
    return -sum((c / length) * math.log2(c / length) for c in freq.values())


def has_ip_address(hostname: str) -> int:
    pattern = r"^(\d{1,3}\.){3}\d{1,3}$"
    return 1 if re.match(pattern, hostname) else 0


def extract_features(url: str, use_network: bool = False) -> dict:
    """
    use_network is accepted for backward compatibility with the API but
    ignored — all features here are network-free by design.
    """
    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    parsed = urlparse(url)
    hostname = (parsed.netloc.split(":")[0] or "").lower()
    path = parsed.path or ""
    full = url.lower()

    labels = hostname.split(".") if hostname else []
    # subdomain count: everything before the registrable domain (rough heuristic)
    num_subdomains = max(len(labels) - 2, 0)

    digits = sum(ch.isdigit() for ch in url)
    specials = sum(1 for ch in url if ch in "!$%^&*()_+={}[]|\\:;\"'<>,~`")

    tld = labels[-1] if labels else ""

    features = {
        "url_length": len(url),
        "hostname_length": len(hostname),
        "path_length": len(path),
        "num_dots": url.count("."),
        "num_hyphens": url.count("-"),
        "num_at": url.count("@"),
        "num_digits": digits,
        "num_subdomains": num_subdomains,
        "num_special_chars": specials,
        "has_ip": has_ip_address(hostname),
        "has_https": 1 if parsed.scheme == "https" else 0,
        "is_shortener": 1 if re.search(SHORTENERS, full) else 0,
        "has_suspicious_word": 1 if any(w in full for w in SUSPICIOUS_WORDS) else 0,
        "has_suspicious_tld": 1 if tld in SUSPICIOUS_TLDS else 0,
        "digit_ratio": round(digits / len(url), 4) if url else 0,
        "entropy": round(_shannon_entropy(hostname), 4),
    }

    return {k: features[k] for k in FEATURE_ORDER}
