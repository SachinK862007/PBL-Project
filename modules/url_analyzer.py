"""Heuristic URL analysis: structure, domain and impersonation signals.

The analyser never visits the address. It only reads the URL as text, which is
why it is safe to run against suspected phishing links.
"""

from __future__ import annotations

import difflib
import re
from urllib.parse import urlsplit

# Brands that phishing pages most often imitate.
BRANDS = {
    "amazon", "paypal", "google", "microsoft", "apple", "netflix", "facebook",
    "instagram", "whatsapp", "linkedin", "dropbox", "adobe", "steam", "binance",
    "coinbase", "telegram", "twitter", "github", "sbi", "hdfc", "icici", "axis",
    "flipkart", "irctc", "paytm", "phonepe", "dhl", "fedex", "usps", "chase",
    "wellsfargo", "bankofamerica", "outlook", "office365", "icloud", "spotify",
    "youtube", "tiktok", "snapchat", "reddit", "zoom", "slack", "discord",
    "samsung", "alibaba", "aliexpress", "booking", "airbnb", "uber", "epicgames",
}

MULTI_SUFFIXES = {
    "co.in", "co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au", "co.nz",
    "co.jp", "co.za", "com.br", "com.mx", "com.sg", "com.tr", "co.kr", "gov.in",
    "ac.in", "edu.in", "nic.in", "com.pk", "com.ng", "co.ke",
}

RISKY_TLDS = {
    "zip", "mov", "top", "xyz", "loan", "click", "work", "gq", "tk", "ml", "cf",
    "ga", "review", "country", "kim", "cricket", "science", "party", "date",
    "faith", "stream", "racing", "win", "bid", "surf", "monster", "quest",
}

SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "rb.gy", "cutt.ly", "is.gd",
    "tiny.cc", "shorturl.at", "rebrand.ly", "ow.ly", "buff.ly",
}

FREE_HOSTS = {
    "000webhostapp.com", "weebly.com", "wixsite.com", "blogspot.com",
    "github.io", "netlify.app", "vercel.app", "pages.dev", "glitch.me",
    "herokuapp.com", "web.app", "firebaseapp.com", "r2.dev",
}

CREDENTIAL_WORDS = {
    "login", "signin", "verify", "verification", "secure", "security", "account",
    "update", "confirm", "password", "wallet", "billing", "invoice", "otp",
    "kyc", "unlock", "recover", "reset", "suspend", "authenticate", "credential",
}

LEET = str.maketrans({
    "0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "6": "g",
    "7": "t", "8": "b", "9": "g", "$": "s", "@": "a",
})


def _split_host(host: str) -> tuple[str, str, str]:
    """Return (registrable_domain, main_label, tld) without external packages."""
    labels = [label for label in host.split(".") if label]
    if len(labels) <= 2:
        domain = host
        main = labels[-2] if len(labels) == 2 else labels[0]
        tld = labels[-1] if labels else ""
        return domain, main, tld

    last_two = ".".join(labels[-2:])
    if last_two in MULTI_SUFFIXES:
        return ".".join(labels[-3:]), labels[-3], last_two
    return ".".join(labels[-2:]), labels[-2], labels[-1]


def _finding(label: str, detail: str, weight: int, severity: str) -> dict:
    return {"label": label, "detail": detail, "weight": weight, "severity": severity}


def _brand_signal(main_label: str, domain: str, tld: str) -> dict | None:
    """Detect look-alike and embedded brand names in the registrable domain."""
    tokens = [token for token in re.split(r"[-_.]", main_label) if token]
    deleet = [token.translate(LEET) for token in tokens]
    whole = main_label.translate(LEET)

    for token, plain in zip(tokens, deleet):
        if token in BRANDS and f"{token}.{tld}" != domain:
            return _finding(
                "Brand impersonation",
                f"'{token}' is a well-known brand, but this is '{domain}', not {token}.{tld}.",
                30,
                "high",
            )
        if plain in BRANDS and token != plain and len(token) >= 5:
            return _finding(
                "Look-alike spelling",
                f"'{main_label}' imitates the brand '{plain}' by swapping letters for digits or symbols.",
                30,
                "high",
            )

    if whole in BRANDS and whole != main_label and len(main_label) >= 5:
        return _finding(
            "Look-alike spelling",
            f"'{main_label}' reads as '{whole}' when digit substitutions are undone.",
            30,
            "high",
        )

    if len(main_label) >= 5:
        for brand in BRANDS:
            if abs(len(brand) - len(main_label)) > 2:
                continue
            ratio = difflib.SequenceMatcher(None, main_label, brand).ratio()
            if 0.86 <= ratio < 1.0:
                return _finding(
                    "Misspelled brand domain",
                    f"'{main_label}' is one small typo away from '{brand}'.",
                    24,
                    "high",
                )
    return None


def analyze(url: str) -> dict:
    """Analyse a validated URL and return the extracted evidence."""
    parts = urlsplit(url)
    host = (parts.hostname or "").lower()
    domain, main_label, tld = _split_host(host)
    path = parts.path or ""
    query = parts.query or ""
    findings: list[dict] = []

    # --- Host level checks -------------------------------------------------
    if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", host):
        findings.append(_finding(
            "Raw IP address host",
            "Legitimate services use domain names; a bare IP hides who operates the site.",
            26, "high"))
    if host.startswith("xn--") or ".xn--" in host:
        findings.append(_finding(
            "Punycode domain",
            "The domain uses punycode, a common way to disguise look-alike characters.",
            22, "high"))
    if "@" in parts.netloc:
        findings.append(_finding(
            "Misleading '@' in address",
            "Everything before '@' is ignored by the browser, so the real destination is hidden.",
            28, "high"))

    brand = _brand_signal(main_label, domain, tld)
    if brand:
        findings.append(brand)

    # --- Domain composition ------------------------------------------------
    if main_label.count("-") >= 2:
        findings.append(_finding(
            "Multi-hyphen domain",
            f"'{main_label}' uses {main_label.count('-')} hyphens, typical of throwaway phishing domains.",
            10, "medium"))
    if host.count(".") >= 3 and not re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", host):
        findings.append(_finding(
            "Deep subdomain chain",
            "Several subdomains push the real domain out of view in a small address bar.",
            10, "medium"))
    if len(host) > 34:
        findings.append(_finding(
            "Very long hostname",
            f"The hostname is {len(host)} characters long, which makes it hard to read at a glance.",
            6, "low"))
    if tld in RISKY_TLDS:
        findings.append(_finding(
            "High-abuse domain ending",
            f"'.{tld}' is a top-level domain with a high share of abuse reports.",
            14, "medium"))
    if domain in SHORTENERS:
        findings.append(_finding(
            "Link shortener",
            "The real destination is hidden behind a redirect.",
            14, "medium"))
    if domain in FREE_HOSTS:
        findings.append(_finding(
            "Free hosting domain",
            "Free subdomain hosting is cheap to create and often used for short-lived phishing pages.",
            10, "medium"))

    # --- Credential bait ---------------------------------------------------
    haystack = f"{host}{path}{query}".lower()
    hits = sorted({word for word in CREDENTIAL_WORDS if word in haystack})
    if hits:
        shown = ", ".join(hits[:4])
        findings.append(_finding(
            "Credential-bait wording",
            f"The address asks for trust or data with: {shown}.",
            min(8 * len(hits), 16), "medium"))

    # --- Transport and structure ------------------------------------------
    if parts.scheme == "http":
        findings.append(_finding(
            "No HTTPS",
            "The connection would be unencrypted, so anything submitted could be read in transit.",
            8, "medium"))
    if len(url) > 90:
        findings.append(_finding(
            "Long URL",
            f"The URL is {len(url)} characters long, which is often used to bury the real target.",
            5, "low"))
    if "%" in url:
        findings.append(_finding(
            "Percent-encoded characters",
            "Encoding can hide the true characters of a link from a quick reading.",
            6, "low"))
    try:
        port = parts.port
    except ValueError:
        port = None
    if port and port not in (80, 443):
        findings.append(_finding(
            "Unusual port",
            f"The link points to port {port} instead of the usual 80 or 443.",
            8, "medium"))

    # A look-alike brand domain that also asks for credentials is the classic
    # phishing login page: two weak-looking traits that become decisive together.
    labels = {item["label"] for item in findings}
    impersonating = labels & {"Look-alike spelling", "Brand impersonation", "Misspelled brand domain"}
    if impersonating and "Credential-bait wording" in labels:
        findings.append(_finding(
            "Login-impersonation pattern",
            "An imitation of a brand name combined with credential wording is the structure of a fake login page.",
            25, "high"))

    score = min(100, sum(item["weight"] for item in findings))
    return {
        "url": url,
        "scheme": parts.scheme,
        "host": host,
        "domain": domain,
        "main_label": main_label,
        "tld": tld,
        "path": path,
        "findings": sorted(findings, key=lambda item: item["weight"], reverse=True),
        "score": score,
    }
