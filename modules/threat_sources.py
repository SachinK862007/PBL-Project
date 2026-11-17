"""Threat-intelligence lookups.

Every source is optional. A source that is unconfigured, slow or broken is
reported as such, and the scan is marked incomplete — an unavailable check is
never treated as proof that a URL is safe.
"""

from __future__ import annotations

import os

import requests

TIMEOUT = 6

SOURCES = [
    ("PhishTank", "PHISHTANK_FEED"),
    ("URLhaus", "URLHAUS_AUTH_KEY"),
    ("OpenPhish", "OPENPHISH_FEED"),
    ("Google Safe Browsing", "GOOGLE_SAFE_BROWSING_KEY"),
]


def _env(name: str) -> str:
    return (os.environ.get(name) or "").strip()


def _result(source: str, status: str, detail: str, matched: bool = False) -> dict:
    return {"source": source, "status": status, "detail": detail, "matched": matched}


def _check_feed(source: str, feed_url: str, url: str) -> dict:
    """Compare the URL against a plain-text feed (one entry per line)."""
    if not feed_url:
        return _result(source, "not_configured",
                       f"Set {source.upper().replace(' ', '_')}_FEED to compare against this list.")
    try:
        response = requests.get(feed_url, timeout=TIMEOUT)
        response.raise_for_status()
    except requests.RequestException as exc:
        return _result(source, "error", f"Feed could not be reached ({type(exc).__name__}).")

    needle = url.lower().rstrip("/")
    for line in response.text.splitlines():
        line = line.strip().lower()
        if not line or line.startswith("#"):
            continue
        if line.rstrip("/") == needle:
            return _result(source, "match", "This exact URL appears in the feed.", True)
    return _result(source, "clear", "No match for this URL in the downloaded feed.")


def _check_urlhaus(url: str) -> dict:
    key = _env("URLHAUS_AUTH_KEY")
    if not key:
        return _result("URLhaus", "not_configured", "Set URLHAUS_AUTH_KEY to query the URLhaus API.")
    try:
        response = requests.post(
            "https://urlhaus-api.abuse.ch/v1/url/",
            data={"url": url},
            headers={"Auth-Key": key},
            timeout=TIMEOUT,
        )
        response.raise_for_status()
        payload = response.json()
    except (requests.RequestException, ValueError) as exc:
        return _result("URLhaus", "error", f"API call failed ({type(exc).__name__}).")

    if payload.get("query_status") == "ok":
        return _result("URLhaus", "match", "URLhaus reports this address as a known threat.", True)
    return _result("URLhaus", "clear", "URLhaus returned no entry for this address.")


def _check_safe_browsing(url: str) -> dict:
    key = _env("GOOGLE_SAFE_BROWSING_KEY")
    if not key:
        return _result("Google Safe Browsing", "not_configured",
                       "Set GOOGLE_SAFE_BROWSING_KEY to enable Safe Browsing lookups.")
    body = {
        "client": {"clientId": "securebrowse", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}],
        },
    }
    try:
        response = requests.post(
            f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={key}",
            json=body,
            timeout=TIMEOUT,
        )
        response.raise_for_status()
        payload = response.json()
    except (requests.RequestException, ValueError) as exc:
        return _result("Google Safe Browsing", "error", f"API call failed ({type(exc).__name__}).")

    matches = payload.get("matches") or []
    if matches:
        kinds = ", ".join(sorted({match.get("threatType", "THREAT") for match in matches}))
        return _result("Google Safe Browsing", "match", f"Listed as unsafe: {kinds}.", True)
    return _result("Google Safe Browsing", "clear", "No unsafe match reported for this URL.")


def check_all(url: str) -> list[dict]:
    """Query every configured source. Unconfigured sources return immediately."""
    return [
        _check_feed("PhishTank", _env("PHISHTANK_FEED"), url),
        _check_urlhaus(url),
        _check_feed("OpenPhish", _env("OPENPHISH_FEED"), url),
        _check_safe_browsing(url),
    ]


def status_snapshot() -> list[dict]:
    """Configuration state of each source, for the site's status list."""
    snapshot = []
    for name, env_name in SOURCES:
        configured = bool(_env(env_name))
        snapshot.append({
            "name": name,
            "env": env_name,
            "configured": configured,
            "status": "Ready" if configured else "Needs key",
        })
    return snapshot
