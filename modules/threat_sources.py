"""Threat-intelligence lookups across feeds and APIs.

Every source reports its own state. A source that is unconfigured, unsynced or
broken is reported as such, and the scan is marked incomplete — an unavailable
check is never treated as proof that a URL is safe.
"""

from __future__ import annotations

import os

import requests

from . import feeds

TIMEOUT = 8

# Order here must match the order of content.SOURCES on the page.
FEED_SOURCES = [
    {"id": "phishtank", "name": "PhishTank", "target": "feed"},
    {"id": "openphish", "name": "OpenPhish", "target": "feed"},
    {"id": "phishing_db", "name": "Phishing.Database", "target": "feed"},
]
API_SOURCES = {"urlhaus", "safe_browsing"}


def _env(name: str) -> str:
    return (os.environ.get(name) or "").strip()


def _result(source: str, status: str, detail: str, matched: bool = False, **extra) -> dict:
    payload = {"source": source, "status": status, "detail": detail, "matched": matched}
    payload.update(extra)
    return payload


def _feed_result(feed_id: str, name: str, hit: bool) -> dict:
    spec = feeds.FEEDS[feed_id]
    current = feeds.state(feed_id)
    key_env = spec.get("key_env")

    if key_env and not spec.get("optional_key") and not _env(key_env):
        return _result(name, "not_configured", f"Needs {key_env} in .env, then sync the feed.")
    if current["entries"] == 0:
        if current["status"] == "error":
            return _result(name, "error", current["message"] or "The feed did not download.")
        return _result(name, "not_synced", "Feed not synced yet — use Sync feeds.")

    age = feeds.age_hours(current["last_sync"])
    freshness = f"synced {age:g} h ago" if age is not None else "cached"
    if hit:
        return _result(name, "match", f"This address is listed in the {name} feed ({freshness}).", True)
    return _result(name, "clear", f"No listing in {feeds.entries_label(current['entries'])} entries ({freshness}).")


def _check_urlhaus(url: str) -> dict:
    key = _env("URLHAUS_AUTH_KEY")
    if not key:
        return _result("URLhaus", "not_configured", "Needs URLHAUS_AUTH_KEY (free at auth.abuse.ch).")
    try:
        response = requests.post(
            "https://urlhaus-api.abuse.ch/v1/url/",
            data={"url": url},
            headers={"Auth-Key": key},
            timeout=TIMEOUT,
        )
    except requests.RequestException as exc:
        return _result("URLhaus", "error", f"API call failed ({type(exc).__name__}).")

    if response.status_code in (401, 403):
        return _result("URLhaus", "error", "URLhaus rejected the Auth-Key. Generate a new one at auth.abuse.ch.")
    try:
        payload = response.json()
    except ValueError:
        return _result("URLhaus", "error", "URLhaus returned an unreadable response.")

    status = payload.get("query_status")
    if status == "ok":
        return _result("URLhaus", "match", "URLhaus lists this address as a known malware URL.", True)
    if status == "no_results":
        return _result("URLhaus", "clear", "URLhaus returned no entry for this address.")
    if status == "unknown_auth_key":
        return _result("URLhaus", "error", "URLhaus rejected the Auth-Key.")
    return _result("URLhaus", "error", f"URLhaus answered '{status}'.")


def _check_safe_browsing(url: str) -> dict:
    key = _env("GOOGLE_SAFE_BROWSING_KEY")
    if not key:
        return _result("Google Safe Browsing", "not_configured",
                       "Needs GOOGLE_SAFE_BROWSING_KEY from Google Cloud.")
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
    except requests.RequestException as exc:
        return _result("Google Safe Browsing", "error", f"API call failed ({type(exc).__name__}).")

    if response.status_code in (400, 403):
        return _result("Google Safe Browsing", "error",
                       "Google rejected the API key — check the key and that the API is enabled.")
    try:
        payload = response.json()
    except ValueError:
        return _result("Google Safe Browsing", "error", "Google returned an unreadable response.")

    matches = payload.get("matches") or []
    if matches:
        kinds = ", ".join(sorted({match.get("threatType", "THREAT") for match in matches}))
        return _result("Google Safe Browsing", "match", f"Listed as unsafe: {kinds}.", True)
    return _result("Google Safe Browsing", "clear", "No unsafe match reported for this URL.")


def check_all(url: str, host: str, domain: str) -> list[dict]:
    """Query every source; results keep the page's source order."""
    hits = feeds.lookup(url, [host, domain])
    return [
        _feed_result("phishtank", "PhishTank", hits.get("phishtank", False)),
        _check_urlhaus(url),
        _feed_result("openphish", "OpenPhish", hits.get("openphish", False)),
        _check_safe_browsing(url),
        _feed_result("phishing_db", "Phishing.Database", hits.get("phishing_db", False)),
    ]


def _feed_snapshot(feed_id: str) -> dict:
    spec = feeds.FEEDS[feed_id]
    current = feeds.state(feed_id)
    key_env = spec.get("key_env")
    key_ready = True if spec.get("optional_key") else (bool(_env(key_env)) if key_env else True)
    entries = current["entries"]
    age = feeds.age_hours(current["last_sync"])

    if not key_ready:
        status, label = "needs_key", "Needs key"
    elif current["status"] == "error" and entries == 0:
        status, label = "error", "Error"
    elif entries == 0:
        status, label = "not_synced", "Sync needed"
    elif age is not None and age > feeds.STALE_AFTER_HOURS:
        status, label = "stale", "Stale"
    else:
        status, label = "live", "Live"

    return {
        "id": feed_id,
        "name": spec["name"],
        "kind": "Feed",
        "status": status,
        "label": label,
        "entries": entries,
        "entries_label": feeds.entries_label(entries) if entries else "—",
        "last_sync": current["last_sync"],
        "age_hours": age,
        "message": current["message"],
        "key_env": key_env,
        "key_ready": key_ready,
        "syncable": bool(key_ready),
        "docs": spec["docs"],
    }


def status_snapshot() -> list[dict]:
    """State of every source, in the order shown on the intel page."""
    urlhaus_env = "URLHAUS_AUTH_KEY"
    gsb_env = "GOOGLE_SAFE_BROWSING_KEY"
    urlhaus_ready = bool(_env(urlhaus_env))
    gsb_ready = bool(_env(gsb_env))

    api = {
        "urlhaus": {
            "id": "urlhaus",
            "name": "URLhaus",
            "kind": "API",
            "status": "live" if urlhaus_ready else "needs_key",
            "label": "Ready" if urlhaus_ready else "Needs key",
            "entries": None,
            "entries_label": "per-URL",
            "last_sync": None,
            "age_hours": None,
            "message": "Queried live for each scan." if urlhaus_ready else "Set URLHAUS_AUTH_KEY.",
            "key_env": urlhaus_env,
            "key_ready": urlhaus_ready,
            "syncable": False,
            "docs": "https://auth.abuse.ch/",
        },
        "safe_browsing": {
            "id": "safe_browsing",
            "name": "Google Safe Browsing",
            "kind": "API",
            "status": "live" if gsb_ready else "needs_key",
            "label": "Ready" if gsb_ready else "Needs key",
            "entries": None,
            "entries_label": "per-URL",
            "last_sync": None,
            "age_hours": None,
            "message": "Queried live for each scan." if gsb_ready else "Set GOOGLE_SAFE_BROWSING_KEY.",
            "key_env": gsb_env,
            "key_ready": gsb_ready,
            "syncable": False,
            "docs": "https://console.cloud.google.com/apis/library/safebrowsing.googleapis.com",
        },
    }

    return [
        _feed_snapshot("phishtank"),
        api["urlhaus"],
        _feed_snapshot("openphish"),
        api["safe_browsing"],
        _feed_snapshot("phishing_db"),
    ]


def feed_overview() -> dict:
    """Feed-only view for the sync controls at the top of the intel section."""
    feeds_list = [_feed_snapshot(feed_id) for feed_id in feeds.FEEDS]
    live = [item for item in feeds_list if item["status"] == "live"]
    return {
        "feeds": feeds_list,
        "live": len(live),
        "total": len(feeds_list),
        "entries": sum(item["entries"] or 0 for item in feeds_list),
        "samples": feeds.samples("openphish", 3),
    }
