"""Threat-feed synchronisation and lookup store.

Two of the sources can be used without any account, so they are synced and
queried for real:

* OpenPhish public feed
* Phishing.Database (the reference repository's active-domain list)

PhishTank needs the feed key from your own PhishTank account, URLhaus needs an
abuse.ch Auth-Key and Google Safe Browsing needs a Google Cloud API key. Their
values are never guessed: without a key the source is reported as "needs key"
and the scan is marked incomplete.

Feed data is stored in the same SQLite file as the scan history so lookups are
an indexed query instead of a full-file scan.
"""

from __future__ import annotations

import csv
import io
import os
import re
import sqlite3
import threading
from datetime import datetime
from pathlib import Path
from urllib.parse import urlsplit

import requests

DATA_DIR = Path(__file__).resolve().parent.parent / "data"
DB_PATH = DATA_DIR / "securebrowse.db"

CONNECT_TIMEOUT = 12
READ_TIMEOUT = 180
STALE_AFTER_HOURS = 36

# Feed files contain placeholders ("redacted") and malformed rows; only real
# hostnames are worth storing.
HOST_RE = re.compile(r"^(?=.{4,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}$")
SKIP_SUFFIXES = (".invalid", ".test", ".localhost", ".local", ".example")
SKIP_SUBSTRINGS = ("redacted",)

FEEDS = {
    "openphish": {
        "name": "OpenPhish",
        "url": "https://openphish.com/feed.txt",
        "mode": "urls",
        "key_env": None,
        "docs": "https://openphish.com/",
        "note": "Public phishing URL feed, refreshed by OpenPhish.",
    },
    "phishing_db": {
        "name": "Phishing.Database",
        "url": (
            "https://raw.githubusercontent.com/Phishing-Database/Phishing.Database/"
            "master/phishing-domains-ACTIVE.txt"
        ),
        "mode": "domains",
        "key_env": None,
        "docs": "https://github.com/Phishing-Database/Phishing.Database",
        "note": "Active phishing domains from the reference repository.",
    },
    "phishtank": {
        "name": "PhishTank",
        "url": "https://data.phishtank.com/data/online-valid.csv",
        "key_url": "https://data.phishtank.com/data/{key}/online-valid.csv",
        "mode": "csv",
        "key_env": "PHISHTANK_APP_KEY",
        "optional_key": True,
        "user_agent": "phishtank/securebrowse-pbl",
        "docs": "https://phishtank.org/developer_info.php",
        "note": "Verified online phishing list; a free app key raises the download limit.",
    },
}

SCHEMA = """
CREATE TABLE IF NOT EXISTS feed_state (
    feed_id   TEXT PRIMARY KEY,
    entries   INTEGER NOT NULL DEFAULT 0,
    last_sync TEXT,
    status    TEXT NOT NULL DEFAULT 'never',
    message   TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS feed_entries (
    feed_id TEXT NOT NULL,
    value   TEXT NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_feed_entries ON feed_entries(feed_id, value);
"""

_sync_lock = threading.Lock()


def _connect() -> sqlite3.Connection:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(DB_PATH, timeout=20)
    connection.row_factory = sqlite3.Row
    return connection


def init_db() -> None:
    with _connect() as connection:
        connection.executescript(SCHEMA)


def _env(name: str) -> str:
    return (os.environ.get(name) or "").strip()


def _now() -> str:
    return datetime.now().isoformat(timespec="seconds")


def _canonical_url(value: str) -> str | None:
    """Scheme-less canonical form so http/https variants still match."""
    value = value.strip()
    if not value:
        return None
    if "://" not in value:
        value = "http://" + value
    try:
        parts = urlsplit(value)
    except ValueError:
        return None
    host = (parts.hostname or "").lower().strip(".")
    if not host:
        return None
    path = parts.path or "/"
    query = f"?{parts.query}" if parts.query else ""
    return f"{host}{path}{query}".lower()


def _clean_host(host: str | None) -> str | None:
    if not host:
        return None
    host = host.lower().strip(".")
    if any(marker in host for marker in SKIP_SUBSTRINGS):
        return None
    if host.endswith(SKIP_SUFFIXES):
        return None
    return host if HOST_RE.match(host) else None


def _host_of(value: str) -> str | None:
    value = value.strip()
    if "://" not in value:
        value = "http://" + value
    try:
        host = _clean_host(urlsplit(value).hostname)
    except ValueError:
        return None
    return host


def _values(raw: str, mode: str) -> list[str]:
    raw = raw.strip()
    if not raw:
        return []
    if mode == "domains":
        host = _clean_host(_host_of(raw) if "://" in raw else raw)
        return [host] if host else []

    host = _host_of(raw)
    if not host:
        return []
    canonical = _canonical_url(raw)
    values = [canonical] if canonical else []
    values.append(host)
    return values


def _rows_from(response, mode: str):
    if mode == "csv":
        reader = csv.reader(io.StringIO(response.text))
        header = next(reader, None)
        index = 1
        if header:
            lowered = [cell.strip().lower() for cell in header]
            if "url" in lowered:
                index = lowered.index("url")
        for row in reader:
            if len(row) > index:
                yield from _values(row[index], "urls")
        return

    for line in response.iter_lines(decode_unicode=True):
        if not line:
            continue
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        for value in _values(line, mode):
            yield value


def _feed_target(feed_id: str) -> tuple[str | None, str]:
    spec = FEEDS[feed_id]
    key_env = spec.get("key_env")
    key = _env(key_env) if key_env else ""
    if key and spec.get("key_url"):
        return spec["key_url"].format(key=key), ""
    if key_env and not spec.get("optional_key") and not key:
        return None, key_env
    return spec["url"], ""


def _store(feed_id: str, values: list[str], status: str, message: str) -> int:
    with _connect() as connection:
        connection.execute("DELETE FROM feed_entries WHERE feed_id = ?", (feed_id,))
        connection.executemany(
            "INSERT OR IGNORE INTO feed_entries (feed_id, value) VALUES (?, ?)",
            ((feed_id, value) for value in values),
        )
        entries = connection.execute(
            "SELECT COUNT(*) AS n FROM feed_entries WHERE feed_id = ?", (feed_id,)
        ).fetchone()["n"]
        connection.execute(
            "INSERT INTO feed_state (feed_id, entries, last_sync, status, message) "
            "VALUES (?, ?, ?, ?, ?) "
            "ON CONFLICT(feed_id) DO UPDATE SET entries = excluded.entries, "
            "last_sync = excluded.last_sync, status = excluded.status, message = excluded.message",
            (feed_id, entries, _now(), status, message),
        )
    return entries


def _fail(feed_id: str, message: str) -> dict:
    with _connect() as connection:
        connection.execute(
            "INSERT INTO feed_state (feed_id, entries, last_sync, status, message) "
            "VALUES (?, 0, ?, 'error', ?) "
            "ON CONFLICT(feed_id) DO UPDATE SET status = excluded.status, "
            "message = excluded.message",
            (feed_id, _now(), message),
        )
    return state(feed_id)


def sync(feed_id: str) -> dict:
    """Download one feed and replace its cached entries."""
    if feed_id not in FEEDS:
        raise KeyError(feed_id)

    target, missing_env = _feed_target(feed_id)
    if target is None:
        return _fail(feed_id, f"{missing_env} is not set in .env")

    headers = {
        "User-Agent": FEEDS[feed_id].get("user_agent")
        or "SecureBrowse/1.0 (+https://github.com/psairohith14-coder/PBL-Project)"
    }
    try:
        response = requests.get(target, timeout=(CONNECT_TIMEOUT, READ_TIMEOUT), headers=headers)
    except requests.RequestException as exc:
        return _fail(feed_id, f"Download failed ({type(exc).__name__}). Check the key and the connection.")

    if response.status_code == 429:
        return _fail(feed_id, "The source rate-limited this download (HTTP 429). Try again later.")
    if response.status_code >= 400:
        return _fail(feed_id, f"The source answered HTTP {response.status_code}. Check the key or try later.")

    try:
        values = list(dict.fromkeys(_rows_from(response, FEEDS[feed_id]["mode"])))
    except Exception as exc:  # parsing must never crash the app
        return _fail(feed_id, f"Feed could not be parsed ({type(exc).__name__}).")

    if not values:
        return _fail(feed_id, "The feed returned no usable entries.")

    _store(feed_id, values, "ok", f"{entries_label(len(values))} entries cached.")
    return state(feed_id)


def sync_all(only_keyless: bool = False) -> list[dict]:
    results = []
    for feed_id in FEEDS:
        if only_keyless and FEEDS[feed_id].get("key_env"):
            continue
        results.append(sync(feed_id))
    return results


def entries_label(count: int) -> str:
    return f"{count:,}"


def state(feed_id: str) -> dict:
    with _connect() as connection:
        row = connection.execute(
            "SELECT feed_id, entries, last_sync, status, message FROM feed_state WHERE feed_id = ?",
            (feed_id,),
        ).fetchone()
    if row is None:
        return {
            "feed_id": feed_id,
            "entries": 0,
            "last_sync": None,
            "status": "never",
            "message": "",
        }
    return dict(row)


def lookup(url: str, hosts: list[str]) -> dict[str, bool]:
    """True when the URL, the full host or the registrable domain is listed."""
    canonical = _canonical_url(url)
    values: set[str] = {canonical} if canonical else set()
    for host in hosts:
        host = (host or "").lower().strip(".")
        if not host:
            continue
        values.add(host)
        values.add(host[4:] if host.startswith("www.") else "www." + host)
    values.discard("")

    found: dict[str, bool] = {}
    with _connect() as connection:
        for feed_id in FEEDS:
            row = connection.execute(
                "SELECT 1 FROM feed_entries WHERE feed_id = ? AND value IN ("
                + ",".join("?" * len(values))
                + ") LIMIT 1",
                (feed_id, *values),
            ).fetchone()
            found[feed_id] = row is not None
    return found


def samples(feed_id: str, count: int = 3) -> list[str]:
    with _connect() as connection:
        rows = connection.execute(
            "SELECT value FROM feed_entries WHERE feed_id = ? ORDER BY RANDOM() LIMIT ?",
            (feed_id, count),
        ).fetchall()
    return [row["value"] for row in rows]


def age_hours(last_sync: str | None) -> float | None:
    if not last_sync:
        return None
    try:
        then = datetime.fromisoformat(last_sync)
    except ValueError:
        return None
    return round((datetime.now() - then).total_seconds() / 3600, 1)


def needs_initial_sync() -> bool:
    for feed_id, spec in FEEDS.items():
        if spec.get("key_env") and not spec.get("optional_key") and not _env(spec["key_env"]):
            continue
        if state(feed_id)["entries"] == 0:
            return True
    return False


def sync_keyless_in_background() -> None:
    """First-run warm-up so the intel page has live data without a button press."""
    if not needs_initial_sync():
        return

    def worker() -> None:
        if not _sync_lock.acquire(blocking=False):
            return
        try:
            for feed_id, spec in FEEDS.items():
                if spec.get("key_env") and not spec.get("optional_key") and not _env(spec["key_env"]):
                    continue
                if state(feed_id)["entries"] == 0:
                    sync(feed_id)
        finally:
            _sync_lock.release()

    threading.Thread(target=worker, name="feed-warmup", daemon=True).start()
