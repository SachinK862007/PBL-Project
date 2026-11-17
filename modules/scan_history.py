"""Local SQLite activity log for the security dashboard."""

from __future__ import annotations

import sqlite3
from datetime import datetime
from pathlib import Path

DATA_DIR = Path(__file__).resolve().parent.parent / "data"
DB_PATH = DATA_DIR / "securebrowse.db"

SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    url        TEXT NOT NULL,
    domain     TEXT NOT NULL,
    score      INTEGER NOT NULL,
    level      TEXT NOT NULL,
    incomplete INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL
);
"""


def _connect() -> sqlite3.Connection:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(DB_PATH, timeout=10)
    connection.row_factory = sqlite3.Row
    return connection


def init_db() -> None:
    with _connect() as connection:
        connection.executescript(SCHEMA)


def record(url: str, domain: str, score: int, level: str, incomplete: bool) -> None:
    with _connect() as connection:
        connection.execute(
            "INSERT INTO scans (url, domain, score, level, incomplete, created_at) VALUES (?, ?, ?, ?, ?, ?)",
            (url, domain, score, level, int(incomplete), datetime.now().isoformat(timespec="seconds")),
        )


def _row_to_dict(row: sqlite3.Row) -> dict:
    try:
        stamp = datetime.fromisoformat(row["created_at"])
        when = stamp.strftime("%d %b · %H:%M")
    except ValueError:
        when = row["created_at"]
    return {
        "url": row["url"],
        "domain": row["domain"],
        "score": row["score"],
        "level": row["level"],
        "level_label": {
            "low": "Legitimate",
            "medium": "Medium",
            "high": "High",
        }.get(row["level"], row["level"]),
        "incomplete": bool(row["incomplete"]),
        "when": when,
    }


def recent(limit: int = 8) -> list[dict]:
    with _connect() as connection:
        rows = connection.execute(
            "SELECT url, domain, score, level, incomplete, created_at "
            "FROM scans ORDER BY id DESC LIMIT ?",
            (limit,),
        ).fetchall()
    return [_row_to_dict(row) for row in rows]


def stats() -> dict:
    with _connect() as connection:
        total = connection.execute("SELECT COUNT(*) AS n FROM scans").fetchone()["n"]
        high = connection.execute("SELECT COUNT(*) AS n FROM scans WHERE level = 'high'").fetchone()["n"]
        medium = connection.execute("SELECT COUNT(*) AS n FROM scans WHERE level = 'medium'").fetchone()["n"]
    return {
        "total": total,
        "high": high,
        "medium": medium,
        "low": total - high - medium,
    }
