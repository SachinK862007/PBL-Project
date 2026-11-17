"""Check every threat source and key with one command.

    .venv\\Scripts\\python.exe verify_keys.py      (Windows)
    .venv/bin/python verify_keys.py               (macOS / Linux)

Exit code is 0 when every source is usable, 1 when something still needs a key
or a sync. Nothing here opens a real link: the sample URL is only analysed.
"""

from __future__ import annotations

import sys

from dotenv import load_dotenv

from modules import feeds, threat_sources

SAMPLE = "https://example.com/"
HINTS = {
    "not_configured": "add the key to .env, restart, then sync the feed",
    "not_synced": "press Sync feeds in the app, or POST /api/feeds/sync",
    "error": "read the message above; fix the key or try again later",
}


def main() -> int:
    load_dotenv()
    feeds.init_db()

    print("SecureBrowse source check\n")
    checks = threat_sources.check_all(SAMPLE, "example.com", "example.com")
    problems = []

    for check in checks:
        usable = check["status"] in ("match", "clear")
        mark = "OK  " if usable else "TODO"
        print(f"  [{mark}] {check['source']:<22} {check['status']}")
        print(f"        {check['detail']}")
        if not usable:
            problems.append((check["source"], check["status"]))

    print("\nCached feeds")
    for item in threat_sources.feed_overview()["feeds"]:
        age = f"{item['age_hours']:g} h ago" if item["age_hours"] is not None else "never"
        print(f"  {item['name']:<22} {item['status']:<11} {item['entries_label']:>9} entries | {age}")

    if problems:
        print("\nStill to fix:")
        for name, status in problems:
            print(f"  - {name}: {HINTS.get(status, 'check the message above')}")
        return 1

    print("\nAll five sources are usable.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
