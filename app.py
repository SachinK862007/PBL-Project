"""SecureBrowse — a Python web application that checks URLs for phishing signals.

Run locally:
    .venv\\Scripts\\python.exe app.py       (Windows)
    .venv/bin/python app.py                (macOS / Linux)
"""

from __future__ import annotations

import os

from dotenv import load_dotenv
from flask import Flask, jsonify, render_template, request

from modules import content, scan_history, threat_sources, url_analyzer, url_validator
from modules.result_handler import build_result

load_dotenv()

app = Flask(__name__)
app.config["JSON_SORT_KEYS"] = False
scan_history.init_db()


def _history_payload() -> dict:
    return {"history": scan_history.recent(8), "stats": scan_history.stats()}


@app.get("/")
def home():
    return render_template(
        "index.html",
        content=content,
        sources=threat_sources.status_snapshot(),
        **_history_payload(),
    )


@app.post("/api/scan")
def scan():
    payload = request.get_json(silent=True) or {}
    ok, url, error = url_validator.validate(payload.get("url", ""))
    if not ok:
        return jsonify({"ok": False, "error": error}), 400

    analysis = url_analyzer.analyze(url)
    result = build_result(analysis, threat_sources.check_all(url))
    scan_history.record(
        url=result["url"],
        domain=result["domain"],
        score=result["score"],
        level=result["level"],
        incomplete=result["incomplete"],
    )
    return jsonify({"ok": True, "result": result, **_history_payload()})


@app.get("/api/history")
def history():
    return jsonify(_history_payload())


@app.get("/healthz")
def healthz():
    return jsonify({"ok": True})


if __name__ == "__main__":
    port = int(os.environ.get("SECUREBROWSE_PORT", "5000"))
    app.run(host="127.0.0.1", port=port, debug=os.environ.get("FLASK_DEBUG") == "1")
