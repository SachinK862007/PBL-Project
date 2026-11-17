"""Combine analysis evidence and source answers into one classified result."""

from __future__ import annotations

HIGH_THRESHOLD = 60
MEDIUM_THRESHOLD = 25

LEVEL_LABELS = {
    "low": "Likely legitimate",
    "medium": "Medium risk",
    "high": "High risk",
}

DISCLAIMER = (
    "This verdict describes the address only. It is not a guarantee that the "
    "website is safe, and an address that is not listed is not automatically harmless."
)


def classify(score: int) -> str:
    if score >= HIGH_THRESHOLD:
        return "high"
    if score >= MEDIUM_THRESHOLD:
        return "medium"
    return "low"


def build_result(analysis: dict, source_checks: list[dict]) -> dict:
    """Return the payload rendered by the interface."""
    score = analysis["score"]
    matched = [check for check in source_checks if check["status"] == "match"]
    checked = [check for check in source_checks if check["status"] in ("match", "clear")]
    unavailable = [check for check in source_checks if check["status"] in ("not_configured", "error")]

    if matched:
        score = 100
        reason = f"Reported as a known threat by {', '.join(check['source'] for check in matched)}."
    elif score >= HIGH_THRESHOLD:
        reason = "Several strong phishing indicators appear together in this address."
    elif score >= MEDIUM_THRESHOLD:
        reason = "Some elements of this address are suspicious, so treat it with caution."
    else:
        reason = "No strong phishing indicators were found in the address itself."
        if unavailable:
            reason += " External checks did not run, so the picture is partial."

    level = classify(score)
    return {
        "url": analysis["url"],
        "domain": analysis["domain"],
        "host": analysis["host"],
        "scheme": analysis["scheme"],
        "score": score,
        "level": level,
        "level_label": LEVEL_LABELS[level],
        "reason": reason,
        "findings": analysis["findings"],
        "sources": source_checks,
        "sources_checked": len(checked),
        "sources_total": len(source_checks),
        "unavailable": [check["source"] for check in unavailable],
        "incomplete": bool(unavailable),
        "disclaimer": DISCLAIMER,
    }
