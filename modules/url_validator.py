"""Input validation for the URL analyser."""

from __future__ import annotations

import re
from urllib.parse import urlsplit

MAX_LENGTH = 2048
ALLOWED_SCHEMES = {"http", "https"}
BLOCKED_SCHEMES = {"javascript", "data", "file", "vbscript", "about", "blob"}
HOST_RE = re.compile(r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$")


def validate(raw: str) -> tuple[bool, str, str]:
    """Return (ok, normalised_url, error_message)."""
    if raw is None:
        return False, "", "Enter a URL to analyse."

    value = raw.strip().strip('"').strip("'")
    if not value:
        return False, "", "Enter a URL to analyse."
    if len(value) > MAX_LENGTH:
        return False, "", f"That URL is longer than {MAX_LENGTH} characters."

    declared = value.split(":", 1)[0].lower() if ":" in value.split("/", 1)[0] else ""
    if declared in BLOCKED_SCHEMES:
        return False, "", f"The '{declared}:' scheme is not a website address and is blocked."
    if declared in {"mailto", "tel", "ftp", "sms"}:
        return False, "", "Only http and https web addresses can be analysed."

    if "://" not in value:
        value = "https://" + value.lstrip("/")

    try:
        parts = urlsplit(value)
    except ValueError:
        return False, "", "That does not look like a valid URL."

    scheme = (parts.scheme or "").lower()
    if scheme in BLOCKED_SCHEMES:
        return False, "", f"The '{scheme}:' scheme is not a website address and is blocked."
    if scheme not in ALLOWED_SCHEMES:
        return False, "", "Only http and https web addresses can be analysed."

    host = (parts.hostname or "").lower()
    if not host:
        return False, "", "That URL has no domain name."

    if host.startswith(".") or host.endswith(".") or ".." in host:
        return False, "", "That domain name is not valid."

    is_ipv4 = re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", host) is not None
    if is_ipv4:
        octets = [int(part) for part in host.split(".")]
        if any(octet > 255 for octet in octets):
            return False, "", "That IP address is not valid."
    elif not HOST_RE.match(host):
        return False, "", "That domain name is not valid."
    elif "." not in host:
        return False, "", "That host name has no top-level domain."

    try:
        port = parts.port
    except ValueError:
        return False, "", "That URL has an invalid port."

    rebuilt = parts._replace(scheme=scheme, netloc=parts.netloc.lower()).geturl()
    if " " in rebuilt:
        return False, "", "A URL cannot contain spaces."

    _ = port  # kept for clarity: invalid ports raise above
    return True, rebuilt, ""
