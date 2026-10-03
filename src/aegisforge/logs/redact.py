"""PII redaction for log output.

Logs routinely contain IP addresses and email addresses. ``--redact``
masks them in *rendered output only* (human tables, JSON, CSV) — the
source files are never modified, and the in-memory analysis keeps the
original values so counts and findings stay accurate.

IPv4 addresses become ``xxx.xxx.xxx.xxx`` (length-preserving, so
tables stay aligned); IPv6 and email-like tokens become fixed
``[redacted-…]`` markers.
"""

from __future__ import annotations

import re
from typing import Any

_IPV4 = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b"
)
# Hex groups separated by colons: full and compressed IPv6 forms.
_IPV6 = re.compile(r"\b(?:[0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}\b")
_EMAIL = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")

REDACTED_IPV4 = "xxx.xxx.xxx.xxx"
REDACTED_IPV6 = "[redacted-ipv6]"
REDACTED_EMAIL = "[redacted-email]"


def redact_text(text: str) -> str:
    """Mask IPs and email-like tokens in *text*."""
    if not text:
        return text
    text = _IPV4.sub(REDACTED_IPV4, text)

    def _ipv6_sub(match: re.Match[str]) -> str:
        token = match.group(0)
        # Timestamps like 16:47:04 are hex-plausible but have exactly
        # two colons and no a-f letters — leave those alone.
        has_hex_letter = bool(re.search(r"[a-fA-F]", token))
        if token.count(":") >= 3 or has_hex_letter:
            return REDACTED_IPV6
        return token

    text = _IPV6.sub(_ipv6_sub, text)
    text = _EMAIL.sub(REDACTED_EMAIL, text)
    return text


def redact_value(value: Any) -> Any:
    """Recursively redact strings inside nested data."""
    if isinstance(value, str):
        return redact_text(value)
    if isinstance(value, dict):
        return {k: redact_value(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [redact_value(v) for v in value]
    return value
