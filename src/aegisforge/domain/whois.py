"""WHOIS lookups over TCP port 43, stdlib-only.

Used as a fallback when RDAP is unavailable. Queries a WHOIS server,
follows one referral (``whois:`` / ``Whois Server:``), and extracts a
best-effort set of registration fields from the raw text. Parsed fields
are heuristic — the raw text is always kept so the analyst can verify.
"""

from __future__ import annotations

import re
import socket
from dataclasses import asdict, dataclass, field
from typing import Any

DEFAULT_WHOIS_SERVER = "whois.iana.org"
WHOIS_PORT = 43
_MAX_REPLY_BYTES = 65536

_REFERRAL_RES = (
    re.compile(r"(?im)^\s*whois:\s*(\S+)\s*$"),
    re.compile(r"(?im)^\s*Whois Server:\s*(\S+)\s*$"),
)
_FIELD_RES = {
    "registrar": re.compile(r"(?im)^\s*Registrar:\s*(.+?)\s*$"),
    "creation_date": re.compile(
        r"(?im)^\s*(?:Creation Date|Created|Registered On|Registered:)\s*(.+?)\s*$"
    ),
    "expiry_date": re.compile(
        r"(?im)^\s*(?:Registry Expiry Date|Expiration Date|Expiry Date|Expires On|"
        r"Valid Until|paid-till)\s*(.+?)\s*$"
    ),
    "registrant_org": re.compile(r"(?im)^\s*Registrant Organization:\s*(.+?)\s*$"),
}


class WhoisError(Exception):
    """Raised when a WHOIS query cannot complete."""


@dataclass
class WhoisResult:
    """Raw and parsed WHOIS data for one query."""

    query: str
    server: str
    referral_server: str | None = None
    fields: dict[str, str] = field(default_factory=dict)
    raw: str = ""
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _recvall(sock: socket.socket) -> bytes:
    chunks = bytearray()
    while len(chunks) < _MAX_REPLY_BYTES:
        try:
            chunk = sock.recv(4096)
        except TimeoutError as exc:
            raise WhoisError(f"WHOIS read timed out: {exc}") from exc
        if not chunk:
            break
        chunks.extend(chunk)
    return bytes(chunks)


def query_server(server: str, query: str, timeout: float = 10.0) -> str:
    """Send one WHOIS query to *server* and return the raw reply text."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.settimeout(timeout)
        sock.connect((server, WHOIS_PORT))
        sock.sendall(query.encode("utf-8", errors="replace") + b"\r\n")
        raw = _recvall(sock)
    except (TimeoutError, OSError) as exc:
        raise WhoisError(f"WHOIS query to {server} failed: {exc}") from exc
    finally:
        sock.close()
    return raw.decode("utf-8", errors="replace")


def _find_referral(text: str) -> str | None:
    for pattern in _REFERRAL_RES:
        match = pattern.search(text)
        if match:
            return match.group(1).strip().rstrip(".")
    return None


def _parse_fields(text: str) -> dict[str, str]:
    fields: dict[str, str] = {}
    for key, pattern in _FIELD_RES.items():
        match = pattern.search(text)
        if match and key not in fields:
            fields[key] = match.group(1).strip()
    return fields


def whois_lookup(
    domain: str,
    timeout: float = 10.0,
    server: str = DEFAULT_WHOIS_SERVER,
) -> WhoisResult:
    """Look up *domain* via WHOIS, following one referral level."""
    result = WhoisResult(query=domain, server=server)
    try:
        first = query_server(server, domain, timeout)
    except WhoisError as exc:
        result.error = str(exc)
        return result
    referral = _find_referral(first)
    if referral and referral.lower() != server.lower():
        result.referral_server = referral
        try:
            second = query_server(referral, domain, timeout)
        except WhoisError as exc:
            result.raw = first
            result.fields = _parse_fields(first)
            result.error = f"referral to {referral} failed: {exc}"
            return result
        result.raw = second
        result.fields = _parse_fields(second)
    else:
        result.raw = first
        result.fields = _parse_fields(first)
    if not result.raw.strip():
        result.error = f"WHOIS server {server} returned an empty reply"
    return result
