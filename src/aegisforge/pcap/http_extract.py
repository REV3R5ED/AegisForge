"""HTTP metadata extraction from TCP/80 payloads.

Only the request line, ``Host``/``User-Agent`` headers and response
status lines are extracted — never message bodies. Everything is
truncated to :data:`MAX_HTTP_SNIPPET` (200 chars) for privacy, and
payloads are ASCII-decoded with errors replaced. Returns records;
never raises.
"""

from __future__ import annotations

from aegisforge.pcap.models import MAX_HTTP_SNIPPET, HttpRecord

_METHODS = (
    "GET",
    "POST",
    "HEAD",
    "PUT",
    "DELETE",
    "OPTIONS",
    "PATCH",
    "TRACE",
    "CONNECT",
)


def _snip(text: str) -> str:
    text = text.strip().replace("\r", "").replace("\n", " ")
    return text[:MAX_HTTP_SNIPPET]


def _headers(payload_text: str) -> dict[str, str]:
    headers: dict[str, str] = {}
    for line in payload_text.split("\n")[1:]:
        if not line.strip():
            break  # end of headers; bodies are never read
        if ":" in line:
            name, _, value = line.partition(":")
            headers[name.strip().lower()] = value.strip()
    return headers


def extract_http(
    payload: bytes, timestamp: str, src: str, dst: str
) -> list[HttpRecord]:
    """Extract HTTP metadata from one TCP payload. Never raises."""
    records: list[HttpRecord] = []
    try:
        text = payload.decode("ascii", errors="replace")
    except Exception:  # pragma: no cover - decode with replace cannot fail
        return records
    if "\n" not in text and "\r" not in text:
        return records
    first_line = text.split("\n", 1)[0].strip()
    headers = _headers(text)
    if first_line.startswith("HTTP/"):
        # Response: "HTTP/1.1 200 OK"
        parts = first_line.split()
        status = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else None
        records.append(
            HttpRecord(
                timestamp=timestamp,
                src=src,
                dst=dst,
                status=status,
                host=_snip(headers.get("host", "")),
            )
        )
    else:
        parts = first_line.split()
        if len(parts) >= 2 and parts[0] in _METHODS:
            method, path = parts[0], parts[1]
            records.append(
                HttpRecord(
                    timestamp=timestamp,
                    src=src,
                    dst=dst,
                    method=method,
                    host=_snip(headers.get("host", "")),
                    path=_snip(path),
                    user_agent=_snip(headers.get("user-agent", "")),
                )
            )
    return records
