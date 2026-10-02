"""HTTP/HTTPS metadata collection over an established socket.

The port scanner already holds a connected (optionally TLS-wrapped)
socket whose first bytes are the server's response head — captured by
:func:`aegisforge.network.services.grab_banner` for HTTP-ish ports.
This module parses that head into structured metadata: status line,
server header, redirect target, content type. No new connections, no
body download, bounded parsing.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass
class HTTPMetadata:
    """Response-head metadata for one HTTP(S) endpoint."""

    host: str
    port: int
    use_tls: bool = False
    http_version: str | None = None
    status_code: int | None = None
    reason: str | None = None
    server: str | None = None
    location: str | None = None
    content_type: str | None = None
    headers: dict[str, str] = field(default_factory=dict)
    is_redirect: bool = False
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def parse_response_head(
    head: str, host: str, port: int, *, use_tls: bool = False
) -> HTTPMetadata:
    """Parse an HTTP response head (status line + headers) into metadata."""
    meta = HTTPMetadata(host=host, port=port, use_tls=use_tls)
    lines = head.splitlines()
    if not lines:
        meta.error = "empty response"
        return meta
    status = lines[0].strip()
    parts = status.split(None, 2)
    if len(parts) < 2 or not parts[0].upper().startswith("HTTP/"):
        meta.error = f"not an HTTP response: {status[:60]!r}"
        return meta
    meta.http_version = parts[0][5:] or None
    try:
        meta.status_code = int(parts[1])
    except ValueError:
        meta.error = f"unparseable status code: {parts[1]!r}"
        return meta
    meta.reason = parts[2] if len(parts) > 2 else ""
    for line in lines[1:]:
        if not line.strip():
            break
        if ":" not in line:
            continue
        name, _, value = line.partition(":")
        key = name.strip().lower()
        if key and key not in meta.headers:
            meta.headers[key] = value.strip()
    meta.server = meta.headers.get("server")
    meta.location = meta.headers.get("location")
    meta.content_type = meta.headers.get("content-type")
    meta.is_redirect = (
        meta.status_code is not None
        and 300 <= meta.status_code < 400
        and meta.location is not None
    )
    return meta


def summarize(meta: HTTPMetadata) -> str:
    """One-line human summary, e.g. 'HTTP/1.1 200 OK (nginx) -> /login'."""
    if meta.error:
        return f"http error: {meta.error}"
    scheme = "https" if meta.use_tls else "http"
    base = (
        f"{scheme} {meta.http_version} {meta.status_code} {meta.reason or ''}".strip()
    )
    if meta.server:
        base += f" ({meta.server})"
    if meta.is_redirect and meta.location:
        base += f" -> {meta.location}"
    return base
