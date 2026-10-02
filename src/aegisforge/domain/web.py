"""HTTP/HTTPS header and redirect-chain collection.

Issues a GET via :mod:`http.client`, follows redirects manually (max 5),
and records the status chain, ``Server`` header, content type and final
URL. Response bodies are never read. HTTPS uses a non-verifying context
by design — the investigation records what the server presents and
reports verification separately through the TLS section.
"""

from __future__ import annotations

import http.client
import ssl
import urllib.parse
from dataclasses import asdict, dataclass, field
from typing import Any

MAX_REDIRECTS = 5
_REDIRECT_STATUSES = {301, 302, 303, 307, 308}


class WebError(Exception):
    """Raised when an HTTP probe cannot complete."""


@dataclass
class RedirectHop:
    """One hop in a redirect chain."""

    url: str
    status: int
    location: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class WebResult:
    """Header/redirect metadata for one web endpoint."""

    url: str
    final_url: str | None = None
    hops: list[RedirectHop] = field(default_factory=list)
    status_code: int | None = None
    server: str | None = None
    content_type: str | None = None
    headers: dict[str, str] = field(default_factory=dict)
    use_tls: bool = False
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _connection(
    scheme: str, host: str, port: int, timeout: float
) -> http.client.HTTPConnection:
    if scheme == "https":
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        return http.client.HTTPSConnection(host, port, timeout=timeout, context=context)
    return http.client.HTTPConnection(host, port, timeout=timeout)


def fetch_headers(
    url: str, timeout: float = 10.0, max_redirects: int = MAX_REDIRECTS
) -> WebResult:
    """Fetch response headers for *url*, following redirects."""
    result = WebResult(url=url)
    current = url
    seen: set[str] = set()
    for _ in range(max_redirects + 1):
        if current in seen:
            result.error = f"redirect loop detected at {current}"
            return result
        seen.add(current)
        parts = urllib.parse.urlsplit(current)
        scheme = parts.scheme.lower()
        if scheme not in ("http", "https"):
            result.error = f"unsupported URL scheme: {scheme!r}"
            return result
        host = parts.hostname or ""
        port = parts.port or (443 if scheme == "https" else 80)
        path = parts.path or "/"
        if parts.query:
            path += "?" + parts.query
        result.use_tls = scheme == "https"
        connection = _connection(scheme, host, port, timeout)
        try:
            connection.request("GET", path, headers={"User-Agent": "AegisForge/0.3"})
            reply = connection.getresponse()
            headers = {k.lower(): v for k, v in reply.getheaders()}
            # Drain nothing — close immediately; bodies are never read.
            reply.read(0)
        except (TimeoutError, OSError, http.client.HTTPException, ssl.SSLError) as exc:
            result.error = f"HTTP request to {current} failed: {exc}"
            connection.close()
            return result
        finally:
            connection.close()
        status = reply.status
        location = headers.get("location")
        result.hops.append(RedirectHop(url=current, status=status, location=location))
        if status in _REDIRECT_STATUSES and location:
            current = urllib.parse.urljoin(current, location)
            continue
        result.final_url = current
        result.status_code = status
        result.server = headers.get("server")
        result.content_type = (headers.get("content-type") or "").split(";")[0] or None
        interesting_headers = (
            "server",
            "content-type",
            "x-powered-by",
            "strict-transport-security",
        )
        for interesting in interesting_headers:
            if interesting in headers:
                result.headers[interesting] = headers[interesting]
        return result
    result.error = f"too many redirects (>{max_redirects}) starting at {url}"
    return result
