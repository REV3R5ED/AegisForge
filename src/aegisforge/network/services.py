"""Service identification and banner grabbing for open TCP ports.

Banner reads are passive, bounded, and short-timed. For HTTP-ish ports
a minimal ``HEAD`` request is sent so the response head doubles as the
banner. Nothing here trusts the remote end: reads are size-capped and
all bytes are sanitized before display.
"""

from __future__ import annotations

import socket
from typing import Any

# Well-known port -> service name fallback when no banner identifies it.
WELL_KNOWN_PORTS: dict[int, str] = {
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "dns",
    80: "http",
    110: "pop3",
    111: "rpcbind",
    135: "msrpc",
    139: "netbios-ssn",
    143: "imap",
    443: "https",
    445: "smb",
    465: "smtps",
    587: "smtp",
    636: "ldaps",
    993: "imaps",
    995: "pop3s",
    1433: "mssql",
    1521: "oracle",
    1723: "pptp",
    3306: "mysql",
    3389: "rdp",
    5432: "postgresql",
    5900: "vnc",
    6379: "redis",
    8080: "http",
    8443: "https",
    27017: "mongodb",
}

# Ports where a TLS handshake is attempted before any other probing.
TLS_PORTS: frozenset[int] = frozenset({443, 8443, 465, 993, 995, 636, 989, 990, 3269})

# Ports where an HTTP request is sent to elicit a response head.
HTTP_PORTS: frozenset[int] = frozenset(
    {80, 8080, 8000, 8888, 8001, 5000, 3000, 8443, 443}
)

_BANNER_MAX_BYTES = 2048
_BANNER_DISPLAY_CHARS = 200


def _sanitize(raw: bytes) -> str:
    """Decode banner bytes to a single safe display line."""
    text = raw.decode("utf-8", errors="replace")
    # Collapse control characters and whitespace runs.
    cleaned = "".join(ch if ch.isprintable() or ch in " \t" else " " for ch in text)
    collapsed = " ".join(cleaned.split())
    if len(collapsed) > _BANNER_DISPLAY_CHARS:
        collapsed = collapsed[:_BANNER_DISPLAY_CHARS] + "..."
    return collapsed


def sanitize_banner(raw: bytes) -> str:
    """Public wrapper: raw response bytes -> safe one-line display string."""
    return _sanitize(raw)


def _recv_head(sock: socket.socket, max_bytes: int) -> bytes:
    """Read until the HTTP header terminator, EOF, or the byte cap."""
    chunks: list[bytes] = []
    received = 0
    while received < max_bytes:
        try:
            chunk = sock.recv(min(4096, max_bytes - received))
        except TimeoutError:
            break
        if not chunk:
            break
        chunks.append(chunk)
        received += len(chunk)
        if b"\r\n\r\n" in b"".join(chunks):
            break
    return b"".join(chunks)[:max_bytes]


def fetch_head(
    sock: socket.socket,
    port: int,
    *,
    host: str = "",
    timeout: float = 2.0,
    max_bytes: int = _BANNER_MAX_BYTES,
) -> bytes | None:
    """Read a raw response head from an already-connected socket.

    For HTTP-ish ports a minimal HEAD request is sent first; otherwise
    the read is passive. Returns raw bytes (line structure preserved)
    or None when nothing arrived. Callers sanitize for display via
    :func:`sanitize_banner` and parse HTTP via
    :func:`aegisforge.network.http.parse_response_head`.
    """
    previous = sock.gettimeout()
    try:
        sock.settimeout(timeout)
        if port in HTTP_PORTS:
            request = (
                f"HEAD / HTTP/1.0\r\nHost: {host or 'localhost'}\r\n"
                "Connection: close\r\nUser-Agent: AegisForge\r\n\r\n"
            )
            try:
                sock.sendall(request.encode("ascii"))
            except OSError:
                return None
        return _recv_head(sock, max_bytes) or None
    except OSError:
        return None
    finally:
        try:
            sock.settimeout(previous)
        except OSError:
            pass


def grab_banner(
    sock: socket.socket,
    port: int,
    *,
    host: str = "",
    timeout: float = 2.0,
    max_bytes: int = _BANNER_MAX_BYTES,
) -> str | None:
    """Grab a service banner from an already-connected socket.

    Returns a sanitized one-line string, or None when nothing arrived.
    Use :func:`fetch_head` when the raw line structure is needed.
    """
    raw = fetch_head(sock, port, host=host, timeout=timeout, max_bytes=max_bytes)
    if not raw:
        return None
    return _sanitize(raw) or None


def identify_service(port: int, banner: str | None, *, tls: bool = False) -> str:
    """Best-effort service name from banner content and port number."""
    text = (banner or "").upper()
    if text.startswith("SSH-"):
        return "ssh"
    if text.startswith("HTTP/"):
        return "https" if tls else "http"
    if text.startswith("220"):
        if port in (25, 587, 465):
            return "smtps" if tls or port == 465 else "smtp"
        if port == 21:
            return "ftp"
        return "smtp" if port != 21 else "ftp"
    if "MYSQL" in text or "MARIADB" in text:
        return "mysql"
    if text.startswith("+OK"):
        return "pop3"
    if text.startswith("* OK"):
        return "imap"
    if "RDP" in text or "MICROSOFT" in text and port == 3389:
        return "rdp"
    if tls and port in (443, 8443):
        return "https"
    return WELL_KNOWN_PORTS.get(port, "unknown")


def service_summary(
    port: int, banner: str | None, *, tls: bool = False
) -> dict[str, Any]:
    """Small structured record describing the identified service."""
    return {
        "port": port,
        "service": identify_service(port, banner, tls=tls),
        "banner": banner,
        "tls": tls,
    }
