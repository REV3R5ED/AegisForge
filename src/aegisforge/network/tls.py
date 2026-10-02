"""TLS certificate inspection via the stdlib ``ssl`` module.

Deliberate design choice: the probe context does NOT verify the chain
(``CERT_NONE``) so the scanner records whatever certificate the peer
presents — self-signed, expired, or mismatched — instead of refusing
the handshake. Verification signal is reported explicitly through
``hostname_verified`` and ``days_until_expiry``. A scanner observes;
it does not refuse.

Two entry points: :func:`inspect_tls_socket` upgrades an
already-connected socket (used by the port scanner), and
:func:`inspect_tls` opens its own connection (standalone use and the
later domain-investigation phase).
"""

from __future__ import annotations

import ipaddress
import socket
import ssl
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any

from aegisforge.network.validation import (
    validate_port,
    validate_target,
    validate_timeout,
)


class TLSProbeError(Exception):
    """Raised when a TLS probe cannot complete."""


_CERT_TIME_FORMAT = "%b %d %H:%M:%S %Y %Z"


@dataclass
class TLSInfo:
    """Parsed certificate and connection details for one TLS endpoint."""

    host: str
    port: int
    subject: dict[str, str] = field(default_factory=dict)
    issuer: dict[str, str] = field(default_factory=dict)
    not_before: str | None = None
    not_after: str | None = None
    days_until_expiry: int | None = None
    san_dns_names: list[str] = field(default_factory=list)
    san_ip_addresses: list[str] = field(default_factory=list)
    hostname_verified: bool = False
    protocol: str | None = None
    cipher: str | None = None
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _name_to_dict(name: Any) -> dict[str, str]:
    """Convert the ((('CN', 'x'),), ...) cert-name structure to a dict."""
    result: dict[str, str] = {}
    if not name:
        return result
    for rdn in name:
        for attr in rdn:
            if len(attr) >= 2:
                result[str(attr[0])] = str(attr[1])
    return result


def _parse_cert_time(value: Any) -> datetime | None:
    if not value or not isinstance(value, str):
        return None
    try:
        parsed = datetime.strptime(value.strip(), _CERT_TIME_FORMAT)
    except ValueError:
        return None
    return parsed.replace(tzinfo=timezone.utc)


def hostname_matches_cert(
    host: str,
    san_dns_names: list[str],
    san_ip_addresses: list[str],
    subject: dict[str, str],
) -> bool:
    """Wildcard-aware check of *host* against certificate names.

    Follows RFC 6125 loosely: a ``*.example.com`` wildcard matches
    exactly one left-most label.
    """
    host = host.strip().lower().rstrip(".")
    try:
        host_ip = ipaddress.ip_address(host)
    except ValueError:
        host_ip = None
    if host_ip is not None:
        return any(_ip_equal(host_ip, entry) for entry in san_ip_addresses)
    candidates = [name.lower().rstrip(".") for name in san_dns_names]
    if not candidates:
        # Legacy CN fallback only when the certificate carries no DNS SANs
        # (RFC 6125: SANs, when present, take precedence over CN).
        cn = subject.get("CN", "").lower().rstrip(".")
        if cn:
            candidates.append(cn)
    for pattern in candidates:
        if pattern == host:
            return True
        if pattern.startswith("*."):
            suffix = pattern[2:]
            if "." in host and host.split(".", 1)[1] == suffix:
                # Exactly one label before the suffix.
                if host.count(".") == suffix.count(".") + 1:
                    return True
    return False


def _ip_equal(
    host_ip: ipaddress.IPv4Address | ipaddress.IPv6Address, entry: str
) -> bool:
    try:
        return ipaddress.ip_address(entry.strip()) == host_ip
    except ValueError:
        return False


def _probe_context() -> ssl.SSLContext:
    """Non-verifying context: capture the cert, report verification ourselves."""
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    return context


def describe_cert(tls_sock: ssl.SSLSocket, host: str, port: int) -> TLSInfo:
    """Build a TLSInfo from an established TLS socket."""
    info = TLSInfo(host=host, port=port)
    try:
        info.protocol = tls_sock.version()
        cipher = tls_sock.cipher()
        if cipher:
            info.cipher = cipher[0]
        cert = tls_sock.getpeercert()
    except (OSError, ssl.SSLError, ValueError) as exc:
        info.error = f"could not read peer certificate: {exc}"
        return info
    if not cert:
        info.error = "peer presented no certificate"
        return info
    if isinstance(cert, dict):
        info.subject = _name_to_dict(cert.get("subject"))
        info.issuer = _name_to_dict(cert.get("issuer"))
        not_before = _parse_cert_time(cert.get("notBefore"))
        not_after = _parse_cert_time(cert.get("notAfter"))
        if not_before:
            info.not_before = not_before.isoformat().replace("+00:00", "Z")
        if not_after:
            info.not_after = not_after.isoformat().replace("+00:00", "Z")
            delta = not_after - datetime.now(timezone.utc)
            info.days_until_expiry = delta.days
        san: list[tuple[str, str]] = []
        raw_san = cert.get("subjectAltName")
        if isinstance(raw_san, (list, tuple)):
            for entry in raw_san:
                if isinstance(entry, (list, tuple)) and len(entry) == 2:
                    san.append((str(entry[0]), str(entry[1])))
        info.san_dns_names = sorted(str(value) for kind, value in san if kind == "DNS")
        info.san_ip_addresses = sorted(
            str(value) for kind, value in san if kind == "IP Address"
        )
        info.hostname_verified = hostname_matches_cert(
            host, info.san_dns_names, info.san_ip_addresses, info.subject
        )
    return info


def wrap_tls(sock: socket.socket, host: str, timeout: float = 5.0) -> ssl.SSLSocket:
    """Upgrade a connected TCP socket to TLS with SNI. May raise."""
    context = _probe_context()
    try:
        sock.settimeout(timeout)
        return context.wrap_socket(sock, server_hostname=host)
    except (OSError, ssl.SSLError) as exc:
        raise TLSProbeError(f"TLS handshake with {host} failed: {exc}") from exc


def inspect_tls(host: str, port: int = 443, timeout: float = 5.0) -> TLSInfo:
    """Standalone TLS inspection: connect, handshake, parse, close."""
    target = validate_target(host)
    port = validate_port(port)
    timeout = validate_timeout(timeout)
    try:
        raw = socket.create_connection((target, port), timeout=timeout)
    except OSError as exc:
        return TLSInfo(host=target, port=port, error=f"TCP connect failed: {exc}")
    tls_sock: ssl.SSLSocket | None = None
    try:
        tls_sock = wrap_tls(raw, target, timeout)
        return describe_cert(tls_sock, target, port)
    except TLSProbeError as exc:
        return TLSInfo(host=target, port=port, error=str(exc))
    finally:
        for candidate in (tls_sock, raw):
            if candidate is not None:
                try:
                    candidate.close()
                except OSError:
                    pass


def inspect_tls_socket(
    sock: socket.socket, host: str, port: int, timeout: float = 5.0
) -> tuple[TLSInfo, socket.socket]:
    """Wrap a connected socket; return (info, active socket).

    On handshake failure the info record carries ``error`` and the
    original plaintext socket is returned so callers can fall back to
    plaintext probing.
    """
    try:
        tls_sock = wrap_tls(sock, host, timeout)
    except TLSProbeError as exc:
        return TLSInfo(host=host, port=port, error=str(exc)), sock
    return describe_cert(tls_sock, host, port), tls_sock
