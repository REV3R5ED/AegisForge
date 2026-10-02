"""DNS forward and reverse lookups via the stdlib socket module.

Lookups run in a worker thread so a caller-supplied timeout is honored
(``socket.getaddrinfo`` itself takes no timeout).
"""

from __future__ import annotations

import socket
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FutureTimeoutError
from dataclasses import asdict, dataclass
from typing import Any

from aegisforge.network.validation import (
    ValidationError,
    validate_target,
    validate_timeout,
)


class DNSError(Exception):
    """Raised when a DNS lookup fails."""


@dataclass
class DNSResult:
    query: str
    addresses: list[dict[str, Any]]
    reverse_name: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _with_timeout(func: Any, timeout: float) -> Any:
    with ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(func)
        try:
            return future.result(timeout=timeout)
        except FutureTimeoutError as exc:
            raise DNSError(f"DNS lookup timed out after {timeout}s") from exc


def resolve_forward(name: str, timeout: float = 5.0) -> DNSResult:
    """Resolve a DNS name to addresses."""
    name = validate_target(name)
    timeout = validate_timeout(timeout)

    def _lookup() -> list[tuple[Any, ...]]:
        return socket.getaddrinfo(name, None, proto=socket.IPPROTO_TCP)

    try:
        infos = _with_timeout(_lookup, timeout)
    except socket.gaierror as exc:
        raise DNSError(f"cannot resolve {name!r}: {exc}") from exc
    addresses: list[dict[str, Any]] = []
    seen: set[str] = set()
    for family, _, _, _, sockaddr in infos:
        ip = sockaddr[0]
        if ip in seen:
            continue
        seen.add(ip)
        addresses.append(
            {"ip": ip, "family": "IPv6" if family == socket.AF_INET6 else "IPv4"}
        )
    if not addresses:
        raise DNSError(f"no addresses found for {name!r}")
    return DNSResult(query=name, addresses=addresses)


def resolve_reverse(ip: str, timeout: float = 5.0) -> DNSResult:
    """Reverse-resolve an IP address to a hostname."""
    ip = validate_target(ip)
    timeout = validate_timeout(timeout)

    def _lookup() -> tuple[str, list[str], list[str]]:
        return socket.gethostbyaddr(ip)

    try:
        hostname, _, _ = _with_timeout(_lookup, timeout)
    except (socket.herror, socket.gaierror, OSError) as exc:
        raise DNSError(f"cannot reverse-resolve {ip!r}: {exc}") from exc
    family = "IPv6" if ":" in ip else "IPv4"
    return DNSResult(
        query=ip, addresses=[{"ip": ip, "family": family}], reverse_name=hostname
    )


def lookup(target: str, timeout: float = 5.0) -> DNSResult:
    """Forward lookup for names, reverse lookup for IP literals."""
    target = validate_target(target)
    try:
        socket.inet_pton(socket.AF_INET, target)
        return resolve_reverse(target, timeout)
    except OSError:
        pass
    try:
        socket.inet_pton(socket.AF_INET6, target)
        return resolve_reverse(target, timeout)
    except OSError:
        pass
    if not all(c.isalnum() or c in ".-_:" for c in target):
        raise ValidationError(f"invalid DNS target: {target!r}")
    return resolve_forward(target, timeout)
