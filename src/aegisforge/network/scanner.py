"""TCP connect port scanning with explicit authorized-target scoping.

Active scanning is opt-in per target: loopback, private, link-local and
other non-routable addresses scan by default; anything globally
routable requires ``--allow-remote`` so probing someone else's
infrastructure is always a deliberate, auditable choice. Hostnames are
resolved first and every resolved address is checked.

Port states follow the connect-scan convention:
  open     — TCP handshake completed
  closed   — connection actively refused
  filtered — timed out (after retries) or otherwise unreachable
"""

from __future__ import annotations

import socket
import ssl
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass, field
from typing import Any

from aegisforge.network import http as http_mod
from aegisforge.network import services as services_mod
from aegisforge.network import tls as tls_mod
from aegisforge.network.validation import (
    ValidationError,
    is_public_ip,
    validate_port,
    validate_positive_int,
    validate_target,
    validate_timeout,
)

#: Port states.
OPEN = "open"
CLOSED = "closed"
FILTERED = "filtered"

#: Default scan set when the user gives neither --ports nor --port-range.
DEFAULT_PORTS: list[int] = [
    21,
    22,
    23,
    25,
    53,
    80,
    110,
    111,
    135,
    139,
    143,
    443,
    445,
    993,
    995,
    1723,
    3306,
    3389,
    5432,
    5900,
    6379,
    8080,
    8443,
    27017,
]

_MAX_CONNECT_TIMEOUT = 30.0  # hard cap on one connect attempt


class ScanAuthorizationError(ValidationError):
    """Raised when a scan target needs explicit --allow-remote consent."""


@dataclass
class ScanOptions:
    """Tunable knobs for one scan invocation."""

    timeout: float = 1.0
    retries: int = 1
    max_parallel: int = 50
    banner: bool = True
    banner_timeout: float = 2.0
    tls_probe: bool = True
    http_probe: bool = True

    def validated(self) -> ScanOptions:
        validate_timeout(self.timeout)
        validate_positive_int("retries", self.retries, minimum=0, maximum=5)
        validate_positive_int("max_parallel", self.max_parallel, maximum=100)
        validate_timeout(self.banner_timeout)
        return self


@dataclass
class PortResult:
    """Outcome for a single TCP port."""

    port: int
    state: str = FILTERED
    rtt_ms: float | None = None
    service: str | None = None
    banner: str | None = None
    tls: dict[str, Any] | None = None
    http: dict[str, Any] | None = None
    attempts: int = 1
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ScanResult:
    """Outcome of scanning one target."""

    target: str
    resolved_ip: str | None = None
    ports: list[PortResult] = field(default_factory=list)
    duration_ms: float = 0.0
    allow_remote: bool = False
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @property
    def open_ports(self) -> list[PortResult]:
        return [p for p in self.ports if p.state == OPEN]


def check_scan_authorization(target: str, *, allow_remote: bool) -> str:
    """Validate *target* and enforce remote-scan authorization.

    Returns the resolved IP used for the scan. Raises
    ScanAuthorizationError when any resolved address is globally
    routable and ``allow_remote`` is False; ValidationError when the
    target cannot be resolved.
    """
    cleaned = validate_target(target)
    try:
        infos = socket.getaddrinfo(cleaned, None, proto=socket.IPPROTO_TCP)
    except socket.gaierror as exc:
        raise ValidationError(f"cannot resolve target {cleaned!r}: {exc}") from exc
    addresses = sorted({str(info[4][0]) for info in infos if info[4]})
    if not addresses:
        raise ValidationError(f"could not resolve target {cleaned!r} to an address")
    public = [addr for addr in addresses if is_public_ip(addr)]
    if public and not allow_remote:
        shown = ", ".join(public[:3])
        raise ScanAuthorizationError(
            f"refusing to scan public target {cleaned!r} (resolves to {shown}) "
            "without --allow-remote: confirm you are authorized to scan "
            "this target, then re-run with --allow-remote"
        )
    return addresses[0]


def _enrich(
    host: str, sock: socket.socket, port: int, result: PortResult, options: ScanOptions
) -> None:
    """Identify the service behind an open port (best effort, bounded)."""
    stream: socket.socket = sock
    use_tls = False
    if options.tls_probe and port in services_mod.TLS_PORTS:
        tls_info, stream = tls_mod.inspect_tls_socket(
            sock, host, port, options.banner_timeout
        )
        result.tls = tls_info.to_dict()
        if tls_info.error is None:
            use_tls = isinstance(stream, ssl.SSLSocket)
    banner: str | None = None
    raw_head: bytes | None = None
    if options.banner:
        try:
            raw_head = services_mod.fetch_head(
                stream, port, host=host, timeout=options.banner_timeout
            )
        except OSError:
            raw_head = None
        if raw_head:
            banner = services_mod.sanitize_banner(raw_head)
    result.banner = banner
    if options.http_probe and raw_head and port in services_mod.HTTP_PORTS:
        head_text = raw_head.decode("utf-8", errors="replace")
        if head_text.lstrip().upper().startswith("HTTP/"):
            meta = http_mod.parse_response_head(head_text, host, port, use_tls=use_tls)
            result.http = meta.to_dict()
    result.service = services_mod.identify_service(port, banner, tls=use_tls)


def scan_port(
    target_ip: str,
    port: int,
    host: str,
    options: ScanOptions,
) -> PortResult:
    """TCP-connect scan of a single port with bounded retries."""
    validate_port(port)
    attempts = 0
    last_error = "connection timed out"
    started = time.monotonic()
    while attempts <= options.retries:
        attempts += 1
        try:
            raw = socket.create_connection(
                (target_ip, port), timeout=min(options.timeout, _MAX_CONNECT_TIMEOUT)
            )
        except TimeoutError:
            last_error = f"connection timed out after {options.timeout}s"
            continue
        except ConnectionRefusedError:
            return PortResult(
                port=port, state=CLOSED, attempts=attempts, error="connection refused"
            )
        except OSError as exc:
            return PortResult(
                port=port, state=FILTERED, attempts=attempts, error=f"{exc}"
            )
        rtt_ms = round((time.monotonic() - started) * 1000, 2)
        result = PortResult(port=port, state=OPEN, rtt_ms=rtt_ms, attempts=attempts)
        try:
            with raw:
                _enrich(host, raw, port, result, options)
        except OSError as exc:
            result.error = f"service probe failed: {exc}"
        return result
    return PortResult(port=port, state=FILTERED, attempts=attempts, error=last_error)


def scan_host(
    target: str,
    ports: list[int],
    options: ScanOptions,
    *,
    allow_remote: bool = False,
) -> ScanResult:
    """Scan *ports* on *target* with a bounded worker pool."""
    options = options.validated()
    if not ports:
        raise ValidationError("at least one port is required")
    resolved_ip = check_scan_authorization(target, allow_remote=allow_remote)
    started = time.monotonic()
    results: dict[int, PortResult] = {}
    with ThreadPoolExecutor(max_workers=options.max_parallel) as pool:
        future_map = {
            pool.submit(scan_port, resolved_ip, port, target, options): port
            for port in ports
        }
        for future in as_completed(future_map):
            port = future_map[future]
            try:
                results[port] = future.result()
            except ValidationError as exc:
                results[port] = PortResult(port=port, state=FILTERED, error=str(exc))
    ordered = [results[port] for port in ports]
    duration_ms = round((time.monotonic() - started) * 1000, 2)
    return ScanResult(
        target=target,
        resolved_ip=resolved_ip,
        ports=ordered,
        duration_ms=duration_ms,
        allow_remote=allow_remote,
    )
