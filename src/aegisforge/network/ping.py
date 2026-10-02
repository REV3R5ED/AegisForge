"""ICMP reachability via the OS ping utility (bounded, no raw sockets).

Uses the system ``ping``/``ping.exe`` through subprocess with an
argument list (never shell=True). Single-host and concurrent
multi-host checks with controlled parallelism.
"""

from __future__ import annotations

import platform
import re
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass
from typing import Any

from aegisforge.network.validation import (
    ValidationError,
    validate_positive_int,
    validate_target,
    validate_timeout,
)

_DEFAULT_TIMEOUT = 30.0  # hard cap on one ping process


@dataclass
class PingResult:
    target: str
    reachable: bool
    transmitted: int = 0
    received: int = 0
    loss_percent: float = 100.0
    rtt_min_ms: float | None = None
    rtt_avg_ms: float | None = None
    rtt_max_ms: float | None = None
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _ping_argv(target: str, count: int, timeout: float) -> list[str]:
    system = platform.system()
    if system == "Windows":
        # -n count, -w timeout per reply in milliseconds.
        return ["ping", "-n", str(count), "-w", str(int(timeout * 1000)), target]
    if system == "Darwin":
        # -c count, -W timeout per packet in milliseconds on macOS.
        return ["ping", "-c", str(count), "-W", str(int(timeout * 1000)), target]
    # Linux and others: -c count, -W timeout per packet in seconds.
    return ["ping", "-c", str(count), "-W", str(max(1, int(timeout))), target]


_LINUX_STATS_RE = re.compile(
    r"(\d+)\s+packets transmitted,\s+(\d+)\s+(?:packets\s+)?received"
    r"(?:,\s+([\d.]+)%\s+packet loss)?"
)
_RTT_RE = re.compile(
    r"(?:rtt|round-trip)\s+min/avg/max(?:/mdev)?\s*=\s*([\d.]+)/([\d.]+)/([\d.]+)"
)


def _parse_output(output: str, count: int) -> PingResult | None:
    """Parse ping output; returns None when nothing parseable was found."""
    stats = _LINUX_STATS_RE.search(output)
    if not stats:
        return None
    transmitted = int(stats.group(1))
    received = int(stats.group(2))
    loss = float(stats.group(3)) if stats.group(3) else 0.0
    rtt_min = rtt_avg = rtt_max = None
    rtt = _RTT_RE.search(output)
    if rtt:
        rtt_min, rtt_avg, rtt_max = (float(rtt.group(i)) for i in (1, 2, 3))
    return PingResult(
        target="",
        reachable=received > 0,
        transmitted=transmitted,
        received=received,
        loss_percent=loss,
        rtt_min_ms=rtt_min,
        rtt_avg_ms=rtt_avg,
        rtt_max_ms=rtt_max,
    )


def ping_host(target: str, count: int = 3, timeout: float = 2.0) -> PingResult:
    """Ping one host with bounded count and timeout."""
    target = validate_target(target)
    count = validate_positive_int("count", count, maximum=100)
    timeout = validate_timeout(timeout)
    argv = _ping_argv(target, count, timeout)
    try:
        proc = subprocess.run(
            argv,
            capture_output=True,
            text=True,
            timeout=_DEFAULT_TIMEOUT,
            check=False,
        )
    except FileNotFoundError:
        return PingResult(
            target=target, reachable=False, error="ping utility not found"
        )
    except subprocess.TimeoutExpired:
        return PingResult(target=target, reachable=False, error="ping timed out")
    except OSError as exc:
        return PingResult(target=target, reachable=False, error=f"ping failed: {exc}")
    parsed = _parse_output(proc.stdout + proc.stderr, count)
    if parsed is None:
        return PingResult(
            target=target,
            reachable=False,
            transmitted=count,
            error="could not parse ping output",
        )
    parsed.target = target
    return parsed


def ping_many(
    targets: list[str],
    count: int = 3,
    timeout: float = 2.0,
    max_parallel: int = 20,
) -> list[PingResult]:
    """Ping several hosts concurrently with a bounded worker pool."""
    from aegisforge.network.validation import validate_targets

    cleaned = validate_targets(targets, max_targets=256)
    max_parallel = validate_positive_int("max_parallel", max_parallel, maximum=50)
    results: dict[str, PingResult] = {}
    with ThreadPoolExecutor(max_workers=max_parallel) as pool:
        future_map = {
            pool.submit(ping_host, target, count, timeout): target for target in cleaned
        }
        for future in as_completed(future_map):
            target = future_map[future]
            try:
                results[target] = future.result()
            except ValidationError as exc:
                results[target] = PingResult(
                    target=target, reachable=False, error=str(exc)
                )
    return [results[target] for target in cleaned]
