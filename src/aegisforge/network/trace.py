"""Bounded traceroute via the OS traceroute/tracert utility.

Argument lists only (never shell=True); hop count and per-hop timeout
are hard-bounded to keep the defensive posture of the tool.
"""

from __future__ import annotations

import platform
import re
import socket
import subprocess
from dataclasses import asdict, dataclass
from typing import Any

from aegisforge.network.validation import (
    validate_positive_int,
    validate_target,
    validate_timeout,
)

_HARD_MAX_HOPS = 64
_DEFAULT_TIMEOUT = 120.0


@dataclass
class TraceHop:
    hop: int
    ip: str | None
    hostname: str | None = None
    rtt_ms: float | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class TraceResult:
    target: str
    reached: bool
    hops: list[TraceHop]
    max_hops: int
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        return d


def _trace_argv(target: str, max_hops: int, timeout: float) -> list[str]:
    system = platform.system()
    if system == "Windows":
        # -d: no reverse DNS, -h: max hops, -w: per-hop timeout ms.
        return [
            "tracert",
            "-d",
            "-h",
            str(max_hops),
            "-w",
            str(int(timeout * 1000)),
            target,
        ]
    if system == "Darwin":
        # -n: numeric, -w: wait seconds, -m: max hops, -q: probes per hop.
        return [
            "traceroute",
            "-n",
            "-w",
            str(timeout),
            "-m",
            str(max_hops),
            "-q",
            "1",
            target,
        ]
    return [
        "traceroute",
        "-n",
        "-w",
        str(timeout),
        "-m",
        str(max_hops),
        "-q",
        "1",
        target,
    ]


_HOP_RE = re.compile(r"^\s*(\d+)\s+(.+)$")
_IP_RE = re.compile(r"(\d{1,3}(?:\.\d{1,3}){3}|[0-9a-fA-F:]{2,39})")
_RTT_RE = re.compile(r"([\d.]+)\s*ms")


def _parse_hops(output: str) -> list[TraceHop]:
    hops: list[TraceHop] = []
    for line in output.splitlines():
        match = _HOP_RE.match(line)
        if not match:
            continue
        hop_no = int(match.group(1))
        rest = match.group(2)
        if "*" in rest and not _IP_RE.search(rest):
            hops.append(TraceHop(hop=hop_no, ip=None))
            continue
        ip_match = _IP_RE.search(rest)
        rtt_match = _RTT_RE.search(rest)
        hops.append(
            TraceHop(
                hop=hop_no,
                ip=ip_match.group(1) if ip_match else None,
                rtt_ms=float(rtt_match.group(1)) if rtt_match else None,
            )
        )
    return hops


def traceroute(target: str, max_hops: int = 30, timeout: float = 2.0) -> TraceResult:
    """Run a bounded traceroute to a single explicit target."""
    target = validate_target(target)
    max_hops = validate_positive_int("max_hops", max_hops, maximum=_HARD_MAX_HOPS)
    timeout = validate_timeout(timeout)
    argv = _trace_argv(target, max_hops, timeout)
    try:
        proc = subprocess.run(
            argv, capture_output=True, text=True, timeout=_DEFAULT_TIMEOUT, check=False
        )
    except FileNotFoundError:
        return TraceResult(
            target=target,
            reached=False,
            hops=[],
            max_hops=max_hops,
            error="traceroute utility not found",
        )
    except subprocess.TimeoutExpired:
        return TraceResult(
            target=target,
            reached=False,
            hops=[],
            max_hops=max_hops,
            error="traceroute timed out",
        )
    except OSError as exc:
        return TraceResult(
            target=target,
            reached=False,
            hops=[],
            max_hops=max_hops,
            error=f"traceroute failed: {exc}",
        )
    hops = _parse_hops(proc.stdout)
    reached = any(h.ip == target for h in hops if h.ip)
    if not reached:
        # Fall back to resolving the target and comparing.
        try:
            resolved = {info[4][0] for info in socket.getaddrinfo(target, None)}
            reached = any(h.ip in resolved for h in hops if h.ip)
        except OSError:
            pass
    return TraceResult(target=target, reached=reached, hops=hops, max_hops=max_hops)
