"""Tests for traceroute (subprocess is mocked — no real network)."""

import subprocess

import pytest

from aegisforge.network.trace import _parse_hops, traceroute
from aegisforge.network.validation import ValidationError

LINUX_TRACE = (
    "traceroute to 93.184.216.34 (93.184.216.34), 30 hops max\n"
    " 1  192.168.1.1  1.234 ms\n"
    " 2  * * *\n"
    " 3  10.20.30.1  8.123 ms\n"
    " 4  93.184.216.34  12.456 ms\n"
)


def _completed(stdout: str) -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess(
        args=["traceroute"], returncode=0, stdout=stdout, stderr=""
    )


def test_parse_hops():
    hops = _parse_hops(LINUX_TRACE)
    assert len(hops) == 4
    assert hops[0].hop == 1 and hops[0].ip == "192.168.1.1"
    assert hops[0].rtt_ms == pytest.approx(1.234)
    assert hops[1].ip is None  # timeout hop
    assert hops[3].ip == "93.184.216.34"


def test_traceroute_reaches_target(monkeypatch):
    monkeypatch.setattr(
        "aegisforge.network.trace.subprocess.run",
        lambda *a, **k: _completed(LINUX_TRACE),
    )
    result = traceroute("93.184.216.34", max_hops=30, timeout=2.0)
    assert result.reached is True
    assert len(result.hops) == 4
    assert result.error is None


def test_traceroute_not_reached(monkeypatch):
    monkeypatch.setattr(
        "aegisforge.network.trace.subprocess.run",
        lambda *a, **k: _completed("traceroute to 10.9.9.9\n 1  * * *\n"),
    )
    monkeypatch.setattr(
        "aegisforge.network.trace.socket.getaddrinfo",
        lambda *a, **k: [(None, None, None, None, ("10.9.9.9", 0))],
    )
    result = traceroute("10.9.9.9")
    assert result.reached is False


def test_traceroute_missing_binary(monkeypatch):
    def _missing(*a, **k):
        raise FileNotFoundError("no traceroute")

    monkeypatch.setattr("aegisforge.network.trace.subprocess.run", _missing)
    result = traceroute("example.com")
    assert result.reached is False
    assert "not found" in (result.error or "")


def test_traceroute_rejects_bad_target():
    with pytest.raises(ValidationError):
        traceroute("a;b")


def test_traceroute_rejects_too_many_hops():
    with pytest.raises(ValidationError):
        traceroute("example.com", max_hops=500)


def test_traceroute_uses_argument_list(monkeypatch):
    seen: dict[str, object] = {}

    def _capture(argv, **kwargs):
        seen["argv"] = argv
        return _completed(LINUX_TRACE)

    monkeypatch.setattr("aegisforge.network.trace.subprocess.run", _capture)
    traceroute("example.com", max_hops=5)
    assert isinstance(seen["argv"], list)
    assert "5" in seen["argv"]
