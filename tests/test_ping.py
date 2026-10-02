"""Tests for ping (subprocess is mocked — no real network)."""

import subprocess

import pytest

from aegisforge.network.ping import _parse_output, ping_host, ping_many
from aegisforge.network.validation import ValidationError

LINUX_OK = """PING example.com (93.184.216.34) 56(84) bytes of data.
64 bytes from 93.184.216.34: icmp_seq=1 ttl=55 time=12.3 ms
64 bytes from 93.184.216.34: icmp_seq=2 ttl=55 time=11.9 ms
64 bytes from 93.184.216.34: icmp_seq=3 ttl=55 time=12.1 ms

--- example.com ping statistics ---
3 packets transmitted, 3 received, 0% packet loss, time 2003ms
rtt min/avg/max/mdev = 11.900/12.100/12.300/0.164 ms
"""

LINUX_LOSS = """PING down.example (10.0.0.9) 56(84) bytes of data.

--- down.example ping statistics ---
3 packets transmitted, 0 received, 100% packet loss, time 2042ms
"""


def _completed(stdout: str, returncode: int = 0) -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess(
        args=["ping"], returncode=returncode, stdout=stdout, stderr=""
    )


def test_parse_linux_output():
    parsed = _parse_output(LINUX_OK, 3)
    assert parsed is not None
    assert parsed.transmitted == 3
    assert parsed.received == 3
    assert parsed.loss_percent == 0.0
    assert parsed.rtt_avg_ms == pytest.approx(12.1)


def test_parse_loss_output():
    parsed = _parse_output(LINUX_LOSS, 3)
    assert parsed is not None
    assert parsed.received == 0
    assert parsed.loss_percent == 100.0


def test_parse_garbage_returns_none():
    assert _parse_output("totally unrelated text", 3) is None


def test_ping_host_success(monkeypatch):
    monkeypatch.setattr(
        "aegisforge.network.ping.subprocess.run",
        lambda *a, **k: _completed(LINUX_OK),
    )
    result = ping_host("example.com", count=3, timeout=2.0)
    assert result.target == "example.com"
    assert result.reachable is True
    assert result.received == 3


def test_ping_host_unreachable(monkeypatch):
    monkeypatch.setattr(
        "aegisforge.network.ping.subprocess.run",
        lambda *a, **k: _completed(LINUX_LOSS, returncode=1),
    )
    result = ping_host("down.example")
    assert result.reachable is False
    assert result.loss_percent == 100.0


def test_ping_host_no_ping_binary(monkeypatch):
    def _missing(*a, **k):
        raise FileNotFoundError("no ping")

    monkeypatch.setattr("aegisforge.network.ping.subprocess.run", _missing)
    result = ping_host("example.com")
    assert result.reachable is False
    assert "not found" in (result.error or "")


def test_ping_host_timeout_expired(monkeypatch):
    def _expired(*a, **k):
        raise subprocess.TimeoutExpired(cmd="ping", timeout=30)

    monkeypatch.setattr("aegisforge.network.ping.subprocess.run", _expired)
    result = ping_host("example.com")
    assert result.reachable is False
    assert "timed out" in (result.error or "")


def test_ping_host_rejects_bad_target():
    with pytest.raises(ValidationError):
        ping_host("evil; rm -rf /")


def test_ping_host_rejects_bad_count():
    with pytest.raises(ValidationError):
        ping_host("example.com", count=0)


def test_ping_many_orders_and_concurrency(monkeypatch):
    monkeypatch.setattr(
        "aegisforge.network.ping.subprocess.run",
        lambda *a, **k: _completed(LINUX_OK),
    )
    results = ping_many(["b.example", "a.example", "a.example"], max_parallel=2)
    assert [r.target for r in results] == ["b.example", "a.example"]
    assert all(r.reachable for r in results)


def test_ping_many_rejects_too_many():
    with pytest.raises(ValidationError):
        ping_many([f"h{i}.example" for i in range(300)])


def test_ping_uses_argument_list_not_shell(monkeypatch):
    seen: dict[str, object] = {}

    def _capture(argv, **kwargs):
        seen["argv"] = argv
        seen["kwargs"] = kwargs
        return _completed(LINUX_OK)

    monkeypatch.setattr("aegisforge.network.ping.subprocess.run", _capture)
    ping_host("example.com")
    assert isinstance(seen["argv"], list)
    assert seen["kwargs"].get("shell") in (None, False)
