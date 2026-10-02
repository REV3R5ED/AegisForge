"""Tests for the TCP port scanner (sockets are mocked — no real network)."""

import socket

import pytest

from aegisforge.network import scanner as scanner_mod
from aegisforge.network.scanner import (
    CLOSED,
    FILTERED,
    OPEN,
    ScanAuthorizationError,
    ScanOptions,
    scan_host,
    scan_port,
)
from aegisforge.network.validation import ValidationError


class FakeSocket:
    """Minimal connected-socket double for scan_port."""

    def __init__(self, recv_data: bytes = b""):
        self._recv_data = recv_data
        self._timeout: float | None = None
        self.sent = bytearray()
        self.closed = False

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
        return False

    def settimeout(self, value):
        self._timeout = value

    def gettimeout(self):
        return self._timeout

    def sendall(self, data):
        self.sent.extend(data)

    def recv(self, n):
        if not self._recv_data:
            return b""
        chunk, self._recv_data = self._recv_data[:n], self._recv_data[n:]
        return chunk

    def close(self):
        self.closed = True


def _addrinfo(*ips):
    return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, 0)) for ip in ips]


@pytest.fixture()
def local_dns(monkeypatch):
    monkeypatch.setattr(
        scanner_mod.socket, "getaddrinfo", lambda *a, **k: _addrinfo("127.0.0.1")
    )


def _options(**overrides):
    base = {
        "timeout": 1.0,
        "retries": 0,
        "max_parallel": 4,
        "banner": False,
        "tls_probe": False,
        "http_probe": False,
    }
    base.update(overrides)
    return ScanOptions(**base)


def test_authorization_allows_localhost(local_dns):
    assert (
        scanner_mod.check_scan_authorization("localhost", allow_remote=False)
        == "127.0.0.1"
    )


def test_authorization_blocks_public_without_flag(monkeypatch):
    monkeypatch.setattr(
        scanner_mod.socket, "getaddrinfo", lambda *a, **k: _addrinfo("93.184.216.34")
    )
    with pytest.raises(ScanAuthorizationError, match="--allow-remote"):
        scanner_mod.check_scan_authorization("example.com", allow_remote=False)


def test_authorization_allows_public_with_flag(monkeypatch):
    monkeypatch.setattr(
        scanner_mod.socket, "getaddrinfo", lambda *a, **k: _addrinfo("93.184.216.34")
    )
    assert (
        scanner_mod.check_scan_authorization("example.com", allow_remote=True)
        == "93.184.216.34"
    )


def test_authorization_blocks_when_any_address_public(monkeypatch):
    monkeypatch.setattr(
        scanner_mod.socket,
        "getaddrinfo",
        lambda *a, **k: _addrinfo("127.0.0.1", "93.184.216.34"),
    )
    with pytest.raises(ScanAuthorizationError):
        scanner_mod.check_scan_authorization("example.com", allow_remote=False)


def test_authorization_unresolvable(monkeypatch):
    def _fail(*a, **k):
        raise socket.gaierror("no such host")

    monkeypatch.setattr(scanner_mod.socket, "getaddrinfo", _fail)
    with pytest.raises(ValidationError, match="cannot resolve"):
        scanner_mod.check_scan_authorization("nope.invalid", allow_remote=False)


def test_scan_port_open(monkeypatch, local_dns):
    monkeypatch.setattr(
        scanner_mod.socket,
        "create_connection",
        lambda *a, **k: FakeSocket(b"SSH-2.0-OpenSSH_9.6\r\n"),
    )
    result = scan_port("127.0.0.1", 22, "localhost", _options())
    assert result.state == OPEN
    assert result.port == 22
    assert result.attempts == 1
    assert result.rtt_ms is not None and result.rtt_ms >= 0


def test_scan_port_closed(monkeypatch, local_dns):
    def _refused(*a, **k):
        raise ConnectionRefusedError("refused")

    monkeypatch.setattr(scanner_mod.socket, "create_connection", _refused)
    result = scan_port("127.0.0.1", 22, "localhost", _options())
    assert result.state == CLOSED
    assert "refused" in (result.error or "")


def test_scan_port_filtered_after_retries(monkeypatch, local_dns):
    calls = []

    def _timeout(*a, **k):
        calls.append(1)
        raise TimeoutError("timed out")

    monkeypatch.setattr(scanner_mod.socket, "create_connection", _timeout)
    result = scan_port("127.0.0.1", 22, "localhost", _options(retries=2))
    assert result.state == FILTERED
    assert result.attempts == 3
    assert len(calls) == 3


def test_scan_port_unreachable_is_filtered(monkeypatch, local_dns):
    def _unreach(*a, **k):
        raise OSError(113, "No route to host")

    monkeypatch.setattr(scanner_mod.socket, "create_connection", _unreach)
    result = scan_port("127.0.0.1", 22, "localhost", _options())
    assert result.state == FILTERED


def test_scan_port_invalid_port_rejected(local_dns):
    with pytest.raises(ValidationError):
        scan_port("127.0.0.1", 0, "localhost", _options())


def test_scan_port_enriches_service(monkeypatch, local_dns):
    monkeypatch.setattr(
        scanner_mod.socket,
        "create_connection",
        lambda *a, **k: FakeSocket(b"SSH-2.0-OpenSSH_9.6\r\n"),
    )
    result = scan_port("127.0.0.1", 22, "localhost", _options(banner=True))
    assert result.state == OPEN
    assert result.service == "ssh"
    assert result.banner == "SSH-2.0-OpenSSH_9.6"


def test_scan_port_http_metadata(monkeypatch, local_dns):
    body = b"HTTP/1.1 200 OK\r\nServer: nginx/1.25\r\nContent-Length: 0\r\n\r\n"
    monkeypatch.setattr(
        scanner_mod.socket, "create_connection", lambda *a, **k: FakeSocket(body)
    )
    result = scan_port(
        "127.0.0.1", 80, "localhost", _options(banner=True, http_probe=True)
    )
    assert result.state == OPEN
    assert result.service == "http"
    assert result.http is not None
    assert result.http["status_code"] == 200
    assert result.http["server"] == "nginx/1.25"


def test_scan_host_runs_concurrently(monkeypatch, local_dns):
    def _fake_connect(address, timeout=None):
        _host, port = address
        if port % 2 == 0:
            return FakeSocket(b"")
        raise ConnectionRefusedError("refused")

    monkeypatch.setattr(scanner_mod.socket, "create_connection", _fake_connect)
    scan = scan_host("localhost", [21, 22, 23, 80], _options(max_parallel=2))
    assert scan.target == "localhost"
    assert scan.resolved_ip == "127.0.0.1"
    assert [p.port for p in scan.ports] == [21, 22, 23, 80]
    assert {p.port for p in scan.open_ports} == {22, 80}
    assert scan.duration_ms >= 0


def test_scan_host_rejects_empty_ports(local_dns):
    with pytest.raises(ValidationError, match="at least one port"):
        scan_host("localhost", [], _options())


def test_scan_host_rejects_public_without_flag(monkeypatch):
    monkeypatch.setattr(
        scanner_mod.socket, "getaddrinfo", lambda *a, **k: _addrinfo("93.184.216.34")
    )
    with pytest.raises(ScanAuthorizationError):
        scan_host("example.com", [80], _options())


def test_scan_options_validated():
    with pytest.raises(ValidationError):
        ScanOptions(timeout=0.01).validated()
    with pytest.raises(ValidationError):
        ScanOptions(retries=99).validated()
    with pytest.raises(ValidationError):
        ScanOptions(max_parallel=500).validated()
    assert ScanOptions().validated().timeout == 1.0


def test_default_ports_sane():
    assert scanner_mod.DEFAULT_PORTS == sorted(set(scanner_mod.DEFAULT_PORTS))
    assert 22 in scanner_mod.DEFAULT_PORTS
    assert 443 in scanner_mod.DEFAULT_PORTS
    assert len(scanner_mod.DEFAULT_PORTS) <= 64
