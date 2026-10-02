"""Tests for DNS lookups (socket is mocked — no real network)."""

import socket

import pytest

from aegisforge.network.dns import DNSError, lookup, resolve_forward, resolve_reverse
from aegisforge.network.validation import ValidationError


def test_resolve_forward(monkeypatch):
    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda *a, **k: [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 0)),
            (
                socket.AF_INET6,
                socket.SOCK_STREAM,
                6,
                "",
                ("2606:2800:220:1::1", 0, 0, 0),
            ),
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 0)),  # dup
        ],
    )
    result = resolve_forward("example.com")
    assert result.query == "example.com"
    ips = [a["ip"] for a in result.addresses]
    assert ips == ["93.184.216.34", "2606:2800:220:1::1"]
    assert result.addresses[0]["family"] == "IPv4"
    assert result.addresses[1]["family"] == "IPv6"


def test_resolve_forward_failure(monkeypatch):
    def _fail(*a, **k):
        raise socket.gaierror(-2, "Name or service not known")

    monkeypatch.setattr(socket, "getaddrinfo", _fail)
    with pytest.raises(DNSError, match="cannot resolve"):
        resolve_forward("nope.invalid")


def test_resolve_reverse(monkeypatch):
    monkeypatch.setattr(
        socket, "gethostbyaddr", lambda ip: ("host.example", [], ["93.184.216.34"])
    )
    result = resolve_reverse("93.184.216.34")
    assert result.reverse_name == "host.example"
    assert result.addresses[0]["family"] == "IPv4"


def test_resolve_reverse_failure(monkeypatch):
    def _fail(ip):
        raise socket.herror(1, "Unknown host")

    monkeypatch.setattr(socket, "gethostbyaddr", _fail)
    with pytest.raises(DNSError, match="cannot reverse-resolve"):
        resolve_reverse("10.255.255.1")


def test_lookup_dispatches_on_ip_literal(monkeypatch):
    monkeypatch.setattr(socket, "gethostbyaddr", lambda ip: ("rev.example", [], [ip]))
    result = lookup("10.0.0.1")
    assert result.reverse_name == "rev.example"


def test_lookup_rejects_bad_target():
    with pytest.raises((DNSError, ValidationError)):
        lookup("")


def test_lookup_timeout(monkeypatch):
    import time

    def _slow(*a, **k):
        time.sleep(5)
        return []

    monkeypatch.setattr(socket, "getaddrinfo", _slow)
    with pytest.raises(DNSError, match="timed out"):
        resolve_forward("example.com", timeout=0.2)
