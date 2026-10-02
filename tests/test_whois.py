"""Tests for WHOIS lookups (TCP port 43 fully mocked)."""

import socket

import pytest

from aegisforge.domain.whois import whois_lookup


@pytest.fixture()
def fake_whois(monkeypatch):
    servers = set()
    payloads = {}

    class RoutingSocket:
        def __init__(self, *args, **kwargs):
            pass

        def settimeout(self, timeout):
            pass

        def connect(self, addr):
            self._server = addr[0]
            if self._server not in servers:
                raise OSError(f"connection refused: {self._server}")

        def sendall(self, data):
            self._query = data.decode().strip().lower()

        def recv(self, size):
            key = (self._server, self._query)
            if key not in payloads:
                raise AssertionError(f"unexpected WHOIS query: {key}")
            data = payloads[key]
            payloads[key] = b""  # single read, then EOF
            return data

        def close(self):
            pass

    monkeypatch.setattr(socket, "socket", lambda *a, **k: RoutingSocket())
    return servers, payloads


def test_whois_follows_referral(fake_whois):
    servers, payloads = fake_whois
    servers.add("whois.iana.org")
    servers.add("whois.verisign-grs.com")
    payloads[("whois.iana.org", "example.com")] = (
        b"domain: EXAMPLE.COM\nwhois: whois.verisign-grs.com\n"
    )
    payloads[("whois.verisign-grs.com", "example.com")] = (
        b"Domain Name: EXAMPLE.COM\nRegistrar: Example Registrar\n"
        b"Registry Expiry Date: 2030-01-01T00:00:00Z\n"
    )
    result = whois_lookup("example.com")
    assert result.error is None
    assert result.referral_server == "whois.verisign-grs.com"
    assert result.fields["registrar"] == "Example Registrar"
    assert "2030-01-01" in result.fields["expiry_date"]
    assert "EXAMPLE.COM" in result.raw


def test_whois_no_referral_single_query(fake_whois):
    servers, payloads = fake_whois
    servers.add("whois.iana.org")
    payloads[("whois.iana.org", "example.com")] = b"Registrar: Example Registrar\n"
    result = whois_lookup("example.com")
    assert result.referral_server is None
    assert result.fields["registrar"] == "Example Registrar"


def test_whois_referral_failure_keeps_first_reply(fake_whois):
    servers, payloads = fake_whois
    servers.add("whois.iana.org")
    payloads[("whois.iana.org", "example.com")] = (
        b"domain: EXAMPLE.COM\nwhois: whois.down.example\n"
    )
    # whois.down.example is not in `replies` -> connect raises.
    result = whois_lookup("example.com")
    assert result.referral_server == "whois.down.example"
    assert result.error is not None
    assert "referral" in result.error
    assert "EXAMPLE.COM" in result.raw


def test_whois_connection_failure_graceful(monkeypatch):
    class DeadSocket:
        def __init__(self, *a, **k):
            pass

        def settimeout(self, t):
            pass

        def connect(self, addr):
            raise OSError("connection refused")

        def close(self):
            pass

    monkeypatch.setattr(socket, "socket", lambda *a, **k: DeadSocket())
    result = whois_lookup("example.com")
    assert result.error is not None
    assert "failed" in result.error


def test_whois_alternate_referral_header(fake_whois):
    servers, payloads = fake_whois
    servers.add("whois.iana.org")
    servers.add("whois.pir.org")
    payloads[("whois.iana.org", "example.org")] = (
        b"domain: EXAMPLE.ORG\nWhois Server: whois.pir.org\n"
    )
    payloads[("whois.pir.org", "example.org")] = b"Registrar: PIR Registrar\n"
    result = whois_lookup("example.org")
    assert result.referral_server == "whois.pir.org"
    assert result.fields["registrar"] == "PIR Registrar"
