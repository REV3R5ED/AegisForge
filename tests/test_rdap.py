"""Tests for RDAP lookups (HTTPS fully mocked)."""

import json
import urllib.request

import pytest

from aegisforge.domain import rdap as rdap_mod
from aegisforge.domain.rdap import RDAPError, find_rdap_server, rdap_lookup


class _FakeReply:
    def __init__(self, payload: bytes):
        self._payload = payload

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def read(self, size=-1):
        if size is None or size < 0:
            return self._payload
        return self._payload[:size]


@pytest.fixture()
def fake_https(monkeypatch):
    routes = {}

    def fake_urlopen(request, timeout=None, context=None):
        url = request.full_url if hasattr(request, "full_url") else request
        if url not in routes:
            raise AssertionError(f"unexpected HTTPS request: {url}")
        value = routes[url]
        if isinstance(value, Exception):
            raise value
        return _FakeReply(json.dumps(value).encode())

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
    return routes


_BOOTSTRAP = {
    "services": [
        [["com", "net"], ["https://rdap.verisign.com/com/v1/"]],
        [["example"], ["https://rdap.example/v1/"]],
    ]
}

_DOMAIN_PAYLOAD = {
    "status": ["active"],
    "events": [
        {"eventAction": "registration", "eventDate": "2000-01-01T00:00:00Z"},
        {"eventAction": "expiration", "eventDate": "2030-01-01T00:00:00Z"},
    ],
    "entities": [
        {
            "roles": ["registrar"],
            "vcardArray": [
                "vcard",
                [
                    ["version", {}, "text", "4.0"],
                    ["fn", {}, "text", "Example Registrar"],
                ],
            ],
        }
    ],
    "nameservers": [{"ldhName": "ns1.example.com"}],
}


def test_find_rdap_server_longest_suffix(fake_https):
    fake_https[rdap_mod.IANA_DNS_BOOTSTRAP] = _BOOTSTRAP
    server = find_rdap_server("www.example.com")
    assert server == "https://rdap.verisign.com/com/v1/"


def test_find_rdap_server_no_match(fake_https):
    fake_https[rdap_mod.IANA_DNS_BOOTSTRAP] = _BOOTSTRAP
    assert find_rdap_server("host.invalidtld") is None


def test_find_rdap_server_bootstrap_failure(fake_https):
    fake_https[rdap_mod.IANA_DNS_BOOTSTRAP] = OSError("offline")
    with pytest.raises(RDAPError):
        find_rdap_server("example.com")


def test_rdap_lookup_parses(fake_https):
    fake_https[rdap_mod.IANA_DNS_BOOTSTRAP] = _BOOTSTRAP
    fake_https["https://rdap.verisign.com/com/v1/domain/example.com"] = _DOMAIN_PAYLOAD
    result = rdap_lookup("example.com")
    assert result.error is None
    assert result.registrar == "Example Registrar"
    assert result.status == ["active"]
    assert result.events["registration"] == "2000-01-01T00:00:00Z"
    assert result.events["expiration"] == "2030-01-01T00:00:00Z"
    assert result.nameservers == ["ns1.example.com"]


def test_rdap_lookup_query_failure_graceful(fake_https):
    fake_https[rdap_mod.IANA_DNS_BOOTSTRAP] = _BOOTSTRAP
    fake_https["https://rdap.verisign.com/com/v1/domain/example.com"] = OSError("reset")
    result = rdap_lookup("example.com")
    assert result.error is not None
    assert "RDAP query failed" in result.error


def test_rdap_lookup_bootstrap_failure_graceful(fake_https):
    fake_https[rdap_mod.IANA_DNS_BOOTSTRAP] = OSError("offline")
    result = rdap_lookup("example.com")
    assert result.error is not None
    assert "bootstrap" in result.error


def test_rdap_lookup_bad_json(monkeypatch):
    def fake_urlopen(request, timeout=None, context=None):
        return _FakeReply(b"not json{")

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
    result = rdap_lookup("example.com", rdap_server="https://rdap.x/v1/")
    assert result.error is not None
