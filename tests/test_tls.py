"""Tests for TLS certificate inspection (fully mocked)."""

import pytest

from aegisforge.network import tls as tls_mod
from aegisforge.network.tls import (
    TLSInfo,
    describe_cert,
    hostname_matches_cert,
    inspect_tls,
)


def _cert(
    not_after="Oct  2 00:00:00 2030 GMT",
    san=(("DNS", "example.com"), ("DNS", "www.example.com")),
):
    return {
        "subject": ((("CN", "example.com"),),),
        "issuer": ((("CN", "Test CA"),),),
        "notBefore": "Oct  2 00:00:00 2020 GMT",
        "notAfter": not_after,
        "subjectAltName": san,
    }


class FakeTLSSocket:
    def __init__(self, cert):
        self._cert = cert
        self.closed = False

    def version(self):
        return "TLSv1.3"

    def cipher(self):
        return ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)

    def getpeercert(self):
        return self._cert

    def close(self):
        self.closed = True


def test_describe_cert_parses_fields():
    info = describe_cert(FakeTLSSocket(_cert()), "example.com", 443)
    assert info.error is None
    assert info.subject.get("CN") == "example.com"
    assert info.issuer.get("CN") == "Test CA"
    assert info.not_after is not None and info.not_after.startswith("2030-10-02")
    assert info.days_until_expiry is not None and info.days_until_expiry > 1400
    assert info.san_dns_names == ["example.com", "www.example.com"]
    assert info.protocol == "TLSv1.3"
    assert info.cipher == "TLS_AES_256_GCM_SHA384"
    assert info.hostname_verified is True


def test_describe_cert_hostname_mismatch():
    info = describe_cert(FakeTLSSocket(_cert()), "other.example", 443)
    assert info.hostname_verified is False


def test_describe_cert_wildcard():
    cert = _cert(san=(("DNS", "*.example.com"),))
    assert describe_cert(FakeTLSSocket(cert), "www.example.com", 443).hostname_verified
    assert not describe_cert(
        FakeTLSSocket(cert), "a.b.example.com", 443
    ).hostname_verified
    assert not describe_cert(FakeTLSSocket(cert), "example.com", 443).hostname_verified


def test_describe_cert_ip_san():
    cert = _cert(san=(("IP Address", "93.184.216.34"),))
    assert describe_cert(FakeTLSSocket(cert), "93.184.216.34", 443).hostname_verified
    assert not describe_cert(
        FakeTLSSocket(cert), "93.184.216.35", 443
    ).hostname_verified


def test_describe_cert_expired():
    info = describe_cert(
        FakeTLSSocket(_cert(not_after="Oct  2 00:00:00 2020 GMT")),
        "example.com",
        443,
    )
    assert info.days_until_expiry is not None and info.days_until_expiry < 0


def test_describe_cert_no_cert():
    class Empty(FakeTLSSocket):
        def getpeercert(self):
            return None

    info = describe_cert(Empty(None), "example.com", 443)
    assert info.error is not None and "no certificate" in info.error


def test_hostname_matches_cert_unit():
    assert hostname_matches_cert("example.com", ["example.com"], [], {})
    assert hostname_matches_cert("EXAMPLE.com", ["example.com"], [], {})
    assert not hostname_matches_cert("evil.com", ["example.com"], [], {})
    # CN fallback when no SANs.
    assert hostname_matches_cert("example.com", [], [], {"CN": "example.com"})


def test_inspect_tls_connect_failure(monkeypatch):

    def _fail(*a, **k):
        raise OSError("no route")

    monkeypatch.setattr(tls_mod.socket, "create_connection", _fail)
    info = inspect_tls("example.com", 443, timeout=1.0)
    assert info.error is not None and "TCP connect failed" in info.error


def test_inspect_tls_handshake_failure(monkeypatch):

    class Raw:
        def close(self):
            pass

    monkeypatch.setattr(tls_mod.socket, "create_connection", lambda *a, **k: Raw())
    monkeypatch.setattr(
        tls_mod,
        "wrap_tls",
        lambda *a, **k: (_ for _ in ()).throw(tls_mod.TLSProbeError("boom")),
    )
    info = inspect_tls("example.com", 443, timeout=1.0)
    assert info.error is not None and "boom" in info.error


def test_tls_info_to_dict_shape():
    info = TLSInfo(host="h", port=443)
    d = info.to_dict()
    assert d["host"] == "h" and d["port"] == 443
    assert "san_dns_names" in d and "hostname_verified" in d


def test_inspect_tls_success(monkeypatch):

    class Raw:
        def __init__(self):
            self.closed = False

        def settimeout(self, value):
            pass

        def close(self):
            self.closed = True

    raw = Raw()
    monkeypatch.setattr(tls_mod.socket, "create_connection", lambda *a, **k: raw)

    class FakeContext:
        def wrap_socket(self, sock, server_hostname=None):
            return FakeTLSSocket(_cert())

    monkeypatch.setattr(tls_mod, "_probe_context", lambda: FakeContext())
    info = inspect_tls("example.com", 443, timeout=1.0)
    assert info.error is None
    assert info.subject.get("CN") == "example.com"
    assert raw.closed is True


def test_inspect_tls_socket_fallback_on_handshake_failure():
    class Plain:
        def settimeout(self, value):
            raise OSError("socket closed")

    plain = Plain()
    info, sock = tls_mod.inspect_tls_socket(plain, "example.com", 443, timeout=1.0)
    # Real handshake against a dummy object fails -> error recorded,
    # original socket returned for plaintext fallback.
    assert info.error is not None
    assert sock is plain


def test_wrap_tls_failure_raises():

    class Bad:
        def settimeout(self, value):
            raise OSError("bad socket")

    with pytest.raises(tls_mod.TLSProbeError, match="handshake"):
        tls_mod.wrap_tls(Bad(), "example.com", timeout=1.0)


def test_describe_cert_bad_time_format():
    cert = _cert()
    cert["notAfter"] = "not a date"
    info = describe_cert(FakeTLSSocket(cert), "example.com", 443)
    assert info.not_after is None
    assert info.days_until_expiry is None
    assert info.error is None


def test_name_to_dict_edge_cases():
    assert tls_mod._name_to_dict(None) == {}
    assert tls_mod._name_to_dict([]) == {}
    assert tls_mod._name_to_dict(((("CN", "x"), ("O", "y")),)) == {
        "CN": "x",
        "O": "y",
    }
