"""Tests for HTTP header/redirect collection (http.client fully mocked)."""

import http.client

import pytest

from aegisforge.domain.web import fetch_headers


class _FakeReply:
    def __init__(self, status, headers):
        self.status = status
        self._headers = headers

    def getheaders(self):
        return self._headers

    def read(self, size=-1):
        return b""


class _FakeConnection:
    routes = {}

    def __init__(self, host, port, timeout=None, context=None):
        self.host = host
        self.port = port
        self.requested = []

    def request(self, method, path, headers=None):
        self.requested.append((method, path))
        key = (self.host, self.port, path)
        if key not in _FakeConnection.routes:
            raise AssertionError(f"unexpected HTTP request: {key}")

    def getresponse(self):
        method, path = self.requested[-1]
        status, headers = _FakeConnection.routes[(self.host, self.port, path)]
        return _FakeReply(status, headers)

    def close(self):
        pass


@pytest.fixture()
def fake_http(monkeypatch):
    _FakeConnection.routes = {}
    monkeypatch.setattr(http.client, "HTTPConnection", _FakeConnection)
    monkeypatch.setattr(http.client, "HTTPSConnection", _FakeConnection)
    return _FakeConnection.routes


def test_simple_get_records_headers(fake_http):
    fake_http[("example.com", 80, "/")] = (
        200,
        [("Server", "nginx/1.24"), ("Content-Type", "text/html; charset=utf-8")],
    )
    result = fetch_headers("http://example.com/")
    assert result.error is None
    assert result.status_code == 200
    assert result.server == "nginx/1.24"
    assert result.content_type == "text/html"
    assert result.final_url == "http://example.com/"
    assert len(result.hops) == 1


def test_redirect_chain_followed(fake_http):
    fake_http[("example.com", 80, "/")] = (
        301,
        [("Location", "https://example.com/")],
    )
    fake_http[("example.com", 443, "/")] = (
        302,
        [("Location", "/home")],
    )
    fake_http[("example.com", 443, "/home")] = (200, [("Server", "x")])
    result = fetch_headers("http://example.com/")
    assert result.error is None
    assert result.status_code == 200
    assert result.final_url == "https://example.com/home"
    assert [hop.status for hop in result.hops] == [301, 302, 200]
    assert result.use_tls is True


def test_too_many_redirects(fake_http):
    for i in range(8):
        fake_http[("example.com", 80, f"/{i}")] = (301, [("Location", f"/{i + 1}")])
    result = fetch_headers("http://example.com/0")
    assert result.error is not None
    assert "redirect" in result.error


def test_connection_failure_graceful(monkeypatch):
    class DeadConnection:
        def __init__(self, *a, **k):
            pass

        def request(self, *a, **k):
            raise OSError("connection refused")

        def close(self):
            pass

    monkeypatch.setattr(http.client, "HTTPConnection", DeadConnection)
    result = fetch_headers("http://example.com/")
    assert result.error is not None
    assert "failed" in result.error


def test_unsupported_scheme():
    result = fetch_headers("ftp://example.com/")
    assert result.error is not None
    assert "scheme" in result.error


def test_redirect_loop_detected(fake_http):
    fake_http[("example.com", 80, "/a")] = (301, [("Location", "/b")])
    fake_http[("example.com", 80, "/b")] = (301, [("Location", "/a")])
    result = fetch_headers("http://example.com/a")
    assert result.error is not None
    assert "loop" in result.error
