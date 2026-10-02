"""Tests for HTTP response-head metadata parsing."""

from aegisforge.network.http import parse_response_head, summarize

HEAD_OK = (
    "HTTP/1.1 200 OK\r\n"
    "Server: nginx/1.25.3\r\n"
    "Content-Type: text/html\r\n"
    "Content-Length: 123\r\n"
    "\r\n"
)

HEAD_REDIRECT = (
    "HTTP/1.1 301 Moved Permanently\r\n"
    "Server: Apache\r\n"
    "Location: https://example.com/new\r\n"
    "\r\n"
)


def test_parse_ok_response():
    meta = parse_response_head(HEAD_OK, "example.com", 80)
    assert meta.error is None
    assert meta.status_code == 200
    assert meta.reason == "OK"
    assert meta.http_version == "1.1"
    assert meta.server == "nginx/1.25.3"
    assert meta.content_type == "text/html"
    assert meta.is_redirect is False
    assert meta.use_tls is False


def test_parse_redirect():
    meta = parse_response_head(HEAD_REDIRECT, "example.com", 80)
    assert meta.is_redirect is True
    assert meta.location == "https://example.com/new"


def test_parse_https_flag():
    meta = parse_response_head(HEAD_OK, "example.com", 443, use_tls=True)
    assert meta.use_tls is True


def test_parse_garbage():
    meta = parse_response_head("SSH-2.0-OpenSSH", "h", 22)
    assert meta.error is not None and "not an HTTP" in meta.error


def test_parse_empty():
    meta = parse_response_head("", "h", 80)
    assert meta.error == "empty response"


def test_parse_bad_status_code():
    meta = parse_response_head("HTTP/1.1 XX OK\r\n\r\n", "h", 80)
    assert meta.error is not None and "status code" in meta.error


def test_parse_header_case_insensitive():
    head = "HTTP/1.0 404 Not Found\r\nSERVER: custom/1.0\r\n\r\n"
    meta = parse_response_head(head, "h", 80)
    assert meta.status_code == 404
    assert meta.server == "custom/1.0"


def test_summarize():
    meta = parse_response_head(HEAD_OK, "example.com", 80)
    summary = summarize(meta)
    assert "200" in summary and "nginx" in summary
    redirect = summarize(parse_response_head(HEAD_REDIRECT, "h", 80))
    assert "https://example.com/new" in redirect
    error_meta = parse_response_head("", "h", 80)
    assert "error" in summarize(error_meta)


def test_metadata_to_dict():
    d = parse_response_head(HEAD_OK, "example.com", 80).to_dict()
    assert d["status_code"] == 200
    assert d["headers"]["server"] == "nginx/1.25.3"
