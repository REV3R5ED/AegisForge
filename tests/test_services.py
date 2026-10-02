"""Tests for banner grabbing and service identification (no real network)."""

from aegisforge.network import services as services_mod
from aegisforge.network.services import grab_banner, identify_service


class FakeSocket:
    def __init__(self, recv_data: bytes = b""):
        self._recv_data = recv_data
        self._timeout: float | None = 2.0
        self.sent = bytearray()

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


def test_identify_ssh_banner():
    assert identify_service(22, "SSH-2.0-OpenSSH_9.6") == "ssh"
    assert identify_service(2222, "SSH-2.0-dropbear") == "ssh"


def test_identify_smtp_ftp_banners():
    assert identify_service(25, "220 mail.example.com ESMTP") == "smtp"
    assert identify_service(587, "220 mail.example.com ESMTP") == "smtp"
    assert identify_service(21, "220 FTP Server ready") == "ftp"


def test_identify_http_banner():
    assert identify_service(8080, "HTTP/1.1 200 OK") == "http"
    assert identify_service(443, "HTTP/1.1 200 OK", tls=True) == "https"


def test_identify_mysql_pop3_imap():
    assert identify_service(3306, "5.7.44\\x00mysql_native_password") == "mysql"
    assert identify_service(110, "+OK POP3 ready") == "pop3"
    assert identify_service(143, "* OK IMAP4 ready") == "imap"


def test_identify_falls_back_to_port_map():
    assert identify_service(22, None) == "ssh"
    assert identify_service(3389, None) == "rdp"
    assert identify_service(12345, None) == "unknown"
    assert identify_service(443, None, tls=True) == "https"


def test_grab_banner_passive():
    sock = FakeSocket(b"SSH-2.0-OpenSSH_9.6\r\n")
    assert grab_banner(sock, 22) == "SSH-2.0-OpenSSH_9.6"


def test_grab_banner_sends_head_for_http_ports():
    sock = FakeSocket(b"HTTP/1.1 200 OK\r\nServer: x\r\n\r\n")
    banner = grab_banner(sock, 80, host="example.com")
    assert banner is not None and "HTTP/1.1 200 OK" in banner
    assert b"HEAD / HTTP/1.0" in sock.sent
    assert b"Host: example.com" in sock.sent


def test_grab_banner_none_when_silent():
    assert grab_banner(FakeSocket(b""), 22) is None


def test_grab_banner_sanitizes_and_truncates():
    sock = FakeSocket(b"\x00\x01" + b"A" * 500 + b"\r\n")
    banner = grab_banner(sock, 22)
    assert banner is not None
    assert "\x00" not in banner
    assert len(banner) <= 203  # 200 chars + ellipsis


def test_grab_banner_send_failure_returns_none():
    class Broken(FakeSocket):
        def sendall(self, data):
            raise OSError("broken pipe")

    assert grab_banner(Broken(), 80) is None


def test_tls_and_http_port_sets():
    assert 443 in services_mod.TLS_PORTS
    assert 80 in services_mod.HTTP_PORTS
    assert 22 not in services_mod.TLS_PORTS
