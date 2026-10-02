"""Tests for the DNS wire client (packet builder/parser, byte vectors)."""

import socket
import struct

import pytest

from aegisforge.domain import dns_client
from aegisforge.domain.dns_client import (
    DNSParseError,
    _decode_name,
    build_query,
    encode_name,
    parse_response,
    query,
    system_resolvers,
)
from aegisforge.network.validation import ValidationError

QID = 0x1234


def _question(name: str, qtype_num: int) -> bytes:
    return encode_name(name) + struct.pack(">HH", qtype_num, 1)


def _rr(name: bytes, rtype: int, ttl: int, rdata: bytes) -> bytes:
    return name + struct.pack(">HHIH", rtype, 1, ttl, len(rdata)) + rdata


def _response(
    qname: str, qtype_num: int, answers: list[bytes], rcode: int = 0, tc: bool = False
) -> bytes:
    flags = 0x8180 | (0x0200 if tc else 0) | (rcode & 0xF)
    header = struct.pack(">HHHHHH", QID, flags, 1, len(answers), 0, 0)
    return header + _question(qname, qtype_num) + b"".join(answers)


PTR_QNAME = struct.pack(">H", 0xC00C)  # pointer to the question name


def test_encode_name_roundtrip():
    assert encode_name("example.com") == b"\x07example\x03com\x00"
    assert encode_name("EXAMPLE.COM.") == b"\x07EXAMPLE\x03COM\x00"
    assert encode_name("") == b"\x00"


def test_encode_name_label_too_long():
    with pytest.raises(ValidationError):
        encode_name("x" * 64 + ".com")


def test_build_query_structure():
    packet = build_query("example.com", "A", QID)
    qid, flags, qd, an, ns, ar = struct.unpack(">HHHHHH", packet[:12])
    assert qid == QID
    assert flags == 0x0100  # recursion desired
    assert (qd, an, ns, ar) == (1, 0, 0, 0)
    qtype, qclass = struct.unpack(">HH", packet[-4:])
    assert (qtype, qclass) == (1, 1)


def test_build_query_bad_type():
    with pytest.raises(ValidationError):
        build_query("example.com", "PTR", QID)


def test_parse_a_record():
    rdata = socket.inet_aton("93.184.216.34")
    packet = _response("example.com", 1, [_rr(PTR_QNAME, 1, 300, rdata)])
    response = parse_response(packet, QID, "example.com", "A")
    assert response.ok and not response.truncated
    assert len(response.answers) == 1
    record = response.answers[0]
    assert record.rtype == "A"
    assert record.ttl == 300
    assert record.data["address"] == "93.184.216.34"


def test_parse_aaaa_record():
    rdata = bytes.fromhex("26062800022000010248189325c81946")
    packet = _response("example.com", 28, [_rr(PTR_QNAME, 28, 300, rdata)])
    response = parse_response(packet, QID, "example.com", "AAAA")
    assert response.answers[0].data["address"] == "2606:2800:220:1:248:1893:25c8:1946"


def test_parse_mx_record():
    rdata = struct.pack(">H", 10) + encode_name("mail.example.com")
    packet = _response("example.com", 15, [_rr(PTR_QNAME, 15, 300, rdata)])
    response = parse_response(packet, QID, "example.com", "MX")
    record = response.answers[0]
    assert record.data["preference"] == 10
    assert record.data["exchange"] == "mail.example.com"


def test_parse_ns_record():
    rdata = encode_name("ns1.example.com")
    packet = _response("example.com", 2, [_rr(PTR_QNAME, 2, 300, rdata)])
    response = parse_response(packet, QID, "example.com", "NS")
    assert response.answers[0].data["nameserver"] == "ns1.example.com"


def test_parse_cname_record():
    rdata = encode_name("alias.example.net")
    packet = _response("example.com", 5, [_rr(PTR_QNAME, 5, 300, rdata)])
    response = parse_response(packet, QID, "example.com", "CNAME")
    assert response.answers[0].data["target"] == "alias.example.net"


def test_parse_txt_record():
    rdata = b"\x0bv=spf1 -all" + b"\x05hello"
    packet = _response("example.com", 16, [_rr(PTR_QNAME, 16, 300, rdata)])
    response = parse_response(packet, QID, "example.com", "TXT")
    record = response.answers[0]
    assert record.data["strings"] == ["v=spf1 -all", "hello"]
    assert record.data["text"] == "v=spf1 -allhello"


def test_parse_soa_record():
    rdata = (
        encode_name("ns1.example.com")
        + encode_name("hostmaster.example.com")
        + struct.pack(">IIIII", 2026010101, 7200, 3600, 1209600, 300)
    )
    packet = _response("example.com", 6, [_rr(PTR_QNAME, 6, 300, rdata)])
    response = parse_response(packet, QID, "example.com", "SOA")
    data = response.answers[0].data
    assert data["mname"] == "ns1.example.com"
    assert data["rname"] == "hostmaster.example.com"
    assert data["serial"] == 2026010101
    assert data["minimum"] == 300


def test_parse_dnskey_record():
    key = bytes(range(32))
    rdata = struct.pack(">HBB", 257, 3, 8) + key
    packet = _response("example.com", 48, [_rr(PTR_QNAME, 48, 300, rdata)])
    response = parse_response(packet, QID, "example.com", "DNSKEY")
    data = response.answers[0].data
    assert data["flags"] == 257
    assert data["algorithm"] == 8
    assert data["is_sep"] is True
    assert 0 <= data["key_tag"] <= 65535


def test_parse_ds_record():
    rdata = struct.pack(">HBB", 12345, 8, 2) + bytes.fromhex("ab" * 32)
    packet = _response("example.com", 43, [_rr(PTR_QNAME, 43, 300, rdata)])
    response = parse_response(packet, QID, "example.com", "DS")
    data = response.answers[0].data
    assert data["key_tag"] == 12345
    assert data["digest"] == "ab" * 32


def test_parse_multiple_answers_sorted_by_wire_order():
    answers = [
        _rr(PTR_QNAME, 1, 300, socket.inet_aton("93.184.216.34")),
        _rr(PTR_QNAME, 1, 300, socket.inet_aton("93.184.216.35")),
    ]
    packet = _response("example.com", 1, answers)
    response = parse_response(packet, QID, "example.com", "A")
    assert [a.data["address"] for a in response.answers] == [
        "93.184.216.34",
        "93.184.216.35",
    ]


def test_nxdomain_is_warning_not_crash():
    packet = _response("nope.example.com", 1, [], rcode=3)
    response = parse_response(packet, QID, "nope.example.com", "A")
    assert not response.ok
    assert response.rcode_name == "NXDOMAIN"
    assert response.answers == []
    assert any("NXDOMAIN" in w for w in response.warnings)


def test_refused_is_warning():
    packet = _response("example.com", 1, [], rcode=5)
    response = parse_response(packet, QID, "example.com", "A")
    assert any("REFUSED" in w for w in response.warnings)


def test_truncated_flag_recorded():
    rdata = socket.inet_aton("93.184.216.34")
    packet = _response("example.com", 1, [_rr(PTR_QNAME, 1, 300, rdata)], tc=True)
    response = parse_response(packet, QID, "example.com", "A")
    assert response.truncated
    assert any("truncated" in w for w in response.warnings)


def test_qid_mismatch_raises():
    packet = _response("example.com", 1, [])
    with pytest.raises(DNSParseError, match="transaction id mismatch"):
        parse_response(packet, QID + 1, "example.com", "A")


def test_short_message_raises():
    with pytest.raises(DNSParseError, match="too short"):
        parse_response(b"\x12\x34", QID, "example.com", "A")


def test_compression_loop_becomes_warning():
    # Answer name is a pointer to itself: the parser records a
    # "partial parse" warning instead of crashing the whole response.
    qname = encode_name("example.com")
    question = qname + struct.pack(">HH", 1, 1)
    answer_offset = 12 + len(question)
    rr = (
        struct.pack(">H", 0xC000 | answer_offset)
        + struct.pack(">HHIH", 1, 1, 300, 4)
        + socket.inet_aton("1.2.3.4")
    )
    header = struct.pack(">HHHHHH", QID, 0x8180, 1, 1, 0, 0)
    packet = header + question + rr
    response = parse_response(packet, QID, "example.com", "A")
    assert response.answers == []
    assert any("partial parse" in w for w in response.warnings)


def test_decode_name_plain():
    buf = encode_name("www.example.com") + b"EXTRA"
    name, end = _decode_name(buf, 0)
    assert name == "www.example.com"
    assert buf[end : end + 5] == b"EXTRA"


# ---------------------------------------------------------------------------
# query() with mocked sockets
# ---------------------------------------------------------------------------


class _FakeUDPSocket:
    def __init__(self, response: bytes):
        self._response = response
        self.sent: bytes | None = None

    def settimeout(self, timeout):
        pass

    def sendto(self, data, addr):
        self.sent = data

    def recvfrom(self, size):
        return self._response, ("8.8.8.8", 53)

    def close(self):
        pass


class _FakeTCPSocket:
    def __init__(self, response: bytes):
        self._response = response
        self.sent: bytes | None = None
        self._read_pos = 0

    def settimeout(self, timeout):
        pass

    def connect(self, addr):
        pass

    def sendall(self, data):
        self.sent = data

    def recv(self, size):
        chunk = self._response[self._read_pos : self._read_pos + size]
        self._read_pos += size
        return chunk

    def close(self):
        pass


def _udp_responder(monkeypatch, response_builder):
    created = {}

    def fake_socket(family, kind):
        assert kind == socket.SOCK_DGRAM
        sock = _FakeUDPSocket(b"")
        created["sock"] = sock

        original_sendto = sock.sendto

        def sendto(data, addr):
            qid = struct.unpack(">H", data[:2])[0]
            sock._response = response_builder(qid)
            return original_sendto(data, addr)

        sock.sendto = sendto  # type: ignore[method-assign]
        return sock

    monkeypatch.setattr(socket, "socket", fake_socket)
    return created


def test_query_udp_success(monkeypatch):
    def builder(qid):
        rdata = socket.inet_aton("93.184.216.34")
        header = struct.pack(">HHHHHH", qid, 0x8180, 1, 1, 0, 0)
        return header + _question("example.com", 1) + _rr(PTR_QNAME, 1, 60, rdata)

    created = _udp_responder(monkeypatch, builder)
    response = query("example.com", "A", resolver="8.8.8.8", timeout=2.0)
    assert response.ok
    assert response.answers[0].data["address"] == "93.184.216.34"
    sent_qid = struct.unpack(">H", created["sock"].sent[:2])[0]
    assert sent_qid < 65536


def test_query_timeout_raises_dnserror(monkeypatch):
    class TimeoutSocket(_FakeUDPSocket):
        def recvfrom(self, size):
            raise TimeoutError("timed out")

    monkeypatch.setattr(socket, "socket", lambda family, kind: TimeoutSocket(b""))
    with pytest.raises(dns_client.DNSError, match="timed out"):
        query("example.com", "A", resolver="8.8.8.8", timeout=0.5)


def test_query_truncated_falls_back_to_tcp(monkeypatch):
    tcp_created = {}

    def builder(qid):
        rdata = socket.inet_aton("93.184.216.34")
        header = struct.pack(">HHHHHH", qid, 0x8380, 1, 1, 0, 0)  # TC set
        body = header + _question("example.com", 1) + _rr(PTR_QNAME, 1, 60, rdata)
        return struct.pack(">H", len(body)) + body

    def fake_socket(family, kind):
        if kind == socket.SOCK_DGRAM:
            qid_holder = {}

            class Udp(_FakeUDPSocket):
                def sendto(self, data, addr):
                    qid_holder["qid"] = struct.unpack(">H", data[:2])[0]
                    self.sent = data

                def recvfrom(self, size):
                    qid = qid_holder["qid"]
                    header = struct.pack(">HHHHHH", qid, 0x8380, 1, 0, 0, 0)
                    return header + _question("example.com", 1), ("8.8.8.8", 53)

            return Udp(b"")

        sock = _FakeTCPSocket(b"")
        tcp_created["sock"] = sock

        def sendall(data):
            (length,) = struct.unpack(">H", data[:2])
            qid = struct.unpack(">H", data[2:4])[0]
            sock._response = builder(qid)
            sock.sent = data

        sock.sendall = sendall  # type: ignore[method-assign]
        return sock

    monkeypatch.setattr(socket, "socket", fake_socket)
    response = query("example.com", "A", resolver="8.8.8.8", timeout=2.0)
    assert response.ok
    assert not response.truncated  # TCP answer is complete
    assert response.answers[0].data["address"] == "93.184.216.34"


def test_query_invalid_type():
    with pytest.raises(ValidationError):
        query("example.com", "PTR", resolver="8.8.8.8")


def test_system_resolvers_returns_list():
    resolvers = system_resolvers()
    assert isinstance(resolvers, list) and resolvers
