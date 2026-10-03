"""Tests for the v0.7 PCAP analysis module: reader, decoders, DNS/HTTP/TLS
extraction, aggregation, findings, timeline, indicators, CLI wiring."""

from __future__ import annotations

import json
import struct
import tracemalloc

import pytest

from aegisforge.cli import main as cli_main
from aegisforge.core.plugins import get_registry
from aegisforge.pcap import analyze as pcap_analyze_mod
from aegisforge.pcap.analyze import AnalyzeOptions
from aegisforge.pcap.decoders import DecodeError, decode_frame
from aegisforge.pcap.dns_extract import is_dns_payload, parse_dns_message
from aegisforge.pcap.http_extract import extract_http
from aegisforge.pcap.reader import (
    PcapError,
    PcapngError,
    iter_packets,
    read_global_header,
)
from aegisforge.pcap.tls_extract import extract_tls

# ---------------------------------------------------------------------------
# Synthetic pcap builders
# ---------------------------------------------------------------------------


def _eth(dst_mac: bytes = b"\x00" * 6, src_mac: bytes = b"\x11" * 6) -> bytes:
    return dst_mac + src_mac + struct.pack(">H", 0x0800)


def _ipv4(
    payload: bytes,
    proto: int = 6,
    src: bytes = bytes([10, 0, 0, 1]),
    dst: bytes = bytes([10, 0, 0, 2]),
) -> bytes:
    header = struct.pack(">BBHHHBBH", 0x45, 0, 20 + len(payload), 1, 0, 64, proto, 0)
    return header + src + dst + payload


def _ipv6(
    payload: bytes,
    next_header: int = 6,
    src: bytes = bytes(15) + b"\x01",
    dst: bytes = bytes(15) + b"\x02",
) -> bytes:
    header = struct.pack(">IHBB", 0x60000000, len(payload), next_header, 64)
    return header + src + dst + payload


def _tcp(
    sport: int,
    dport: int,
    flags: int = 0x02,
    payload: bytes = b"",
    seq: int = 1,
) -> bytes:
    header = struct.pack(">HHIIHHHH", sport, dport, seq, 0, 0x5002, 100, 0, 0)
    # fix flags field: data offset (5) in high nibble
    header = header[:12] + struct.pack(">H", (5 << 12) | flags) + header[14:]
    return header + payload


def _udp(sport: int, dport: int, payload: bytes = b"") -> bytes:
    return struct.pack(">HHHH", sport, dport, 8 + len(payload), 0) + payload


def _dns_query(name: str = "example.com", qtype: int = 1, qid: int = 0x1234) -> bytes:
    header = struct.pack(">HHHHHH", qid, 0x0100, 1, 0, 0, 0)
    question = (
        b"".join(bytes([len(part)]) + part.encode() for part in name.split("."))
        + b"\x00"
    )
    return header + question + struct.pack(">HH", qtype, 1)


def _dns_response(
    name: str = "example.com", qid: int = 0x1234, nxdomain: bool = False
) -> bytes:
    rcode = 3 if nxdomain else 0
    header = struct.pack(">HHHHHH", qid, 0x8180 | rcode, 1, 0 if nxdomain else 1, 0, 0)
    question = (
        b"".join(bytes([len(part)]) + part.encode() for part in name.split("."))
        + b"\x00"
    )
    question += struct.pack(">HH", 1, 1)
    answer = (
        b"\xc0\x0c" + struct.pack(">HHIH", 1, 1, 300, 4) + bytes([93, 184, 216, 34])
    )
    return header + question + (b"" if nxdomain else answer)


def _http_get(host: str = "example.com", path: str = "/index.html") -> bytes:
    return (
        f"GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: test-agent\r\n\r\n"
    ).encode()


def _http_response(status: int = 200) -> bytes:
    return f"HTTP/1.1 {status} OK\r\nContent-Length: 0\r\n\r\n".encode()


def _tls_client_hello(sni: str = "example.com") -> bytes:
    # Minimal ClientHello: record + handshake + body with SNI extension.
    sni_bytes = sni.encode()
    server_name = b"\x00" + struct.pack(">H", len(sni_bytes)) + sni_bytes
    name_list = struct.pack(">H", len(server_name)) + server_name
    ext_data = name_list
    extension = struct.pack(">HH", 0x0000, len(ext_data)) + ext_data
    extensions = struct.pack(">H", len(extension)) + extension
    body = (
        struct.pack(">H", 0x0303)  # client version TLS 1.2
        + bytes(32)  # random
        + b"\x00"  # session id len
        + struct.pack(">H", 2)
        + b"\x13\x01"  # cipher suites
        + b"\x01\x00"  # compression methods
        + extensions
    )
    handshake = b"\x01" + len(body).to_bytes(3, "big") + body
    record = b"\x16\x03\x01" + struct.pack(">H", len(handshake)) + handshake
    return record


def _sll() -> bytes:
    # Linux cooked header: packet type, arphrd, addr len, addr, protocol
    return struct.pack(">HHH", 0, 1, 6) + bytes(8) + struct.pack(">H", 0x0800)


def build_pcap(
    packets: list[bytes],
    magic: int = 0xA1B2C3D4,
    linktype: int = 1,
    ts_sec: int = 1_700_000_000,
) -> bytes:
    # The magic *value* encodes the byte order; it is always written
    # big-endian so the reader sees the canonical byte pattern.
    order = ">" if magic in (0xA1B2C3D4, 0xA1B2CD34) else "<"
    out = struct.pack(">I", magic)
    out += struct.pack(f"{order}HHIIII", 2, 4, 0, 0, 65535, linktype)
    for i, pkt in enumerate(packets):
        out += struct.pack(f"{order}IIII", ts_sec + i, 0, len(pkt), len(pkt)) + pkt
    return out


def tcp_packet(
    sport: int = 12345,
    dport: int = 80,
    flags: int = 0x02,
    payload: bytes = b"",
    v6: bool = False,
    sll: bool = False,
) -> bytes:
    seg = _tcp(sport, dport, flags, payload)
    if v6:
        net = _ipv6(seg)
    else:
        net = _ipv4(seg)
    link = _sll() if sll else _eth()
    if sll:
        return link + net
    return link + net


@pytest.fixture()
def mixed_pcap(tmp_path):
    """Capture with TCP, DNS query+response, HTTP, TLS SNI."""
    packets = [
        tcp_packet(12345, 80, 0x02),  # SYN
        tcp_packet(12345, 80, 0x10, _http_get()),  # HTTP GET
        tcp_packet(80, 12345, 0x10, _http_response(200)),  # HTTP 200
        _eth() + _ipv4(_udp(53000, 53, _dns_query("example.com")), proto=17),
        _eth() + _ipv4(_udp(53, 53000, _dns_response("example.com")), proto=17),
        tcp_packet(12346, 443, 0x02, _tls_client_hello("example.com")),
        tcp_packet(12347, 22, 0x02),  # SSH SYN
        _eth() + _ipv6(_tcp(12348, 80, 0x02)),  # IPv6 SYN
    ]
    path = tmp_path / "mixed.pcap"
    path.write_bytes(build_pcap(packets))
    return str(path)


# ---------------------------------------------------------------------------
# Reader tests
# ---------------------------------------------------------------------------


def test_read_global_header_be(tmp_path):
    path = tmp_path / "t.pcap"
    path.write_bytes(build_pcap([]))
    header, offset = read_global_header(str(path))
    assert header.byte_order == ">"
    assert header.ts_resolution == "us"
    assert header.linktype == 1
    assert offset == 24


def test_read_global_header_le(tmp_path):
    path = tmp_path / "t.pcap"
    path.write_bytes(build_pcap([], magic=0xD4C3B2A1))
    header, _ = read_global_header(str(path))
    assert header.byte_order == "<"


def test_read_global_header_ns(tmp_path):
    path = tmp_path / "t.pcap"
    path.write_bytes(build_pcap([], magic=0xA1B2CD34))
    header, _ = read_global_header(str(path))
    assert header.ts_resolution == "ns"


def test_pcapng_refused(tmp_path):
    path = tmp_path / "t.pcapng"
    path.write_bytes(struct.pack(">I", 0x0A0D0D0A) + bytes(100))
    with pytest.raises(PcapngError, match="pcapng"):
        read_global_header(str(path))


def test_bad_magic_refused(tmp_path):
    path = tmp_path / "t.pcap"
    path.write_bytes(b"\x00" * 24)
    with pytest.raises(PcapError, match="unrecognized pcap magic"):
        read_global_header(str(path))


def test_truncated_file_refused(tmp_path):
    path = tmp_path / "t.pcap"
    path.write_bytes(b"\x00" * 10)
    with pytest.raises(PcapError, match="too short"):
        read_global_header(str(path))


def test_iter_packets_streams(mixed_pcap):
    header, offset = read_global_header(mixed_pcap)
    warnings: list = []
    packets = list(iter_packets(mixed_pcap, header, offset, warnings))
    assert len(packets) == 8
    assert not warnings
    index, timestamp, data, truncated = packets[0]
    assert index == 0
    assert timestamp.startswith("2023-11-14")
    assert not truncated


def test_truncated_tail_warns(tmp_path):
    path = tmp_path / "t.pcap"
    blob = build_pcap([tcp_packet()])
    path.write_bytes(blob + b"\x00" * 8)  # partial record header
    header, offset = read_global_header(str(path))
    warnings: list = []
    packets = list(iter_packets(str(path), header, offset, warnings))
    assert len(packets) == 1
    assert len(warnings) == 1
    assert "truncated packet record header" in warnings[0].reason


def test_unsupported_linktype_warns(tmp_path):
    path = tmp_path / "t.pcap"
    path.write_bytes(build_pcap([tcp_packet()], linktype=99))
    summary = pcap_analyze_mod.summarize(str(path), AnalyzeOptions())
    assert summary.packet_count == 0
    assert any("unsupported linktype" in w["reason"] for w in summary.warnings)


# ---------------------------------------------------------------------------
# Decoder tests
# ---------------------------------------------------------------------------


def test_decode_tcp_packet():
    decoded = decode_frame(tcp_packet(12345, 80, 0x12), 1)
    assert decoded.src_ip == "10.0.0.1"
    assert decoded.dst_ip == "10.0.0.2"
    assert decoded.src_port == 12345
    assert decoded.dst_port == 80
    assert decoded.protocol == "tcp"
    assert decoded.tcp_flags == "SA"
    assert "eth" in decoded.protocols and "ipv4" in decoded.protocols


def test_decode_udp_packet():
    frame = _eth() + _ipv4(_udp(53000, 53, b"data"), proto=17)
    decoded = decode_frame(frame, 1)
    assert decoded.protocol == "udp"
    assert decoded.src_port == 53000
    assert decoded.dst_port == 53
    assert decoded.payload == b"data"


def test_decode_ipv6_packet():
    decoded = decode_frame(tcp_packet(v6=True), 1)
    assert "ipv6" in decoded.protocols
    assert decoded.src_ip == "::1" or decoded.src_ip.endswith(":1")


def test_decode_linux_sll():
    decoded = decode_frame(tcp_packet(sll=True), 113)
    assert decoded.protocol == "tcp"
    assert "linux-cooked" in decoded.protocols


def test_decode_truncated_raises():
    with pytest.raises(DecodeError):
        decode_frame(b"\x00" * 5, 1)


def test_decode_bad_ip_version():
    with pytest.raises(DecodeError):
        decode_frame(_eth() + b"\xf0" * 20, 1)


# ---------------------------------------------------------------------------
# DNS extraction tests
# ---------------------------------------------------------------------------


def test_parse_dns_query():
    msg = parse_dns_message(_dns_query("example.com", qtype=28))
    assert not msg["malformed"]
    assert not msg["is_response"]
    assert msg["questions"][0]["name"] == "example.com"
    assert msg["questions"][0]["qtype"] == "AAAA"


def test_parse_dns_response():
    msg = parse_dns_message(_dns_response("example.com"))
    assert not msg["malformed"]
    assert msg["is_response"]
    assert msg["answers"][0]["rtype"] == "A"
    assert msg["rcode"] == 0


def test_parse_dns_nxdomain():
    msg = parse_dns_message(_dns_response("example.com", nxdomain=True))
    assert msg["rcode"] == 3


def test_parse_dns_malformed():
    # Header claims one question but the message ends immediately.
    truncated = struct.pack(">HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
    assert parse_dns_message(truncated)["malformed"]
    # Bad compression pointer loop.
    loop = struct.pack(">HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0) + b"\xc0\x0c"
    assert parse_dns_message(loop)["malformed"]
    # Too short for a header at all.
    assert parse_dns_message(b"\x00" * 5)["malformed"]


def test_is_dns_payload():
    assert is_dns_payload(_dns_query())
    assert not is_dns_payload(b"short")
    assert not is_dns_payload(b"\xff" * 12)


# ---------------------------------------------------------------------------
# HTTP / TLS extraction tests
# ---------------------------------------------------------------------------


def test_extract_http_request():
    records = extract_http(
        _http_get("example.com", "/a"), "2023-01-01T00:00:00Z", "1.1.1.1", "2.2.2.2"
    )
    assert len(records) == 1
    assert records[0].method == "GET"
    assert records[0].host == "example.com"
    assert records[0].path == "/a"
    assert records[0].user_agent == "test-agent"


def test_extract_http_response():
    records = extract_http(
        _http_response(404), "2023-01-01T00:00:00Z", "2.2.2.2", "1.1.1.1"
    )
    assert len(records) == 1
    assert records[0].status == 404


def test_extract_http_ignores_non_http():
    assert extract_http(b"\x00\x01\x02binary", "t", "a", "b") == []


def test_extract_tls_sni():
    records = extract_tls(
        _tls_client_hello("example.com"), "2023-01-01T00:00:00Z", "1.1.1.1", "2.2.2.2"
    )
    assert len(records) == 1
    assert records[0].sni == "example.com"
    assert records[0].offered_version == "TLS 1.2"


def test_extract_tls_ignores_non_tls():
    assert extract_tls(b"not tls at all....", "t", "a", "b") == []
    assert extract_tls(b"\x16\x03\x01\x00\x01\x00", "t", "a", "b") == []


# ---------------------------------------------------------------------------
# Analysis tests
# ---------------------------------------------------------------------------


def test_summary(mixed_pcap):
    summary = pcap_analyze_mod.summarize(mixed_pcap, AnalyzeOptions())
    assert summary.packet_count == 8
    assert summary.total_bytes > 0
    assert summary.time_first is not None and summary.time_last is not None
    protos = dict(summary.protocol_histogram)
    assert protos["tcp"] >= 5
    assert protos["udp"] == 2
    assert protos["ipv6"] == 1
    talkers = dict(summary.top_talkers_packets)
    assert talkers["10.0.0.1"] >= 4
    ports = dict(summary.top_ports)
    assert ports[80] >= 3
    assert summary.warning_count == 0


def test_summary_unusual_ports(mixed_pcap):
    summary = pcap_analyze_mod.summarize(mixed_pcap, AnalyzeOptions())
    unusual = {(e["protocol"], e["port"]) for e in summary.unusual_ports}
    assert ("tcp", 12345) in unusual  # ephemeral source port
    assert ("tcp", 80) not in unusual  # 80 is common


def test_conversations(mixed_pcap):
    conv = pcap_analyze_mod.conversations(mixed_pcap, AnalyzeOptions(top=50))
    assert len(conv.flows) > 0
    syn = [f for f in conv.flows if f.dst_port == 80 and f.src_port == 12345]
    assert syn and syn[0].packets == 2
    assert "S" in syn[0].tcp_flags
    assert syn[0].duration_s >= 0.0


def test_dns_activity(mixed_pcap):
    dns = pcap_analyze_mod.dns_activity(mixed_pcap, AnalyzeOptions())
    assert len(dns.queries) == 1
    q = dns.queries[0]
    assert q.name == "example.com"
    assert q.qtype == "A"
    assert q.queries == 1
    assert q.responses == 1
    assert dns.malformed_count == 0


def test_dns_malformed_counted(tmp_path):
    pkt = _eth() + _ipv4(_udp(53000, 53, b"\xff" * 30), proto=17)
    path = tmp_path / "t.pcap"
    path.write_bytes(build_pcap([pkt]))
    dns = pcap_analyze_mod.dns_activity(str(path), AnalyzeOptions())
    assert dns.malformed_count == 1
    assert len(dns.queries) == 0


def test_http_metadata(mixed_pcap):
    http = pcap_analyze_mod.http_metadata(mixed_pcap, AnalyzeOptions())
    assert len(http.records) == 2
    req = [r for r in http.records if r.method]
    resp = [r for r in http.records if r.status]
    assert req and req[0].host == "example.com" and req[0].path == "/index.html"
    assert resp and resp[0].status == 200


def test_tls_metadata(mixed_pcap):
    tls = pcap_analyze_mod.tls_metadata(mixed_pcap, AnalyzeOptions())
    assert len(tls.records) == 1
    assert tls.records[0].sni == "example.com"


def test_indicators(mixed_pcap):
    ind = pcap_analyze_mod.extract_indicators(mixed_pcap, AnalyzeOptions())
    by_type: dict[str, set[str]] = {}
    for i in ind.indicators:
        by_type.setdefault(i.itype, set()).add(i.value)
        assert i.observation == "observed in capture"
    assert "10.0.0.1" in by_type["ip"]
    assert "example.com" in by_type["domain"]
    assert "example.com/index.html" in by_type["url"]
    # dedup: example.com appears via DNS + HTTP + TLS but once
    domains = [i.value for i in ind.indicators if i.itype == "domain"]
    assert domains.count("example.com") == 1
    sni_sources = [i.sources for i in ind.indicators if i.value == "example.com"][0]
    assert "tls-sni" in sni_sources


def test_timeline(mixed_pcap):
    tl = pcap_analyze_mod.timeline(mixed_pcap, AnalyzeOptions())
    kinds = {e.kind for e in tl.events}
    assert "flow-start" in kinds
    assert "dns-query" in kinds
    stamps = [e.timestamp for e in tl.events]
    assert stamps == sorted(stamps)


def test_unusual_port_finding(tmp_path):
    packets = [tcp_packet(40000 + i, 31337, 0x02) for i in range(12)]
    path = tmp_path / "t.pcap"
    path.write_bytes(build_pcap(packets))
    summary = pcap_analyze_mod.summarize(
        str(path), AnalyzeOptions(unusual_port_packets=10)
    )
    titles = [f.title for f in summary.findings]
    assert "Unusual port activity" in titles
    finding = [f for f in summary.findings if f.title == "Unusual port activity"][0]
    assert "OBSERVED" in finding.reason and "INFERRED" in finding.reason
    assert "malicious" not in finding.reason.lower()


def test_burst_finding(tmp_path):
    # 60 distinct flows from one source inside one window.
    packets = [tcp_packet(50000 + i, 80, 0x02) for i in range(60)]
    path = tmp_path / "t.pcap"
    path.write_bytes(build_pcap(packets, ts_sec=1_700_000_000))
    summary = pcap_analyze_mod.summarize(
        str(path), AnalyzeOptions(burst_window=3600, burst_threshold=50)
    )
    titles = [f.title for f in summary.findings]
    assert "High connection frequency" in titles


def test_no_findings_below_threshold(mixed_pcap):
    summary = pcap_analyze_mod.summarize(mixed_pcap, AnalyzeOptions())
    assert summary.findings == []


def test_streaming_memory_bound(tmp_path):
    # 20k packets but only 100 distinct flows: packet data must not be
    # retained, so the peak stays bounded while the capture grows.
    packets = [tcp_packet(10000 + (i % 100), 80, 0x10) for i in range(20_000)]
    path = tmp_path / "big.pcap"
    path.write_bytes(build_pcap(packets))
    tracemalloc.start()
    summary = pcap_analyze_mod.summarize(str(path), AnalyzeOptions())
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    assert summary.packet_count == 20_000
    assert peak < 5 * 1024 * 1024, f"peak {peak} bytes exceeds 5 MiB"


# ---------------------------------------------------------------------------
# CLI tests
# ---------------------------------------------------------------------------


def test_plugin_registered():
    info = get_registry().get("pcap")
    assert info.version == "0.7.0"
    assert "pcap summary" in info.commands


def _run(argv: list[str]) -> tuple[int, str]:
    import io
    from contextlib import redirect_stdout

    buf = io.StringIO()
    with redirect_stdout(buf):
        code = cli_main.main(argv)
    return code, buf.getvalue()


def test_cli_summary(mixed_pcap):
    code, out = _run(["pcap", "summary", mixed_pcap])
    assert code == 0
    assert "8 packet(s)" in out
    assert "Top talkers" in out


def test_cli_summary_json(mixed_pcap):
    code, out = _run(["pcap", "summary", mixed_pcap, "--json"])
    assert code == 0
    data = json.loads(out)
    assert data["data"]["packet_count"] == 8


def test_cli_conversations_csv(mixed_pcap):
    code, out = _run(["pcap", "conversations", mixed_pcap, "--csv"])
    assert code == 0
    lines = out.strip().split("\n")
    assert lines[0].startswith("src_ip,dst_ip,protocol")
    assert len(lines) > 1


def test_cli_dns(mixed_pcap):
    code, out = _run(["pcap", "dns", mixed_pcap])
    assert code == 0
    assert "example.com" in out


def test_cli_http(mixed_pcap):
    code, out = _run(["pcap", "http", mixed_pcap])
    assert code == 0
    assert "example.com/index.html" in out


def test_cli_tls(mixed_pcap):
    code, out = _run(["pcap", "tls", mixed_pcap])
    assert code == 0
    assert "example.com" in out


def test_cli_indicators(mixed_pcap):
    code, out = _run(["pcap", "indicators", mixed_pcap])
    assert code == 0
    assert "observed in capture" in out.lower() or "Observed in capture" in out


def test_cli_timeline(mixed_pcap):
    code, out = _run(["pcap", "timeline", mixed_pcap, "--json"])
    assert code == 0
    data = json.loads(out)
    assert len(data["events"]) > 0
    assert all(e["source"] == "pcap" for e in data["events"])


def test_cli_pcapng_clean_error(tmp_path):
    path = tmp_path / "t.pcapng"
    path.write_bytes(struct.pack(">I", 0x0A0D0D0A) + bytes(100))
    code, _ = _run(["pcap", "summary", str(path)])
    assert code == 2


def test_cli_missing_file():
    code, _ = _run(["pcap", "summary", "/nonexistent/file.pcap"])
    assert code == 2


def test_cli_findings_exit_code(tmp_path):
    packets = [tcp_packet(40000 + i, 31337, 0x02) for i in range(12)]
    path = tmp_path / "t.pcap"
    path.write_bytes(build_pcap(packets))
    code, out = _run(["pcap", "summary", str(path)])
    assert code == 1  # findings -> warning status
    assert "Unusual port activity" in out
