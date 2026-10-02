"""Minimal DNS client over UDP/TCP, stdlib-only.

``socket.getaddrinfo`` only exposes A/AAAA/PTR records. Domain
investigation needs MX, NS, TXT, SOA, CNAME, DNSKEY and DS, so this
module speaks the DNS wire protocol directly (RFC 1035): query packets
are built with :mod:`struct` and answers are parsed by hand, including
compressed domain names.

Truncated UDP answers (TC flag) are retried over TCP automatically.
Failed or refused queries are reported as warnings on the response,
never as crashes — a flaky resolver must not kill an investigation.
"""

from __future__ import annotations

import ipaddress
import random
import socket
import struct
from dataclasses import asdict, dataclass, field
from typing import Any

from aegisforge.network.validation import (
    ValidationError,
    validate_target,
    validate_timeout,
)

#: Record types the client can query, mapped to their wire numbers.
QTYPE_NUMBERS = {
    "A": 1,
    "NS": 2,
    "CNAME": 5,
    "SOA": 6,
    "MX": 15,
    "TXT": 16,
    "AAAA": 28,
    "DS": 43,
    "DNSKEY": 48,
}
QTYPE_NAMES = {number: name for name, number in QTYPE_NUMBERS.items()}

RCODES = {
    0: "NOERROR",
    1: "FORMERR",
    2: "SERVFAIL",
    3: "NXDOMAIN",
    4: "NOTIMP",
    5: "REFUSED",
}

#: Fallback resolvers when no system resolver can be determined.
DEFAULT_RESOLVERS = ["8.8.8.8", "1.1.1.1"]

DNS_PORT = 53
_MAX_UDP = 4096
_MAX_TCP_MESSAGE = 65535
_MAX_NAME_JUMPS = 128


class DNSError(Exception):
    """Raised when a DNS query cannot be sent or completed."""


class DNSParseError(DNSError):
    """Raised when a DNS response cannot be parsed."""


@dataclass
class DNSRecord:
    """One parsed resource record."""

    name: str
    rtype: str
    ttl: int
    data: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class DNSResponse:
    """Parsed answer to one DNS query."""

    qname: str
    qtype: str
    rcode: int
    answers: list[DNSRecord] = field(default_factory=list)
    truncated: bool = False
    warnings: list[str] = field(default_factory=list)

    @property
    def rcode_name(self) -> str:
        return RCODES.get(self.rcode, f"RCODE{self.rcode}")

    @property
    def ok(self) -> bool:
        return self.rcode == 0

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["rcode_name"] = self.rcode_name
        data["ok"] = self.ok
        return data


def encode_name(name: str) -> bytes:
    """Encode a domain name into DNS label wire format."""
    cleaned = name.strip().rstrip(".")
    if not cleaned:
        return b"\x00"
    if len(cleaned) > 253:
        raise ValidationError(f"DNS name too long: {name!r}")
    out = bytearray()
    for label in cleaned.split("."):
        raw = label.encode("ascii", errors="strict") if label else b""
        if len(raw) > 63:
            raise ValidationError(f"DNS label too long: {label!r}")
        out.append(len(raw))
        out.extend(raw)
    out.append(0)
    return bytes(out)


def build_query(qname: str, qtype: str, qid: int) -> bytes:
    """Build a standard recursive query packet for *qname*/*qtype*."""
    qtype_num = QTYPE_NUMBERS.get(qtype.upper())
    if qtype_num is None:
        raise ValidationError(
            f"unsupported query type {qtype!r}; expected one of {sorted(QTYPE_NUMBERS)}"
        )
    if not 0 <= qid <= 65535:
        raise ValidationError(f"query id out of range: {qid}")
    header = struct.pack(">HHHHHH", qid, 0x0100, 1, 0, 0, 0)  # RD=1
    question = encode_name(qname) + struct.pack(">HH", qtype_num, 1)  # IN
    return header + question


def _decode_name(buf: bytes, offset: int) -> tuple[str, int]:
    """Decode a (possibly compressed) domain name.

    Returns ``(name, next_offset)`` where ``next_offset`` is the position
    right after the name in the *sequential* stream (following a
    compression jump does not advance it past the pointer).
    """
    labels: list[str] = []
    end: int | None = None
    seen: set[int] = set()
    for _ in range(_MAX_NAME_JUMPS):
        if offset >= len(buf):
            raise DNSParseError("domain name extends past message end")
        length = buf[offset]
        if length & 0xC0 == 0xC0:  # compression pointer
            if offset + 1 >= len(buf):
                raise DNSParseError("truncated compression pointer")
            target = ((length & 0x3F) << 8) | buf[offset + 1]
            if target >= len(buf):
                raise DNSParseError("compression pointer out of bounds")
            if target in seen:
                raise DNSParseError("compression pointer loop")
            seen.add(target)
            if end is None:
                end = offset + 2
            offset = target
            continue
        if length & 0xC0:
            raise DNSParseError(f"invalid label length bits: {length:#x}")
        if length == 0:
            if end is None:
                end = offset + 1
            break
        offset += 1
        if offset + length > len(buf):
            raise DNSParseError("label extends past message end")
        labels.append(buf[offset : offset + length].decode("ascii", errors="replace"))
        offset += length
    else:
        raise DNSParseError("name decoding exceeded jump limit")
    assert end is not None
    return ".".join(labels), end


def _parse_rdata(
    rtype_num: int, rdata: bytes, buf: bytes, rdata_offset: int
) -> dict[str, Any]:
    """Parse record data according to its type number."""
    if rtype_num == 1:  # A
        if len(rdata) != 4:
            raise DNSParseError(f"bad A record length: {len(rdata)}")
        return {"address": socket.inet_ntoa(rdata)}
    if rtype_num == 28:  # AAAA
        if len(rdata) != 16:
            raise DNSParseError(f"bad AAAA record length: {len(rdata)}")
        return {"address": str(ipaddress.IPv6Address(rdata))}
    if rtype_num in (2, 5):  # NS, CNAME
        name, _ = _decode_name(buf, rdata_offset)
        return {("nameserver" if rtype_num == 2 else "target"): name}
    if rtype_num == 15:  # MX
        if len(rdata) < 2:
            raise DNSParseError("truncated MX record")
        preference = struct.unpack(">H", rdata[:2])[0]
        exchange, _ = _decode_name(buf, rdata_offset + 2)
        return {"preference": preference, "exchange": exchange}
    if rtype_num == 16:  # TXT
        parts: list[str] = []
        pos = 0
        while pos < len(rdata):
            chunk_len = rdata[pos]
            pos += 1
            parts.append(rdata[pos : pos + chunk_len].decode("utf-8", errors="replace"))
            pos += chunk_len
        return {"text": "".join(parts), "strings": parts}
    if rtype_num == 6:  # SOA
        mname, pos = _decode_name(buf, rdata_offset)
        rname, pos = _decode_name(buf, pos)
        fixed = rdata[pos - rdata_offset : pos - rdata_offset + 20]
        if len(fixed) != 20:
            raise DNSParseError("truncated SOA timers")
        serial, refresh, retry, expire, minimum = struct.unpack(">IIIII", fixed)
        return {
            "mname": mname,
            "rname": rname,
            "serial": serial,
            "refresh": refresh,
            "retry": retry,
            "expire": expire,
            "minimum": minimum,
        }
    if rtype_num == 48:  # DNSKEY
        if len(rdata) < 4:
            raise DNSParseError("truncated DNSKEY record")
        flags, protocol, algorithm = struct.unpack(">HBB", rdata[:4])
        return {
            "flags": flags,
            "protocol": protocol,
            "algorithm": algorithm,
            "key_tag": _dnskey_key_tag(rdata),
            "key_bytes": len(rdata) - 4,
            "is_zone_key": bool(flags & 0x0100),
            "is_sep": bool(flags & 0x0001),
        }
    if rtype_num == 43:  # DS
        if len(rdata) < 4:
            raise DNSParseError("truncated DS record")
        key_tag, algorithm, digest_type = struct.unpack(">HBB", rdata[:4])
        return {
            "key_tag": key_tag,
            "algorithm": algorithm,
            "digest_type": digest_type,
            "digest": rdata[4:].hex(),
        }
    return {"hex": rdata.hex()}


def _dnskey_key_tag(rdata: bytes) -> int:
    """Compute the DNSKEY key tag (RFC 4034, Appendix B)."""
    total = 0
    for i, byte in enumerate(rdata):
        total += byte << 8 if i & 1 == 0 else byte
    total += (total >> 16) & 0xFFFF
    return total & 0xFFFF


def parse_response(buf: bytes, qid: int, qname: str, qtype: str) -> DNSResponse:
    """Parse a raw DNS response message."""
    response = DNSResponse(qname=qname, qtype=qtype.upper(), rcode=0)
    if len(buf) < 12:
        raise DNSParseError(f"message too short ({len(buf)} bytes)")
    rid, flags, qdcount, ancount, _, _ = struct.unpack(">HHHHHH", buf[:12])
    if rid != qid:
        raise DNSParseError(f"transaction id mismatch: got {rid:#x}, expected {qid:#x}")
    if not flags & 0x8000:
        raise DNSParseError("message is not a response (QR=0)")
    response.truncated = bool(flags & 0x0200)
    response.rcode = flags & 0x000F
    offset = 12
    try:
        for _ in range(qdcount):  # skip the echoed question section
            _, offset = _decode_name(buf, offset)
            offset += 4
        for _ in range(ancount):
            name, offset = _decode_name(buf, offset)
            if offset + 10 > len(buf):
                raise DNSParseError("truncated answer header")
            rtype_num, _, ttl, rdlength = struct.unpack(
                ">HHIH", buf[offset : offset + 10]
            )
            offset += 10
            if offset + rdlength > len(buf):
                raise DNSParseError("record data extends past message end")
            rdata = buf[offset : offset + rdlength]
            rdata_offset = offset
            offset += rdlength
            response.answers.append(
                DNSRecord(
                    name=name,
                    rtype=QTYPE_NAMES.get(rtype_num, f"TYPE{rtype_num}"),
                    ttl=ttl,
                    data=_parse_rdata(rtype_num, rdata, buf, rdata_offset),
                )
            )
    except DNSParseError as exc:
        response.warnings.append(f"partial parse: {exc}")
    if response.truncated:
        response.warnings.append(
            "response truncated over UDP (TC flag); retried over TCP"
        )
    if response.rcode == 3:
        response.warnings.append(f"{qname} does not exist (NXDOMAIN)")
    elif response.rcode != 0:
        response.warnings.append(
            f"resolver returned {response.rcode_name} for {qname}/{qtype.upper()}"
        )
    return response


def system_resolvers() -> list[str]:
    """Best-effort list of the host's configured DNS resolvers.

    Parses ``/etc/resolv.conf`` on POSIX systems. Falls back to public
    resolvers when nothing usable is found — documented, not silent.
    """
    resolvers: list[str] = []
    try:
        with open("/etc/resolv.conf", encoding="utf-8") as handle:
            for line in handle:
                parts = line.split()
                if len(parts) >= 2 and parts[0] == "nameserver":
                    candidate = parts[1].split("%")[0]
                    try:
                        validate_target(candidate)
                        resolvers.append(candidate)
                    except ValidationError:
                        continue
    except OSError:
        pass
    if not resolvers:
        resolvers = list(DEFAULT_RESOLVERS)
    return resolvers


def _socket_family(resolver: str) -> int:
    try:
        ipaddress.IPv6Address(resolver)
        return socket.AF_INET6
    except ipaddress.AddressValueError:
        return socket.AF_INET


def _query_udp(
    packet: bytes, resolver: str, timeout: float, qid: int, qname: str, qtype: str
) -> DNSResponse:
    sock = socket.socket(_socket_family(resolver), socket.SOCK_DGRAM)
    try:
        sock.settimeout(timeout)
        sock.sendto(packet, (resolver, DNS_PORT))
        data, _ = sock.recvfrom(_MAX_UDP)
    except TimeoutError as exc:
        raise DNSError(
            f"DNS query for {qname}/{qtype} to {resolver} timed out after {timeout}s"
        ) from exc
    except OSError as exc:
        raise DNSError(f"DNS query for {qname}/{qtype} failed: {exc}") from exc
    finally:
        sock.close()
    return parse_response(data, qid, qname, qtype)


def _query_tcp(
    packet: bytes, resolver: str, timeout: float, qid: int, qname: str, qtype: str
) -> DNSResponse:
    framed = struct.pack(">H", len(packet)) + packet
    sock = socket.socket(_socket_family(resolver), socket.SOCK_STREAM)
    try:
        sock.settimeout(timeout)
        sock.connect((resolver, DNS_PORT))
        sock.sendall(framed)
        header = _recvall(sock, 2)
        (length,) = struct.unpack(">H", header)
        if length > _MAX_TCP_MESSAGE:
            raise DNSParseError(f"TCP response too large: {length}")
        data = _recvall(sock, length)
    except TimeoutError as exc:
        raise DNSError(
            f"DNS/TCP query for {qname}/{qtype} to {resolver} timed out "
            f"after {timeout}s"
        ) from exc
    except OSError as exc:
        raise DNSError(f"DNS/TCP query for {qname}/{qtype} failed: {exc}") from exc
    finally:
        sock.close()
    response = parse_response(data, qid, qname, qtype)
    response.truncated = False  # TCP answers are complete by construction
    return response


def _recvall(sock: socket.socket, count: int) -> bytes:
    chunks = bytearray()
    while len(chunks) < count:
        chunk = sock.recv(count - len(chunks))
        if not chunk:
            raise DNSParseError("connection closed mid-message")
        chunks.extend(chunk)
    return bytes(chunks)


def query(
    name: str,
    qtype: str,
    resolver: str | None = None,
    timeout: float = 5.0,
) -> DNSResponse:
    """Send one DNS query; return the parsed response.

    ``resolver=None`` uses the system resolvers (first usable one wins).
    Truncated UDP answers are retried over TCP. Hard failures raise
    :class:`DNSError`; soft failures (NXDOMAIN, REFUSED, ...) are
    recorded as warnings on the response.
    """
    name = validate_target(name)
    timeout = validate_timeout(timeout)
    qtype = qtype.upper()
    if qtype not in QTYPE_NUMBERS:
        raise ValidationError(
            f"unsupported query type {qtype!r}; expected one of {sorted(QTYPE_NUMBERS)}"
        )
    resolvers = [resolver] if resolver else system_resolvers()
    if resolver:
        validate_target(resolver)
    qid = random.randint(0, 65535)
    packet = build_query(name, qtype, qid)
    last_error: Exception | None = None
    for candidate in resolvers:
        try:
            response = _query_udp(packet, candidate, timeout, qid, name, qtype)
        except DNSError as exc:
            last_error = exc
            continue
        if response.truncated:
            try:
                return _query_tcp(packet, candidate, timeout, qid, name, qtype)
            except DNSError as exc:
                last_error = exc
                continue
        return response
    raise DNSError(f"all resolvers failed for {name}/{qtype}: {last_error}")
