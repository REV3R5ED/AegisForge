"""Stdlib-only protocol decoders for pcap payloads.

Each decoder parses headers and returns a :class:`Decoded` record;
anything malformed raises :class:`DecodeError`, which the analyzer
converts into a packet-level warning. No payload reassembly is ever
performed — ``payload`` is the raw transport payload handed to the
DNS/HTTP/TLS extractors, and only its length is recorded in reports.
"""

from __future__ import annotations

import ipaddress
import struct
from dataclasses import dataclass, field

ETHERTYPE_IPV4 = 0x0800
ETHERTYPE_IPV6 = 0x86DD
ETHERTYPE_VLAN = 0x8100

IPPROTO_ICMP = 1
IPPROTO_TCP = 6
IPPROTO_UDP = 17
IPPROTO_ICMPV6 = 58

_TCP_FLAG_NAMES = (
    (0x01, "F"),
    (0x02, "S"),
    (0x04, "R"),
    (0x08, "P"),
    (0x10, "A"),
    (0x20, "U"),
    (0x40, "E"),
    (0x80, "C"),
)


class DecodeError(Exception):
    """One packet (or header) could not be decoded."""


@dataclass
class Decoded:
    """Headers decoded from one link-layer frame."""

    protocols: list[str] = field(default_factory=list)
    src_ip: str | None = None
    dst_ip: str | None = None
    src_port: int | None = None
    dst_port: int | None = None
    protocol: str | None = None  # "tcp" | "udp" | "icmp" | "icmpv6" | None
    payload: bytes = b""
    tcp_flags: str = ""


def _need(buf: bytes, size: int, what: str) -> None:
    if len(buf) < size:
        raise DecodeError(f"truncated {what}: {len(buf)} < {size} bytes")


def decode_ethernet(frame: bytes) -> tuple[Decoded, bytes]:
    """Strip the Ethernet header; return (decoded, network_payload)."""
    _need(frame, 14, "ethernet header")
    ethertype = struct.unpack(">H", frame[12:14])[0]
    offset = 14
    # Single 802.1Q tag: skip it and re-read the ethertype.
    if ethertype == ETHERTYPE_VLAN:
        _need(frame, 18, "vlan tag")
        ethertype = struct.unpack(">H", frame[16:18])[0]
        offset = 18
    return Decoded(protocols=["eth"]), frame[offset:]


def decode_linux_sll(frame: bytes) -> tuple[Decoded, bytes]:
    """Strip the 16-byte Linux cooked-capture header."""
    _need(frame, 16, "linux sll header")
    return Decoded(protocols=["linux-cooked"]), frame[16:]


def decode_ipv4(packet: bytes) -> tuple[Decoded, tuple[int, bytes]]:
    _need(packet, 20, "ipv4 header")
    version_ihl = packet[0]
    if version_ihl >> 4 != 4:
        raise DecodeError(f"not an IPv4 packet (version {version_ihl >> 4})")
    ihl = (version_ihl & 0x0F) * 4
    _need(packet, ihl, "ipv4 header with options")
    proto_num = packet[9]
    try:
        src = str(ipaddress.IPv4Address(packet[12:16]))
        dst = str(ipaddress.IPv4Address(packet[16:20]))
    except ipaddress.AddressValueError as exc:
        raise DecodeError(f"bad ipv4 address: {exc}") from exc
    total_len = struct.unpack(">H", packet[2:4])[0]
    payload = packet[ihl:total_len] if total_len > ihl else packet[ihl:]
    decoded = Decoded(protocols=["ipv4"], src_ip=src, dst_ip=dst)
    return decoded, (proto_num, payload)


def decode_ipv6(packet: bytes) -> tuple[Decoded, tuple[int, bytes]]:
    _need(packet, 40, "ipv6 header")
    if packet[0] >> 4 != 6:
        raise DecodeError(f"not an IPv6 packet (version {packet[0] >> 4})")
    payload_len = struct.unpack(">H", packet[4:6])[0]
    next_header = packet[6]
    try:
        src = str(ipaddress.IPv6Address(packet[8:24]))
        dst = str(ipaddress.IPv6Address(packet[24:40]))
    except ipaddress.AddressValueError as exc:
        raise DecodeError(f"bad ipv6 address: {exc}") from exc
    payload = packet[40 : 40 + payload_len] if payload_len else packet[40:]
    decoded = Decoded(protocols=["ipv6"], src_ip=src, dst_ip=dst)
    return decoded, (next_header, payload)


def _tcp_flags_str(flags: int) -> str:
    return "".join(name for bit, name in _TCP_FLAG_NAMES if flags & bit)


def decode_tcp(segment: bytes) -> tuple[Decoded, bytes]:
    _need(segment, 20, "tcp header")
    src_port, dst_port, _, _, off_flags = struct.unpack(">HHIIH", segment[:14])
    data_offset = (off_flags >> 12) * 4
    _need(segment, data_offset, "tcp header with options")
    flags = _tcp_flags_str(off_flags & 0x1FF)
    decoded = Decoded(
        protocol="tcp",
        protocols=["tcp"],
        src_port=src_port,
        dst_port=dst_port,
        tcp_flags=flags,
        payload=segment[data_offset:],
    )
    return decoded, segment[data_offset:]


def decode_udp(datagram: bytes) -> tuple[Decoded, bytes]:
    _need(datagram, 8, "udp header")
    src_port, dst_port = struct.unpack(">HH", datagram[:4])
    decoded = Decoded(
        protocol="udp",
        protocols=["udp"],
        src_port=src_port,
        dst_port=dst_port,
        payload=datagram[8:],
    )
    return decoded, datagram[8:]


def decode_icmp(message: bytes, v6: bool = False) -> Decoded:
    _need(message, 4, "icmp header")
    name = "icmpv6" if v6 else "icmp"
    return Decoded(protocol=name, protocols=[name])


def decode_frame(frame: bytes, linktype: int) -> Decoded:
    """Full decode of one link-layer frame into a :class:`Decoded`.

    Raises :class:`DecodeError` on any malformed header.
    """
    if linktype == 1:  # DLT_EN10MB
        base, network = decode_ethernet(frame)
    elif linktype == 113:  # DLT_LINUX_SLL
        base, network = decode_linux_sll(frame)
    else:  # pragma: no cover - guarded by the analyzer
        raise DecodeError(f"unsupported linktype {linktype}")
    if len(network) < 1:
        raise DecodeError("empty network payload")
    version = network[0] >> 4
    if version == 4:
        ip, (proto_num, transport) = decode_ipv4(network)
    elif version == 6:
        ip, (proto_num, transport) = decode_ipv6(network)
    else:
        raise DecodeError(f"unknown IP version {version}")
    base.protocols.extend(ip.protocols)
    base.src_ip, base.dst_ip = ip.src_ip, ip.dst_ip
    if proto_num == IPPROTO_TCP:
        tcp, _ = decode_tcp(transport)
        base.protocol = "tcp"
        base.protocols.append("tcp")
        base.src_port, base.dst_port = tcp.src_port, tcp.dst_port
        base.tcp_flags = tcp.tcp_flags
        base.payload = tcp.payload
    elif proto_num == IPPROTO_UDP:
        udp, _ = decode_udp(transport)
        base.protocol = "udp"
        base.protocols.append("udp")
        base.src_port, base.dst_port = udp.src_port, udp.dst_port
        base.payload = udp.payload
    elif proto_num in (IPPROTO_ICMP, IPPROTO_ICMPV6):
        icmp = decode_icmp(transport, v6=(proto_num == IPPROTO_ICMPV6))
        base.protocol = icmp.protocol
        base.protocols.append(icmp.protocol or "icmp")
    else:
        base.protocols.append(f"ipproto-{proto_num}")
    return base
