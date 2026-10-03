"""TLS ClientHello metadata extraction from TCP/443 payloads.

Parses just enough of the handshake to recover the offered TLS
version and the SNI (Server Name Indication) extension: TLS record
header → handshake header → ClientHello body → extensions →
server_name. Anything malformed returns no record; failures are
counted by the caller, never raised.
"""

from __future__ import annotations

import struct

from aegisforge.pcap.models import TlsRecord

_TLS_VERSIONS = {
    0x0301: "TLS 1.0",
    0x0302: "TLS 1.1",
    0x0303: "TLS 1.2",
    0x0304: "TLS 1.3",
}

_EXT_SERVER_NAME = 0x0000


def _u16(buf: bytes, offset: int) -> int:
    return int(struct.unpack(">H", buf[offset : offset + 2])[0])


def extract_tls(payload: bytes, timestamp: str, src: str, dst: str) -> list[TlsRecord]:
    """Extract ClientHello metadata from one TCP payload. Never raises."""
    try:
        return _extract(payload, timestamp, src, dst)
    except (IndexError, struct.error, ValueError):
        return []


def _extract(payload: bytes, timestamp: str, src: str, dst: str) -> list[TlsRecord]:
    # TLS record header: type(1) version(2) length(2). 22 = handshake.
    if len(payload) < 5 or payload[0] != 22:
        return []
    record_len = _u16(payload, 3)
    if len(payload) < 5 + record_len:
        return []
    body = payload[5 : 5 + record_len]
    # Handshake header: type(1) length(3). 1 = ClientHello.
    if len(body) < 4 or body[0] != 1:
        return []
    hello_len = int.from_bytes(body[1:4], "big")
    hello = body[4 : 4 + hello_len]
    if len(hello) < 34:  # version(2) + random(32)
        return []
    offered = _TLS_VERSIONS.get(_u16(hello, 0), f"0x{_u16(hello, 0):04x}")
    pos = 34
    # session id
    if pos >= len(hello):
        return []
    pos += 1 + hello[pos]
    # cipher suites
    if pos + 2 > len(hello):
        return []
    pos += 2 + _u16(hello, pos)
    # compression methods
    if pos >= len(hello):
        return []
    pos += 1 + hello[pos]
    # extensions
    if pos + 2 > len(hello):
        return [TlsRecord(timestamp, src, dst, "", offered)]
    ext_total = _u16(hello, pos)
    pos += 2
    end = min(pos + ext_total, len(hello))
    sni = ""
    while pos + 4 <= end:
        ext_type = _u16(hello, pos)
        ext_len = _u16(hello, pos + 2)
        ext_data = hello[pos + 4 : pos + 4 + ext_len]
        if ext_type == _EXT_SERVER_NAME and len(ext_data) >= 2:
            # server_name_list: list_len(2) then entries type(1) len(2) name
            list_len = _u16(ext_data, 0)
            cursor = 2
            limit = min(2 + list_len, len(ext_data))
            while cursor + 3 <= limit:
                name_type = ext_data[cursor]
                name_len = _u16(ext_data, cursor + 1)
                name_bytes = ext_data[cursor + 3 : cursor + 3 + name_len]
                if name_type == 0 and name_bytes:  # host_name
                    sni = name_bytes.decode("ascii", errors="replace")
                    break
                cursor += 3 + name_len
            if sni:
                break
        pos += 4 + ext_len
    return [
        TlsRecord(
            timestamp=timestamp, src=src, dst=dst, sni=sni, offered_version=offered
        )
    ]
