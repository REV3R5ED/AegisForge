"""DNS message extraction from capture payloads.

Reuses the stdlib DNS wire parsing from :mod:`aegisforge.domain.dns_client`
(``_decode_name`` with its compression-pointer loop protection, and the
``QTYPE_NAMES`` table) instead of duplicating that logic. Unlike the
client's ``parse_response`` — which validates a response against an
outstanding query — :func:`parse_dns_message` parses any message found
on the wire, query or response, without prior knowledge of its
transaction id.

Malformed messages return ``{"malformed": True}`` with whatever was
parsed before the failure; they are counted, never fatal.
"""

from __future__ import annotations

import struct
from typing import Any

from aegisforge.domain.dns_client import QTYPE_NAMES, DNSParseError, _decode_name


def parse_dns_message(buf: bytes) -> dict[str, Any]:
    """Parse one DNS message from the wire.

    Returns a dict with ``qid``, ``is_response``, ``questions``,
    ``answers``, ``rcode`` and ``malformed``. Never raises.
    """
    result: dict[str, Any] = {
        "qid": None,
        "is_response": False,
        "questions": [],
        "answers": [],
        "rcode": None,
        "malformed": False,
        "truncated": False,
    }
    try:
        if len(buf) < 12:
            raise DNSParseError(f"message too short ({len(buf)} bytes)")
        qid, flags, qdcount, ancount, _, _ = struct.unpack(">HHHHHH", buf[:12])
        result["qid"] = qid
        result["is_response"] = bool(flags & 0x8000)
        result["rcode"] = flags & 0x000F
        result["truncated"] = bool(flags & 0x0200)
        # Sanity caps: a single message cannot reasonably carry thousands
        # of questions/answers; bail before looping on corrupt counts.
        if qdcount > 64 or ancount > 256:
            raise DNSParseError(f"implausible section counts qd={qdcount} an={ancount}")
        offset = 12
        for _ in range(qdcount):
            name, offset = _decode_name(buf, offset)
            if offset + 4 > len(buf):
                raise DNSParseError("truncated question tail")
            qtype_num, _ = struct.unpack(">HH", buf[offset : offset + 4])
            offset += 4
            result["questions"].append(
                {
                    "name": name,
                    "qtype": QTYPE_NAMES.get(qtype_num, f"TYPE{qtype_num}"),
                }
            )
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
            offset += rdlength
            result["answers"].append(
                {
                    "name": name,
                    "rtype": QTYPE_NAMES.get(rtype_num, f"TYPE{rtype_num}"),
                    "ttl": ttl,
                }
            )
    except DNSParseError:
        result["malformed"] = True
    return result


def is_dns_payload(payload: bytes) -> bool:
    """Cheap heuristic: plausible DNS header (12+ bytes, sane counts)."""
    if len(payload) < 12:
        return False
    _, _, qdcount, ancount, nscount, arcount = struct.unpack(">HHHHHH", payload[:12])
    return bool(qdcount <= 64 and ancount <= 256 and nscount <= 256 and arcount <= 256)
