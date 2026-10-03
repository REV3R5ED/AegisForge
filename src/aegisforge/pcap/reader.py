"""Streaming classic-pcap reader (stdlib only).

Parses the global header (all four magic variants: big/little endian ×
micro/nanosecond timestamps), then yields one packet at a time — the
capture is never loaded wholly into memory. pcapng files are detected
and refused with a clean, catchable error (out of scope for v0.7).

Truncated packet records become warnings, not crashes.
"""

from __future__ import annotations

import struct
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import datetime, timezone

from aegisforge.pcap.models import PcapWarning

GLOBAL_HEADER_LEN = 24
PACKET_HEADER_LEN = 16

#: magic -> (byte order, timestamp resolution)
_MAGICS = {
    0xA1B2C3D4: (">", "us"),
    0xA1B2CD34: (">", "ns"),
    0xD4C3B2A1: ("<", "us"),
    0x4D3CD2A1: ("<", "ns"),
}

PCAPNG_MAGIC = 0x0A0D0D0A

LINKTYPE_ETHERNET = 1
LINKTYPE_LINUX_SLL = 113

LINKTYPE_NAMES = {
    LINKTYPE_ETHERNET: "ethernet",
    LINKTYPE_LINUX_SLL: "linux-cooked",
}


class PcapError(Exception):
    """The file is not a readable classic pcap."""


class PcapngError(PcapError):
    """pcapng is detected; not supported in v0.7."""


@dataclass
class PcapHeader:
    byte_order: str
    ts_resolution: str  # "us" | "ns"
    linktype: int
    snaplen: int


def read_global_header(path: str) -> tuple[PcapHeader, int]:
    """Read and validate the 24-byte global header.

    Returns ``(header, data_offset)``. Raises :class:`PcapError` for
    anything that is not a classic pcap (including pcapng).
    """
    try:
        with open(path, "rb") as fh:
            blob = fh.read(GLOBAL_HEADER_LEN)
    except OSError as exc:
        raise PcapError(f"cannot read {path}: {exc}") from exc
    if len(blob) < GLOBAL_HEADER_LEN:
        raise PcapError(f"{path}: too short for a pcap global header")
    magic_be = struct.unpack(">I", blob[:4])[0]
    magic_le = struct.unpack("<I", blob[:4])[0]
    if magic_be == PCAPNG_MAGIC or magic_le == PCAPNG_MAGIC:
        raise PcapngError(f"{path}: pcapng format is not supported in v0.7")
    parsed = _MAGICS.get(magic_be) or _MAGICS.get(magic_le)
    if parsed is None:
        raise PcapError(
            f"{path}: unrecognized pcap magic "
            f"{blob[:4].hex()} (not classic pcap or pcapng)"
        )
    order, resolution = parsed
    _, ver_major, ver_minor, _, _, snaplen, linktype = struct.unpack(
        f"{order}IHHIIII", blob
    )
    if (ver_major, ver_minor) != (2, 4):
        raise PcapError(
            f"{path}: unsupported pcap version {ver_major}.{ver_minor} (expected 2.4)"
        )
    return (
        PcapHeader(
            byte_order=order,
            ts_resolution=resolution,
            linktype=linktype,
            snaplen=snaplen,
        ),
        GLOBAL_HEADER_LEN,
    )


def _packet_timestamp(order: str, resolution: str, ts_sec: int, ts_frac: int) -> str:
    if resolution == "ns":
        micros = ts_frac // 1000
    else:
        micros = ts_frac
    # Clamp: corrupt captures can carry absurd fractions.
    micros = max(0, min(micros, 999_999))
    moment = datetime.fromtimestamp(ts_sec, tz=timezone.utc).replace(microsecond=micros)
    return moment.strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def iter_packets(
    path: str, header: PcapHeader, offset: int, warnings: list[PcapWarning]
) -> Iterator[tuple[int, str, bytes, bool]]:
    """Yield ``(index, timestamp_iso, packet_bytes, truncated)`` per packet.

    Streaming: one packet record is in memory at a time. Truncated or
    corrupt records append a :class:`PcapWarning` and stop the walk —
    a broken tail never loses the packets already decoded.
    """
    order = header.byte_order
    index = 0
    try:
        fh = open(path, "rb")
    except OSError as exc:
        warnings.append(PcapWarning(reason=f"cannot reopen {path}: {exc}"))
        return
    with fh:
        fh.seek(offset)
        while True:
            rec = fh.read(PACKET_HEADER_LEN)
            if not rec:
                break  # clean EOF
            if len(rec) < PACKET_HEADER_LEN:
                warnings.append(
                    PcapWarning(
                        reason=(
                            "truncated packet record header at end of file "
                            f"({len(rec)} of {PACKET_HEADER_LEN} bytes)"
                        ),
                        packet_index=index,
                    )
                )
                break
            ts_sec, ts_frac, incl_len, orig_len = struct.unpack(f"{order}IIII", rec)
            if incl_len > 10_000_000:
                warnings.append(
                    PcapWarning(
                        reason=(
                            f"absurd captured length {incl_len} at packet "
                            f"{index}; stopping (file may be corrupt)"
                        ),
                        packet_index=index,
                    )
                )
                break
            data = fh.read(incl_len)
            if len(data) < incl_len:
                warnings.append(
                    PcapWarning(
                        reason=(
                            f"truncated packet data at packet {index}: "
                            f"got {len(data)} of {incl_len} bytes"
                        ),
                        packet_index=index,
                    )
                )
                break
            timestamp = _packet_timestamp(order, header.ts_resolution, ts_sec, ts_frac)
            yield index, timestamp, data, incl_len < orig_len
            index += 1


def linktype_name(linktype: int) -> str:
    return LINKTYPE_NAMES.get(linktype, f"linktype-{linktype}")
