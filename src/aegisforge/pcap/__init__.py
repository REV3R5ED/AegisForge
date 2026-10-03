"""Offline PCAP & traffic analysis (v0.7).

Classic pcap files are read in a streaming fashion (never loaded wholly
into memory) and decoded with stdlib-only protocol parsers: Ethernet /
Linux cooked link layers, IPv4, IPv6, TCP, UDP, ICMP/ICMPv6. On top of
the packet stream the module builds protocol statistics, conversation
(5-tuple flow) summaries, DNS activity, HTTP/TLS metadata, unusual-port
and connection-frequency findings, a deduped observed-indicator list,
and a timeline that feeds the core event model.

pcapng is detected and refused with a clean error (out of scope for
v0.7). No payload reassembly is performed; payload lengths are
recorded, never contents, and HTTP records are truncated for privacy.
"""

from aegisforge.core.plugins import ModuleInfo, register

register(
    ModuleInfo(
        name="pcap",
        description=(
            "Offline PCAP analysis: streaming classic-pcap reader "
            "(Ethernet/Linux-cooked, IPv4/IPv6, TCP/UDP/ICMP); protocol "
            "stats, conversation summaries, DNS activity, HTTP/TLS "
            "metadata, unusual ports, connection frequency, top talkers, "
            "observed-indicator extraction and timeline integration with "
            "observed-vs-inferred findings"
        ),
        version="0.7.0",
        commands=[
            "pcap summary",
            "pcap conversations",
            "pcap dns",
            "pcap http",
            "pcap tls",
            "pcap indicators",
            "pcap timeline",
        ],
    )
)
