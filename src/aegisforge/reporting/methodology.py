"""Static methodology text for reports.

Each entry describes one AegisForge capability module: what it does,
how it works, and — deliberately — what it cannot do. Reports include
this section so a reader can judge the findings without trusting the
tool blindly.
"""

from __future__ import annotations

from typing import Any

# Static, honest descriptions. ``version`` is filled in from the plugin
# registry at report time; anything not registered is left out.
_METHODS: dict[str, dict[str, str]] = {
    "network": {
        "purpose": "Network discovery and authorized port/service analysis.",
        "method": (
            "ARP/ICMP/ping sweep for discovery; TCP connect scans with "
            "banner grabs and TLS/HTTP service probes for port analysis; "
            "scan baselines diffed for change detection."
        ),
        "limitations": (
            "Port states are point-in-time observations of one vantage "
            "point. A closed/filtered port is not proof a service is "
            "absent; banner strings are self-reported by the remote host."
        ),
    },
    "domain": {
        "purpose": "Domain investigation: DNS records, RDAP/WHOIS, ASN, TLS.",
        "method": (
            "Passive directory lookups (DNS, RDAP, WHOIS, TLS certificate "
            "inspection, HTTP headers) consolidated into one report. No "
            "scanning of the target's hosts."
        ),
        "limitations": (
            "Registry and DNS data may be stale, redacted for privacy, or "
            "spoofed in transit. Certificate presence does not imply "
            "legitimacy."
        ),
    },
    "logs": {
        "purpose": "Streaming log analysis with format auto-detection.",
        "method": (
            "Single-pass streaming parsers (syslog, Apache/Nginx, JSON "
            "lines, Windows Event XML, key=value); timeline, histograms, "
            "top talkers, error extraction and burst detection."
        ),
        "limitations": (
            "Findings describe patterns in the lines provided. Log "
            "timestamps are written by the source system and can be wrong "
            "or forged; missing logs are invisible to the analysis."
        ),
    },
    "forensics": {
        "purpose": "Read-only file inventory, hashing and timelines.",
        "method": (
            "Recursive inventory with magic-byte identification, "
            "single-pass multi-algorithm hashing, sealed evidence "
            "manifests with later verification (changed/missing/new), "
            "duplicate detection and filesystem timelines."
        ),
        "limitations": (
            "Metadata (mtime/atime) can be altered by tools or attackers. "
            "Hashing proves a file's bytes at hash time, not its origin."
        ),
    },
    "cases": {
        "purpose": "Incident-response case management.",
        "method": (
            "Evidence files are copied (never moved) with SHA-256 recorded "
            "at attach time; unified chronological timeline across "
            "log/file/network evidence; finding lifecycle tracking; "
            "append-only analyst notes."
        ),
        "limitations": (
            "A case only contains what was attached to it. The timeline "
            "merges evidence as-is; untimed entries are listed separately, "
            "never silently dropped."
        ),
    },
    "pcap": {
        "purpose": "Offline PCAP and traffic analysis.",
        "method": (
            "Single-pass packet parsing (no capture, fully offline): "
            "conversations, DNS/HTTP/TLS extraction, top talkers, "
            "indicators and timelines from packet data."
        ),
        "limitations": (
            "Encrypted payloads are opaque; only metadata (sizes, timing, "
            "endpoints, handshake fields) is analyzed. Packet timestamps "
            "come from the capture, not from AegisForge."
        ),
    },
    "intel": {
        "purpose": "Threat-intelligence enrichment of indicators.",
        "method": (
            "Indicator normalization (defang/refang) first; pluggable "
            "providers with SQLite caching and per-provider rate limits. "
            "Network providers run only with explicit --enrich consent."
        ),
        "limitations": (
            "A verdict reflects the provider's data at lookup time, not "
            "ground truth. Blocklist hits mean 'listed', not 'guilty'. "
            "Unless --enrich was used, only local/offline sources were "
            "consulted."
        ),
    },
    "correlate": {
        "purpose": "Cross-source entity correlation over case evidence.",
        "method": (
            "Entity normalization, in-memory entity graph, cross-source "
            "pivot detection, temporal correlation and explainable "
            "arithmetic confidence scores. Strictly read-only."
        ),
        "limitations": (
            "Scores describe the strength of the observation, never "
            "causation. Temporal proximity is 'observed within X of each "
            "other', not 'caused by'."
        ),
    },
}


def methodology_sections(registry: Any) -> list[dict[str, str]]:
    """Methodology entries for every registered module we describe."""
    sections: list[dict[str, str]] = []
    try:
        names = registry.names()
    except Exception:  # defensive: methodology must never break a report
        return sections
    for name in names:
        static = _METHODS.get(name)
        if static is None:
            continue
        try:
            info = registry.get(name)
            version = info.version
        except Exception:
            version = "unknown"
        sections.append(
            {
                "module": name,
                "version": version,
                "purpose": static["purpose"],
                "method": static["method"],
                "limitations": static["limitations"],
            }
        )
    return sections


NOT_CLAIMS: tuple[str, ...] = (
    "This report does not attribute activity to any person or organization.",
    "Correlation scores and temporal proximity describe observation "
    "strength, never causation.",
    "Timestamps come from evidence sources and may be wrong, altered or forged.",
    '"No findings" means "nothing found in the analyzed evidence", not '
    '"nothing happened".',
    "Indicator verdicts reflect provider data at lookup time, not ground truth.",
    "Severity and confidence are analyst/tool judgments, not measurements.",
)
