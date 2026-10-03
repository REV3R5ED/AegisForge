"""Threat-intelligence enrichment (v0.8): provider-neutral interface.

Normalize indicators first, send them only to explicitly configured
sources. IP/domain/URL/hash indicators, pluggable providers, normalized
intel records, confidence/source metadata, SQLite caching, per-provider
rate limits, and correlation with local evidence (cases, pcaps).

Two hard rules, enforced by the engine:
- network providers run only with ``--enrich``;
- indicators sent to a network provider leave the machine — ``intel
  lookup`` names every network provider it contacts.
"""

from aegisforge.core.plugins import ModuleInfo, register

register(
    ModuleInfo(
        name="intel",
        description=(
            "Threat-intelligence enrichment: indicator normalization "
            "(defang/refang, hashes, URLs), pluggable provider interface, "
            "built-in local-blocklist / Team Cymru / DNS / stub providers, "
            "SQLite caching, per-provider rate limits, and correlation "
            "with case and pcap evidence"
        ),
        version="0.8.0",
        commands=[
            "intel lookup",
            "intel correlate",
            "intel providers",
            "intel cache-clear",
        ],
    )
)
