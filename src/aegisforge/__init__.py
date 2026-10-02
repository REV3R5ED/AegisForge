"""AegisForge — modular defensive-security and DFIR platform.

v0.3: architectural foundation (core) + network discovery + authorized
port/service analysis with baselines + domain/DNS investigation
(RDAP/WHOIS/ASN/TLS/HTTP).
Later phases (forensics, logs, PCAP, intel, correlation, cases,
reporting) plug into the core models defined here.
"""

__version__ = "0.3.0"
__author__ = "Pouya Shini Karim"

from aegisforge.core import (
    config,
    events,
    evidence,
    findings,
    logging,
    plugins,
    results,
)

__all__ = [
    "__version__",
    "config",
    "events",
    "evidence",
    "findings",
    "logging",
    "plugins",
    "results",
]
