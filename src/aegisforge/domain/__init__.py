"""Domain investigation module (v0.3): DNS, domain & internet investigation.

Passive directory lookups — DNS record collection, nameserver/MX
analysis, DNSSEC presence, TLS inspection, RDAP/WHOIS, ASN ownership,
HTTP redirect/header collection — consolidated into one report via
``domain investigate``.
"""

from aegisforge.core.plugins import ModuleInfo, register

register(
    ModuleInfo(
        name="domain",
        description=(
            "Domain investigation: DNS records (A/AAAA/MX/NS/TXT/SOA/CNAME), "
            "nameserver and MX analysis, DNSSEC presence, TLS certificate "
            "inspection, RDAP/WHOIS, ASN ownership, HTTP redirect and "
            "header collection"
        ),
        version="0.3.0",
        commands=[
            "domain dns",
            "domain investigate",
        ],
    )
)
