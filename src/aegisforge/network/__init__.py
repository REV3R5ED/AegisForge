"""Network module (v0.2): discovery plus port/service analysis.

v0.1: subnet, ping, DNS, traceroute, interfaces, inventory.
v0.2: authorized TCP port/service scanning with TLS/HTTP probing and
scan baselines with change detection.
"""

from aegisforge.core.plugins import ModuleInfo, register

register(
    ModuleInfo(
        name="network",
        description=(
            "Network discovery and port/service analysis: subnet, ping, "
            "DNS, traceroute, interfaces, TCP port scanning, TLS/HTTP "
            "probing, scan baselines"
        ),
        version="0.2.0",
        commands=[
            "network subnet",
            "network ping",
            "network dns",
            "network trace",
            "network interfaces",
            "network inventory",
            "network scan",
            "network baseline",
        ],
    )
)
