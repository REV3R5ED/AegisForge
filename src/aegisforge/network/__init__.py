"""Network discovery package (v0.1): subnet, ping, DNS, traceroute, interfaces."""

from aegisforge.core.plugins import ModuleInfo, register

register(
    ModuleInfo(
        name="network",
        description="Network discovery: subnet, ping, DNS, traceroute, interfaces",
        version="0.1.0",
        commands=[
            "network subnet",
            "network ping",
            "network dns",
            "network trace",
            "network interfaces",
            "network inventory",
        ],
    )
)
