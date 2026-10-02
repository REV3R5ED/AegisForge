"""Local asset inventory: hostname, OS, interfaces, gateways, DNS.

Composes the discovery primitives into one host-centric view used by
later phases (case management, correlation) as the canonical local
asset record.
"""

from __future__ import annotations

import platform
import socket
from typing import Any

from aegisforge.network.interfaces import list_interfaces, list_routes


def _dns_servers() -> tuple[list[str], list[str]]:
    servers: list[str] = []
    notes: list[str] = []
    if platform.system() == "Windows":
        notes.append("DNS server enumeration is not implemented on Windows")
        return servers, notes
    try:
        with open("/etc/resolv.conf", encoding="utf-8") as fh:
            for line in fh:
                parts = line.split()
                if len(parts) >= 2 and parts[0] == "nameserver":
                    servers.append(parts[1])
    except OSError as exc:
        notes.append(f"could not read /etc/resolv.conf: {exc}")
    return servers, notes


def local_inventory() -> dict[str, Any]:
    """Collect the local asset inventory record."""
    interfaces = list_interfaces()
    routes = list_routes()
    dns_servers, dns_notes = _dns_servers()

    gateways: list[str] = []
    for route in routes["routes"]:
        gw = route.get("gateway")
        if route.get("destination") in ("default", "0.0.0.0/0", "::/0") and gw:
            gateways.append(gw)

    try:
        hostname = socket.gethostname()
    except OSError:
        hostname = "unknown"
    try:
        fqdn = socket.getfqdn()
    except OSError:
        fqdn = hostname

    notes: list[str] = []
    notes.extend(interfaces.get("notes", []))
    notes.extend(routes.get("notes", []))
    notes.extend(dns_notes)

    return {
        "hostname": hostname,
        "fqdn": fqdn,
        "platform": platform.system(),
        "platform_release": platform.release(),
        "python": platform.python_version(),
        "interfaces": interfaces["interfaces"],
        "default_gateways": sorted(set(gateways)),
        "dns_servers": dns_servers,
        "notes": notes,
    }
