"""Interface, route and neighbour discovery via OS utilities.

Cross-platform with graceful degradation: every function returns a
list (possibly empty) plus a ``notes`` entry describing what could not
be collected. All subprocess calls use argument lists, never shell=True,
with hard timeouts.
"""

from __future__ import annotations

import json
import platform
import re
import subprocess
from typing import Any

_SUBPROCESS_TIMEOUT = 15.0


def _run(argv: list[str]) -> str | None:
    try:
        proc = subprocess.run(
            argv,
            capture_output=True,
            text=True,
            timeout=_SUBPROCESS_TIMEOUT,
            check=False,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return None
    if proc.returncode != 0:
        return None
    return proc.stdout


def _interfaces_ip_json() -> list[dict[str, Any]] | None:
    out = _run(["ip", "-j", "addr"])
    if out is None:
        return None
    try:
        data = json.loads(out)
    except json.JSONDecodeError:
        return None
    interfaces: list[dict[str, Any]] = []
    for entry in data:
        ipv4: list[str] = []
        ipv6: list[str] = []
        for addr in entry.get("addr_info", []):
            family = addr.get("family")
            local = addr.get("local")
            if not local:
                continue
            if family == "inet":
                ipv4.append(local)
            elif family == "inet6":
                ipv6.append(local)
        interfaces.append(
            {
                "name": entry.get("ifname", "?"),
                "mac": entry.get("address"),
                "mtu": entry.get("mtu"),
                "status": entry.get("operstate", "unknown").lower(),
                "ipv4": ipv4,
                "ipv6": ipv6,
            }
        )
    return interfaces


def _interfaces_ifconfig() -> list[dict[str, Any]] | None:
    out = _run(["ifconfig"])
    if out is None:
        return None
    interfaces: list[dict[str, Any]] = []
    current: dict[str, Any] | None = None
    for line in out.splitlines():
        if line and not line[0].isspace():
            name = line.split(":")[0].strip()
            current = {
                "name": name,
                "mac": None,
                "mtu": None,
                "status": "unknown",
                "ipv4": [],
                "ipv6": [],
            }
            interfaces.append(current)
            flags = re.search(r"flags=\d+<([^>]*)>", line)
            if flags and "UP" in flags.group(1).split(","):
                current["status"] = "up"
            mtu = re.search(r"\bmtu\s+(\d+)", line)
            if mtu:
                current["mtu"] = int(mtu.group(1))
        elif current is not None:
            mac = re.search(r"(?:ether|address:|HWaddr)\s+([0-9a-fA-F:]{17})", line)
            if mac and not current["mac"]:
                current["mac"] = mac.group(1).lower()
            inet = re.search(r"\binet\s+(\d+\.\d+\.\d+\.\d+)", line)
            if inet:
                current["ipv4"].append(inet.group(1))
            inet6 = re.search(r"\binet6\s+([0-9a-fA-F:]+)(?:%[\w.]+)?", line)
            if inet6:
                current["ipv6"].append(inet6.group(1))
    return interfaces


def _interfaces_ipconfig() -> list[dict[str, Any]] | None:
    out = _run(["ipconfig", "/all"])
    if out is None:
        return None
    interfaces: list[dict[str, Any]] = []
    current: dict[str, Any] | None = None
    for line in out.splitlines():
        stripped = line.strip()
        if (
            not line.startswith((" ", "\t"))
            and stripped
            and not stripped.startswith("Windows")
        ):
            current = {
                "name": stripped.rstrip(":"),
                "mac": None,
                "mtu": None,
                "status": "unknown",
                "ipv4": [],
                "ipv6": [],
            }
            interfaces.append(current)
        elif current is not None:
            mac = re.search(r"Physical Address[.\s]*:\s*([0-9A-Fa-f-]{17})", line)
            if mac:
                current["mac"] = mac.group(1).replace("-", ":").lower()
            ipv4 = re.search(r"IPv4 Address[.\s]*:\s*([\d.]+)", line)
            if ipv4:
                current["ipv4"].append(ipv4.group(1))
            ipv6 = re.search(r"IPv6 Address[.\s]*:\s*([0-9a-fA-F:]+)", line)
            if ipv6:
                current["ipv6"].append(ipv6.group(1))
    # Drop the header pseudo-entry if it collected nothing.
    return [i for i in interfaces if i["ipv4"] or i["ipv6"] or i["mac"]]


def list_interfaces() -> dict[str, Any]:
    """Return local network interfaces with a collection note."""
    system = platform.system()
    interfaces: list[dict[str, Any]] | None = None
    method = ""
    if system == "Windows":
        interfaces = _interfaces_ipconfig()
        method = "ipconfig"
    else:
        interfaces = _interfaces_ip_json()
        method = "ip addr"
        if interfaces is None:
            interfaces = _interfaces_ifconfig()
            method = "ifconfig"
    notes: list[str] = []
    if interfaces is None:
        interfaces = []
        notes.append(f"no supported interface discovery utility found ({method})")
    return {"interfaces": interfaces, "method": method, "notes": notes}


def _routes_ip_json() -> list[dict[str, Any]] | None:
    out = _run(["ip", "-j", "route"])
    if out is None:
        return None
    try:
        data = json.loads(out)
    except json.JSONDecodeError:
        return None
    routes = []
    for entry in data:
        routes.append(
            {
                "destination": entry.get("dst", "default"),
                "gateway": entry.get("gateway"),
                "interface": entry.get("dev"),
                "metric": entry.get("metric"),
            }
        )
    return routes


def list_routes() -> dict[str, Any]:
    """Return the local routing table (best effort)."""
    system = platform.system()
    routes: list[dict[str, Any]] | None = None
    method = ""
    if system != "Windows":
        routes = _routes_ip_json()
        method = "ip route"
    notes: list[str] = []
    if routes is None:
        routes = []
        notes.append(f"route collection not implemented for this platform ({method})")
    return {"routes": routes, "method": method, "notes": notes}


def _neighbours_ip_json() -> list[dict[str, Any]] | None:
    out = _run(["ip", "-j", "neigh"])
    if out is None:
        return None
    try:
        data = json.loads(out)
    except json.JSONDecodeError:
        return None
    neighbours = []
    for entry in data:
        neighbours.append(
            {
                "ip": entry.get("dst"),
                "mac": entry.get("lladdr"),
                "interface": entry.get("dev"),
                "state": entry.get("state"),
            }
        )
    return neighbours


def list_neighbours() -> dict[str, Any]:
    """Return the ARP/neighbour table (best effort, Linux primary)."""
    neighbours = _neighbours_ip_json()
    notes: list[str] = []
    method = "ip neigh"
    if neighbours is None:
        neighbours = []
        notes.append("neighbour discovery requires 'ip neigh' (Linux)")
    return {"neighbours": neighbours, "method": method, "notes": notes}
