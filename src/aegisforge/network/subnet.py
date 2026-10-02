"""IPv4/IPv6 subnet calculator and bounded CIDR expansion.

Pure local computation (stdlib ``ipaddress``) — no network traffic.
"""

from __future__ import annotations

from typing import Any

from aegisforge.network.validation import (
    ValidationError,
    validate_cidr,
    validate_positive_int,
)

# Absolute safety cap so a /0 can never materialize millions of addresses.
HARD_MAX_HOSTS = 65536


def describe_subnet(cidr: str) -> dict[str, Any]:
    """Return calculator details for a CIDR block."""
    network = validate_cidr(cidr)
    first = None
    last = None
    usable = 0
    if network.version == 4:
        if network.prefixlen <= 30:
            hosts = list(network.hosts())
            first = str(hosts[0])
            last = str(hosts[-1])
            usable = len(hosts)
        elif network.prefixlen == 31:
            first, last = str(network.network_address), str(network.broadcast_address)
            usable = 2
        else:  # /32
            first = last = str(network.network_address)
            usable = 1
    else:
        usable = network.num_addresses
    return {
        "cidr": str(network),
        "version": network.version,
        "network_address": str(network.network_address),
        "broadcast_address": str(network.broadcast_address),
        "netmask": str(network.netmask),
        "hostmask": str(network.hostmask),
        "prefixlen": network.prefixlen,
        "num_addresses": network.num_addresses,
        "num_usable_hosts": usable,
        "first_usable": first,
        "last_usable": last,
        "is_private": network.is_private,
        "is_global": network.is_global,
        "is_multicast": network.is_multicast,
        "is_reserved": network.is_reserved,
        "is_loopback": network.is_loopback,
    }


def expand_cidr(cidr: str, max_hosts: int = 1024) -> list[str]:
    """Expand a CIDR to host address strings, bounded by ``max_hosts``.

    Raises ValidationError if the block holds more addresses than allowed.
    """
    max_hosts = validate_positive_int("max_hosts", max_hosts, maximum=HARD_MAX_HOSTS)
    network = validate_cidr(cidr)
    if network.num_addresses > max_hosts:
        raise ValidationError(
            f"{cidr} holds {network.num_addresses} addresses, more than the "
            f"limit of {max_hosts}; narrow the block or raise --max-hosts "
            f"(hard cap {HARD_MAX_HOSTS})"
        )
    if network.version == 4 and network.prefixlen < 31:
        return [str(h) for h in network.hosts()]
    return [str(h) for h in network]
