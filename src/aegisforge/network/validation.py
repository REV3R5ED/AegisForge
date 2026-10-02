"""Input validation shared by network commands.

All validation is fail-fast with clear messages; nothing here touches
the network. Subprocess callers must additionally never use shell=True.
"""

from __future__ import annotations

import ipaddress
import re

# Hostnames / targets: printable, no whitespace or shell metacharacters.
_TARGET_RE = re.compile(r"^[A-Za-z0-9._:-]{1,253}$")
_UNSAFE_RE = re.compile(r"[\s;&|$`\"'\\!*?~#%()\[\]{}<>]")


class ValidationError(ValueError):
    """Raised when user input fails validation."""


def validate_target(target: str, *, allow_cidr: bool = False) -> str:
    """Validate a single host target (IP or DNS name). Returns the stripped target."""
    if not isinstance(target, str):
        raise ValidationError("target must be a string")
    cleaned = target.strip()
    if not cleaned:
        raise ValidationError("target must not be empty")
    if len(cleaned) > 253:
        raise ValidationError("target is too long (max 253 characters)")
    if _UNSAFE_RE.search(cleaned):
        raise ValidationError(f"target contains unsafe characters: {cleaned!r}")
    if not _TARGET_RE.match(cleaned):
        raise ValidationError(
            f"target is not a valid hostname or IP address: {cleaned!r}"
        )
    if "/" in cleaned and not allow_cidr:
        raise ValidationError(f"CIDR notation is not accepted here: {cleaned!r}")
    return cleaned


def validate_targets(targets: list[str], *, max_targets: int) -> list[str]:
    if not targets:
        raise ValidationError("at least one target is required")
    if len(targets) > max_targets:
        raise ValidationError(
            f"too many targets ({len(targets)}); maximum is {max_targets}"
        )
    seen: set[str] = set()
    result: list[str] = []
    for target in targets:
        cleaned = validate_target(target)
        if cleaned not in seen:
            seen.add(cleaned)
            result.append(cleaned)
    return result


def validate_cidr(cidr: str) -> ipaddress.IPv4Network | ipaddress.IPv6Network:
    """Parse and validate a CIDR block. Raises ValidationError on failure."""
    if not isinstance(cidr, str) or not cidr.strip():
        raise ValidationError("CIDR must not be empty")
    cleaned = cidr.strip()
    if _UNSAFE_RE.search(cleaned):
        raise ValidationError(f"CIDR contains unsafe characters: {cleaned!r}")
    try:
        return ipaddress.ip_network(cleaned, strict=False)
    except ValueError as exc:
        raise ValidationError(f"invalid CIDR {cleaned!r}: {exc}") from exc


def validate_port(port: int) -> int:
    if not isinstance(port, int) or isinstance(port, bool):
        raise ValidationError(f"port must be an integer, got {port!r}")
    if not 1 <= port <= 65535:
        raise ValidationError(f"port must be 1-65535, got {port}")
    return port


def validate_positive_int(
    name: str, value: int, *, minimum: int = 1, maximum: int | None = None
) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise ValidationError(f"{name} must be an integer, got {value!r}")
    if value < minimum:
        raise ValidationError(f"{name} must be >= {minimum}, got {value}")
    if maximum is not None and value > maximum:
        raise ValidationError(f"{name} must be <= {maximum}, got {value}")
    return value


def validate_timeout(value: float) -> float:
    if not isinstance(value, (int, float)) or isinstance(value, bool):
        raise ValidationError(f"timeout must be a number, got {value!r}")
    if not 0.1 <= float(value) <= 120.0:
        raise ValidationError(
            f"timeout must be between 0.1 and 120 seconds, got {value}"
        )
    return float(value)


def is_public_ip(value: str) -> bool:
    """True when *value* is a globally routable IP address.

    Loopback, private (RFC 1918 / ULA), link-local, reserved, multicast
    and unspecified addresses return False. Pure function — no network.
    """
    try:
        ip = ipaddress.ip_address(value.strip())
    except ValueError as exc:
        raise ValidationError(f"not a valid IP address: {value!r}") from exc
    return not (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_reserved
        or ip.is_multicast
        or ip.is_unspecified
    )


def parse_port_spec(
    ports: str | None,
    port_range: str | None,
    *,
    max_ports: int,
    default: list[int],
) -> list[int]:
    """Parse ``--ports 22,80,443`` and/or ``--port-range 1-1024``.

    Returns a sorted, deduplicated port list. When neither is given the
    *default* list is returned. Raises ValidationError on bad input or
    when the selection exceeds *max_ports*.
    """
    selected: set[int] = set()
    if ports:
        for chunk in ports.split(","):
            chunk = chunk.strip()
            if not chunk:
                raise ValidationError(f"invalid --ports value {ports!r}: empty entry")
            if not re.fullmatch(r"\d{1,5}", chunk):
                raise ValidationError(
                    f"invalid --ports value {ports!r}: {chunk!r} is not a port number"
                )
            selected.add(validate_port(int(chunk)))
    if port_range:
        match = re.fullmatch(r"\s*(\d{1,5})\s*-\s*(\d{1,5})\s*", port_range)
        if not match:
            raise ValidationError(
                f"invalid --port-range value {port_range!r}: "
                "expected START-END, e.g. 1-1024"
            )
        start, end = (
            validate_port(int(match.group(1))),
            validate_port(int(match.group(2))),
        )
        if start > end:
            raise ValidationError(f"invalid --port-range {port_range!r}: start > end")
        selected.update(range(start, end + 1))
    if not selected:
        return sorted(set(default))
    if len(selected) > max_ports:
        raise ValidationError(
            f"port selection too large ({len(selected)} ports); maximum is {max_ports}"
        )
    return sorted(selected)


_BASELINE_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$")


def validate_baseline_name(name: str) -> str:
    """Validate a baseline name (safe for use as a file name)."""
    if not isinstance(name, str):
        raise ValidationError("baseline name must be a string")
    cleaned = name.strip()
    if not _BASELINE_NAME_RE.match(cleaned):
        raise ValidationError(
            f"invalid baseline name {name!r}: use 1-64 characters of "
            "letters, digits, '-' and '_', starting with a letter or digit"
        )
    return cleaned
