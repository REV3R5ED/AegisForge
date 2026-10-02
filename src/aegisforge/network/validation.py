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
