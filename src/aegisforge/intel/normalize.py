"""Indicator normalization.

:func:`normalize_indicator` turns one raw string into a canonical
:class:`~aegisforge.intel.models.NormalizedIndicator`, or rejects it with
a reason. Rejections are explicit — nothing is ever silently kept.

Normalization rules:
- surrounding whitespace stripped
- defanged forms refanged and labeled: ``hxxp://``/``hxtp://`` →
  ``http://``, ``[.]``/``(.)``/``{.}`` → ``.`` (``defanged=True``)
- domains lowercased, trailing dot stripped
- URLs: scheme required; the host becomes the normalized value while the
  full URL is kept separately; userinfo and fragments dropped
- hashes: 32/40/64 hex characters → md5/sha1/sha256
- IPs validated with :mod:`ipaddress` (v4 and v6)
"""

from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlsplit

from aegisforge.intel.models import HASH_LENGTHS, NormalizedIndicator

_DEFANG_SCHEMES = (
    ("hxxp://", "http://"),
    ("hxxps://", "https://"),
    ("hxtp://", "http://"),
    ("hxtps://", "https://"),
)
_DEFANG_DOT = re.compile(r"\[\.\] | \(\.\) | \{\.\}", re.VERBOSE)
_DOMAIN_LABEL = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$")
_HEX = re.compile(r"^[0-9a-fA-F]+$")


def _refang(text: str) -> tuple[str, bool]:
    """Undo common defanging; returns (text, was_defanged)."""
    lowered = text.lower()
    changed = False
    for bad, good in _DEFANG_SCHEMES:
        if lowered.startswith(bad):
            text = good + text[len(bad) :]
            changed = True
            break
    new_text, n = _DEFANG_DOT.subn(".", text)
    if n:
        text = new_text
        changed = True
    return text, changed


def _is_valid_domain(host: str) -> bool:
    if not host or len(host) > 253:
        return False
    if host.startswith(".") or host.endswith(".") or ".." in host:
        return False
    labels = host.split(".")
    if len(labels) < 2:
        return False
    return all(_DOMAIN_LABEL.match(label) for label in labels)


def _normalize_ip(text: str) -> str | None:
    try:
        return str(ipaddress.ip_address(text))
    except ValueError:
        return None


def normalize_indicator(raw: str) -> NormalizedIndicator:
    """Normalize one raw indicator string.

    Returns a :class:`NormalizedIndicator` with ``rejected=True`` and a
    ``reject_reason`` when the input cannot be interpreted as an
    IP, domain, URL or hash — never raises on bad input.
    """
    original = raw
    text = raw.strip()
    if not text:
        return _rejected(original, "empty indicator")

    text, defanged = _refang(text)

    # URL: must have an explicit scheme.
    if "://" in text:
        try:
            parts = urlsplit(text)
        except ValueError:
            return _rejected(original, "unparseable URL")
        host = (parts.hostname or "").rstrip(".").lower()
        if not parts.scheme or not host:
            return _rejected(original, "URL without scheme or host")
        if not _is_valid_domain(host) and _normalize_ip(host) is None:
            return _rejected(original, f"URL host {host!r} is not a valid domain or IP")
        return NormalizedIndicator(
            value=host,
            type="url",
            original=original,
            domain=host,
            url=text,
            defanged=defanged,
        )

    # Hash: 32/40/64 hex characters.
    if _HEX.match(text) and len(text) in HASH_LENGTHS:
        return NormalizedIndicator(
            value=text.lower(),
            type="hash",
            original=original,
            hash_kind=HASH_LENGTHS[len(text)],
            defanged=defanged,
        )

    # IP address.
    ip = _normalize_ip(text)
    if ip is not None:
        return NormalizedIndicator(
            value=ip, type="ip", original=original, defanged=defanged
        )

    # Domain.
    host = text.rstrip(".").lower()
    if _is_valid_domain(host):
        return NormalizedIndicator(
            value=host, type="domain", original=original, defanged=defanged
        )

    return _rejected(original, f"not a valid IP, domain, URL or hash: {text!r}")


def _rejected(original: str, reason: str) -> NormalizedIndicator:
    # Rejections still carry the NormalizedIndicator shape so callers can
    # report them uniformly; ``rejected=True`` marks them unusable and
    # skips type/value validation.
    return NormalizedIndicator(
        value=original.strip(),
        type="ip",  # placeholder; ignored while rejected=True
        original=original,
        rejected=True,
        reject_reason=reason,
    )


def normalize_indicators(values: list[str]) -> list[NormalizedIndicator]:
    """Normalize a batch of raw indicator strings."""
    return [normalize_indicator(v) for v in values]
