"""Indicator type guessing for linked indicators.

The guess is a convenience only: every linked indicator records
whether its type was guessed from the value's shape or explicitly
chosen by the analyst with ``--type``. Guesses are never presented
as verified classifications.
"""

from __future__ import annotations

import ipaddress
import re

from aegisforge.cases.models import INDICATOR_TYPES

_HEX_HASH_RE = re.compile(r"^[0-9a-fA-F]{32}$|^[0-9a-fA-F]{40}$|^[0-9a-fA-F]{64}$")


def guess_indicator_type(value: str) -> str:
    """Guess an indicator type from the value's shape.

    Returns one of ``INDICATOR_TYPES``. The caller records this as a
    guess, never a verified classification.
    """
    text = value.strip()
    if not text:
        return "domain"
    try:
        ipaddress.ip_address(text)
        return "ip"
    except ValueError:
        pass
    if _HEX_HASH_RE.match(text):
        return "hash"
    lowered = text.lower()
    if lowered.startswith(("http://", "https://", "ftp://")):
        return "url"
    if "@" in text and "." in text.split("@")[-1]:
        return "email"
    return "domain"


def check_indicator_type(type_name: str) -> str:
    """Validate an analyst-specified indicator type."""
    lowered = type_name.strip().lower()
    if lowered not in INDICATOR_TYPES:
        raise ValueError(
            f"unknown indicator type {type_name!r}; "
            f"expected one of {', '.join(INDICATOR_TYPES)}"
        )
    return lowered
