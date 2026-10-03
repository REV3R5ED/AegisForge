"""Entity normalization for the correlation engine.

IP/domain/URL/hash reuse :mod:`aegisforge.intel.normalize`; this module
adds the two entity types intel does not cover:

- ``user``: lowercased; ``DOMAIN\\\\user`` and ``user@DOMAIN`` both
  canonicalize to ``user@domain``; bare names stay bare. Rejects empty
  values and anything containing whitespace or control characters.
- ``hostname``: lowercased, trailing dot stripped; single labels are
  allowed (unlike domains, which require two or more labels).

:func:`normalize_entity` tries each type in turn unless ``type_hint``
is given, and returns ``None`` for values that normalize to nothing —
callers decide whether to count or skip those.
"""

from __future__ import annotations

import re

from aegisforge.correlate.models import ENTITY_TYPES, Entity
from aegisforge.intel import normalize as intel_normalize

_HOSTNAME_LABEL = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$")
_USER_BAD = re.compile(r"[\s\x00-\x1f\x7f]")


def normalize_user(raw: str) -> str | None:
    """Canonicalize a username; None when it is not a usable name."""
    text = raw.strip()
    if not text or _USER_BAD.search(text):
        return None
    if "\\" in text:
        domain, _, user = text.partition("\\")
        domain, user = domain.strip().lower(), user.strip().lower()
        if not domain or not user or _USER_BAD.search(user + domain):
            return None
        if not _has_alnum(user):
            return None
        return f"{user}@{domain}"
    if "@" in text:
        user, _, domain = text.partition("@")
        user, domain = user.strip().lower(), domain.strip().lower()
        if not user or not domain or not _has_alnum(user):
            return None
        return f"{user}@{domain}"
    if not _has_alnum(text):
        return None
    return text.lower()


def _has_alnum(text: str) -> bool:
    return any(ch.isalnum() for ch in text)


def normalize_hostname(raw: str) -> str | None:
    """Canonicalize a hostname; None when it is not a usable name."""
    host = raw.strip().rstrip(".").lower()
    if not host or len(host) > 253 or ".." in host:
        return None
    if not all(_HOSTNAME_LABEL.match(label) for label in host.split(".")):
        return None
    return host


def normalize_entity(raw: str, type_hint: str | None = None) -> Entity | None:
    """Normalize one raw value into an :class:`Entity`, or None.

    With ``type_hint`` the value is normalized as that type only;
    otherwise ip/domain/url/hash are tried first (via the intel
    normalizer), then user, then hostname.
    """
    text = raw.strip()
    if not text:
        return None
    if type_hint is not None:
        if type_hint not in ENTITY_TYPES:
            raise ValueError(
                f"entity type must be one of {ENTITY_TYPES}, got {type_hint!r}"
            )
        return _normalize_typed(text, type_hint)
    ind = intel_normalize.normalize_indicator(text)
    if not ind.rejected:
        return Entity(value=ind.value, type=ind.type)
    user = normalize_user(text)
    if user is not None:
        return Entity(value=user, type="user")
    host = normalize_hostname(text)
    if host is not None:
        return Entity(value=host, type="hostname")
    return None


def _normalize_typed(text: str, type_hint: str) -> Entity | None:
    if type_hint in ("ip", "domain", "url", "hash"):
        ind = intel_normalize.normalize_indicator(text)
        if ind.rejected or ind.type != type_hint:
            return None
        return Entity(value=ind.value, type=ind.type)
    if type_hint == "user":
        user = normalize_user(text)
        return Entity(value=user, type="user") if user else None
    if type_hint == "hostname":
        host = normalize_hostname(text)
        return Entity(value=host, type="hostname") if host else None
    return None  # pragma: no cover - ENTITY_TYPES is closed


def normalize_entities(values: list[str], type_hint: str | None = None) -> list[Entity]:
    """Normalize a batch of raw values, dropping the unusable ones."""
    entities: list[Entity] = []
    for value in values:
        entity = normalize_entity(value, type_hint)
        if entity is not None:
            entities.append(entity)
    return entities
