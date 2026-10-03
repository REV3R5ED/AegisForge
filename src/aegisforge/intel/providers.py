"""Provider-neutral threat-intel interface.

A provider is a class implementing :class:`IntelProvider`. Providers are
registered by name in :data:`PROVIDERS` and instantiated by the engine.

Two hard rules:

1. **No implicit network calls.** A provider with ``network = True`` is
   only ever invoked when it is explicitly configured *and* the user
   passed ``--enrich``. Without ``--enrich`` the engine runs local
   providers only (blocklist lookups, cache hits), so the tool works
   fully offline.
2. **No exfiltration surprises.** Indicators sent to a network provider
   leave the machine. ``intel lookup`` prints a one-line notice naming
   every network provider it contacts.

Third-party providers subclass :class:`IntelProvider`, implement
``lookup`` and ``is_configured``, and call :func:`register_provider`.
API keys come from environment variables only — never config files.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from aegisforge.intel.models import IntelRecord, NormalizedIndicator


class IntelProvider(ABC):
    """One threat-intel source.

    Class attributes:
    - ``name``: registry name (e.g. ``"local-blocklist"``)
    - ``supported_types``: indicator types this provider can answer
    - ``network``: True when ``lookup`` makes network calls
    - ``default_confidence``: confidence used when the source gives none
    """

    name: str = "base"
    supported_types: tuple[str, ...] = ()
    network: bool = False
    default_confidence: int = 50

    def __init__(self) -> None:
        self._config: dict[str, Any] = {}

    def configure(self, config: dict[str, Any]) -> None:
        """Receive provider-specific settings (paths, timeouts, ...)."""
        self._config = dict(config)

    @abstractmethod
    def is_configured(self) -> bool:
        """True when this provider can actually answer lookups."""

    @abstractmethod
    def lookup(self, indicator: NormalizedIndicator) -> IntelRecord:
        """Answer one indicator. Must not raise on provider errors —
        return an ``unknown``-verdict record describing the failure."""


PROVIDERS: dict[str, type[IntelProvider]] = {}


def register_provider(cls: type[IntelProvider]) -> type[IntelProvider]:
    """Register a provider class under its ``name``."""
    if not cls.name or cls.name == "base":
        raise ValueError("provider must define a non-empty, non-'base' name")
    if cls.name in PROVIDERS:
        raise ValueError(f"intel provider {cls.name!r} is already registered")
    PROVIDERS[cls.name] = cls
    return cls


def get_provider(name: str) -> type[IntelProvider]:
    try:
        return PROVIDERS[name]
    except KeyError:
        raise KeyError(f"unknown intel provider {name!r}") from None


def provider_names() -> list[str]:
    return sorted(PROVIDERS)
