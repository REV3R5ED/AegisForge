"""Module/plugin registration for future AegisForge phases.

v0.1 ships the network module registered here. Later phases
(domain, forensic, logs, pcap, intel, correlation, cases, reporting)
register themselves the same way — either by calling
:func:`register` at import time or via ``importlib.metadata`` entry
points under the ``aegisforge.modules`` group.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from dataclasses import dataclass, field
from importlib import metadata
from typing import Any

log = logging.getLogger("aegisforge")

ENTRY_POINT_GROUP = "aegisforge.modules"


@dataclass
class ModuleInfo:
    name: str
    description: str
    version: str = "0.1.0"
    commands: list[str] = field(default_factory=list)
    factory: Callable[[], Any] | None = None


class ModuleRegistry:
    """Registry of AegisForge capability modules."""

    def __init__(self) -> None:
        self._modules: dict[str, ModuleInfo] = {}

    def register(self, info: ModuleInfo) -> None:
        if info.name in self._modules:
            raise ValueError(f"module {info.name!r} is already registered")
        self._modules[info.name] = info

    def get(self, name: str) -> ModuleInfo:
        try:
            return self._modules[name]
        except KeyError:
            raise KeyError(f"unknown module {name!r}") from None

    def names(self) -> list[str]:
        return sorted(self._modules)

    def discover_entry_points(self) -> None:
        """Load third-party modules advertised via entry points (best effort)."""
        try:
            entry_points = metadata.entry_points(group=ENTRY_POINT_GROUP)
        except Exception as exc:  # pragma: no cover - defensive
            log.debug("entry point discovery failed: %s", exc)
            return
        for ep in entry_points:
            try:
                factory = ep.load()
                info = factory() if callable(factory) else factory
                if isinstance(info, ModuleInfo):
                    self.register(info)
            except Exception as exc:
                log.warning("skipping broken module entry point %r: %s", ep.name, exc)


_registry = ModuleRegistry()


def register(info: ModuleInfo) -> None:
    _registry.register(info)


def get_registry() -> ModuleRegistry:
    return _registry
