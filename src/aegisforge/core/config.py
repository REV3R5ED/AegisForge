"""JSON configuration with named profiles.

Configuration resolution order (later wins):
  1. built-in defaults
  2. JSON config file (``--config PATH`` or ``~/.aegisforge/config.json``)
  3. selected profile (``--profile NAME`` picks ``profiles.NAME``)
  4. explicit CLI flags

JSON is used instead of TOML so configuration works identically on
Python 3.10 through 3.13 (stdlib ``tomllib`` is 3.11+).
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


class ConfigError(Exception):
    """Raised when a configuration file is invalid."""


DEFAULTS: dict[str, Any] = {
    "ping_count": 3,
    "ping_timeout": 2.0,
    "max_parallel": 20,
    "dns_timeout": 5.0,
    "trace_max_hops": 30,
    "trace_timeout": 2.0,
    "subnet_max_hosts": 1024,
    "scan_max_targets": 256,
}

_PROFILE_DEFAULT = "default"


def default_config_path() -> Path:
    override = os.environ.get("AEGISFORGE_CONFIG")
    if override:
        return Path(override)
    return Path.home() / ".aegisforge" / "config.json"


def _checked_profile(raw: Any, where: str) -> dict[str, Any]:
    if not isinstance(raw, dict):
        raise ConfigError(f"{where}: profile must be a JSON object")
    unknown = sorted(set(raw) - set(DEFAULTS))
    if unknown:
        raise ConfigError(
            f"{where}: unknown setting(s) {', '.join(unknown)}; "
            f"expected only {', '.join(sorted(DEFAULTS))}"
        )
    return dict(raw)


@dataclass
class AppConfig:
    """Effective configuration for one invocation."""

    values: dict[str, Any] = field(default_factory=lambda: dict(DEFAULTS))
    profile: str = _PROFILE_DEFAULT
    source: str = "defaults"

    def get(self, key: str) -> Any:
        return self.values[key]

    def __getitem__(self, key: str) -> Any:
        return self.values[key]

    def to_dict(self) -> dict[str, Any]:
        return {"profile": self.profile, "source": self.source, **self.values}


def load_config(
    path: str | Path | None = None,
    profile: str = _PROFILE_DEFAULT,
    overrides: dict[str, Any] | None = None,
) -> AppConfig:
    """Load configuration, applying the resolution order documented above."""
    values: dict[str, Any] = dict(DEFAULTS)
    source = "defaults"
    cfg_path = Path(path) if path else default_config_path()

    if cfg_path.exists():
        try:
            raw = json.loads(cfg_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ConfigError(f"cannot read config file {cfg_path}: {exc}") from exc
        if not isinstance(raw, dict):
            raise ConfigError(f"config file {cfg_path} must contain a JSON object")
        if "profiles" not in raw:
            # A top-level object without "profiles" is the default profile.
            values.update(_checked_profile(raw, str(cfg_path)))
        else:
            profiles = raw["profiles"]
            if not isinstance(profiles, dict):
                raise ConfigError(
                    f"config file {cfg_path}: 'profiles' must be an object"
                )
            if profile not in profiles:
                available = sorted(profiles) or ["(none defined)"]
                raise ConfigError(
                    f"config file {cfg_path}: profile {profile!r} is not defined; "
                    f"available: {', '.join(available)}"
                )
            values.update(
                _checked_profile(profiles[profile], f"{cfg_path}: profile {profile!r}")
            )
        source = str(cfg_path)

    if overrides:
        unknown = sorted(set(overrides) - set(DEFAULTS))
        if unknown:
            raise ConfigError(f"unknown setting(s) {', '.join(unknown)}")
        values.update(overrides)

    return AppConfig(values=values, profile=profile, source=source)


def example_config() -> str:
    return json.dumps(
        {
            "profiles": {
                "default": dict(DEFAULTS),
                "quick": {**DEFAULTS, "ping_count": 1, "ping_timeout": 1.0},
            }
        },
        indent=2,
    )
