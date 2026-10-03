"""Configuration command implementations."""

from __future__ import annotations

import argparse

from aegisforge.core.config import AppConfig
from aegisforge.core.results import Result


def cmd_config_show(args: argparse.Namespace, cfg: AppConfig) -> Result:
    result = Result(command="config show")
    result.data = cfg.to_dict()
    result.summary = f"profile {cfg.profile!r} from {cfg.source}"
    return result
