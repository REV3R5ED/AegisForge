"""Centralized logging: stderr diagnostics plus an audit trail.

Diagnostics go to stderr so stdout stays clean for machine-readable
output. Every CLI invocation also appends a redacted audit record to
the audit log (best effort — logging must never break the tool).
"""

from __future__ import annotations

import json
import logging
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

_LOGGER_NAME = "aegisforge"


def state_dir() -> Path:
    """Per-user state directory (override with AEGISFORGE_STATE_DIR)."""
    override = os.environ.get("AEGISFORGE_STATE_DIR")
    if override:
        return Path(override)
    return Path.home() / ".aegisforge"


def audit_log_path() -> Path:
    override = os.environ.get("AEGISFORGE_AUDIT_LOG")
    if override:
        return Path(override)
    return state_dir() / "audit.log"


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def get_logger(name: str = _LOGGER_NAME) -> logging.Logger:
    return logging.getLogger(name)


def configure_logging(verbose: bool = False) -> None:
    """Route diagnostics to stderr. Call once at CLI startup."""
    level_name = os.environ.get("AEGISFORGE_LOG_LEVEL", "")
    if verbose:
        level = logging.DEBUG
    elif level_name:
        level = getattr(logging, level_name.upper(), logging.WARNING)
    else:
        level = logging.WARNING
    logger = get_logger()
    logger.setLevel(level)
    if not logger.handlers:
        handler = logging.StreamHandler(sys.stderr)
        handler.setFormatter(
            logging.Formatter("aegisforge: %(levelname)s: %(message)s")
        )
        logger.addHandler(handler)


def audit_log(record: dict[str, Any]) -> None:
    """Append one JSON audit record. Never raises."""
    try:
        path = audit_log_path()
        path.parent.mkdir(parents=True, exist_ok=True)
        entry = {"timestamp": utc_now_iso(), **record}
        with path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry, sort_keys=True) + "\n")
    except OSError:
        # Audit logging is best effort; it must never break a run.
        pass
