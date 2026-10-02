"""Trial license tracking — v0.1: notice only, NO enforcement.

AegisForge is commercial software with a 7-day free trial (see LICENSE).
This module records first use and reports trial status. In v0.1 the CLI
prints a friendly notice on startup; there is deliberately NO hard
lockout — the trial keeps working past day 7 for now.

Future commercial enforcement (post-v0.1) will:
  - validate purchased keys via :func:`validate_license_key`,
  - raise :class:`LicenseExpiredError` when the trial lapses without a
    valid license, and refuse to run.

Both the exception and the validation stub exist below but are DORMANT
in v0.1: nothing in the v0.1 code path calls them.
"""

from __future__ import annotations

import json
import os
import sys
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import TextIO

from aegisforge.core.logging import state_dir

TRIAL_DAYS = 7
TRIAL_FILE = "trial.json"
LICENSE_FILE = "license.key"
BYPASS_ENV = "AEGISFORGE_NO_TRIAL_CHECK"
_BYPASS_MESSAGE = "trial check bypassed"


class LicenseExpiredError(Exception):
    """Raised when the trial has lapsed without a commercial license.

    DORMANT in v0.1 — reserved for future commercial enforcement.
    """


@dataclass
class TrialStatus:
    days_remaining: int
    licensed: bool
    expired: bool
    first_run: str | None
    message: str


def _read_trial(directory: Path) -> dict[str, object]:
    try:
        data = json.loads((directory / TRIAL_FILE).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return data if isinstance(data, dict) else {}


def _write_trial(directory: Path, first_run: str) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    (directory / TRIAL_FILE).write_text(
        json.dumps({"first_run": first_run, "version": "0.1.0"}), encoding="utf-8"
    )


def _parse_iso(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _has_license_key(directory: Path) -> bool:
    try:
        return bool((directory / LICENSE_FILE).read_text(encoding="utf-8").strip())
    except OSError:
        return False


def trial_status(
    directory: Path | None = None,
    now: datetime | None = None,
) -> TrialStatus:
    """Return the current trial status. Records first use on first call.

    Never raises for corrupt state — a broken trial file restarts the
    trial rather than breaking the tool.
    """
    if os.environ.get(BYPASS_ENV) == "1":
        return TrialStatus(TRIAL_DAYS, False, False, None, _BYPASS_MESSAGE)
    directory = directory or state_dir()
    now = now or datetime.now(timezone.utc)

    if _has_license_key(directory):
        # v0.1: presence of a key file counts as licensed. Post-v0.1 this
        # will go through validate_license_key().
        return TrialStatus(TRIAL_DAYS, True, False, None, "commercial license active")

    record = _read_trial(directory)
    first_run_raw = record.get("first_run")
    first_run: datetime | None = None
    if isinstance(first_run_raw, str):
        try:
            first_run = _parse_iso(first_run_raw)
        except ValueError:
            first_run = None

    if first_run is None:
        stamped = now.isoformat().replace("+00:00", "Z")
        _write_trial(directory, stamped)
        return TrialStatus(
            TRIAL_DAYS, False, False, stamped, "free trial started: 7 days remaining"
        )

    elapsed = now - first_run
    if elapsed >= timedelta(days=TRIAL_DAYS):
        return TrialStatus(
            0,
            False,
            True,
            first_run_raw if isinstance(first_run_raw, str) else None,
            "free trial ended — a commercial license will be required for "
            "continued use; contact the author to purchase",
        )
    remaining = TRIAL_DAYS - elapsed.days
    return TrialStatus(
        remaining,
        False,
        False,
        first_run_raw if isinstance(first_run_raw, str) else None,
        f"{remaining} day(s) of free trial remaining",
    )


def print_trial_notice(status: TrialStatus, stream: TextIO | None = None) -> None:
    """Print a friendly trial notice to stderr. Best effort, never raises."""
    try:
        out = stream or sys.stderr
        if status.licensed or status.message == _BYPASS_MESSAGE:
            return
        if status.expired:
            out.write(
                "Trial: free trial has ended — please purchase a commercial "
                "license for continued use (see LICENSE).\n"
            )
        else:
            out.write(
                f"Trial: {status.days_remaining} day(s) of free trial remaining.\n"
            )
        out.flush()
    except OSError:
        pass


def validate_license_key(key: str) -> bool:
    """Validate a purchased commercial license key.

    DORMANT STUB — not called anywhere in v0.1. Real key validation
    (signature check against the author's public key) ships with
    commercial enforcement after v0.1.
    """
    raise NotImplementedError("commercial license-key validation is not active in v0.1")
