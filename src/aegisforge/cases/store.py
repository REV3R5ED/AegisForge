"""Case storage: directory layout, ID sequencing, atomic JSON persistence.

Layout::

    <state_dir>/cases/
        _counter.json                 # {"next": 3} — persisted case counter
        CASE-2026-001/
            case.json                 # CaseMetadata
            evidence/network/
            evidence/logs/
            evidence/files/
            timeline/
            findings/
            report/

Case IDs look like ``CASE-2026-001``: the creation year plus a
zero-padded global sequence. The sequence never resets, so IDs are
unique even across year boundaries.
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from aegisforge.cases.models import CASE_STATUSES, CaseMetadata
from aegisforge.core.logging import state_dir

COUNTER_FILE = "_counter.json"
CASE_FILE = "case.json"


class CaseError(ValueError):
    """A case operation failed (bad ID, missing case, invalid state)."""


def cases_root() -> Path:
    """Root directory holding all cases (override via AEGISFORGE_STATE_DIR)."""
    root = state_dir() / "cases"
    root.mkdir(parents=True, exist_ok=True)
    return root


def case_dir(case_id: str) -> Path:
    return cases_root() / case_id


def _read_counter() -> int:
    path = cases_root() / COUNTER_FILE
    if not path.exists():
        return 1
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return int(data.get("next", 1))
    except (ValueError, OSError, TypeError):
        return 1


def _write_counter(next_value: int) -> None:
    path = cases_root() / COUNTER_FILE
    _atomic_write_json(path, {"next": next_value})


def _atomic_write_json(path: Path, data: dict[str, Any]) -> None:
    """Write JSON atomically: temp file + rename, never a partial file."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    os.replace(tmp, path)


def next_case_id(now: datetime | None = None) -> str:
    """Allocate the next case ID (advances the persisted counter)."""
    seq = _read_counter()
    _write_counter(seq + 1)
    moment = now or datetime.now(timezone.utc)
    return f"CASE-{moment:%Y}-{seq:03d}"


def create_case(title: str, note: str | None = None) -> CaseMetadata:
    """Create a case directory and its metadata file."""
    title = title.strip()
    if not title:
        raise CaseError("case title must not be empty")
    case_id = next_case_id()
    root = case_dir(case_id)
    subdirs = (
        "evidence/network",
        "evidence/logs",
        "evidence/files",
        "timeline",
        "findings",
        "report",
    )
    for sub in subdirs:
        (root / sub).mkdir(parents=True, exist_ok=True)
    case = CaseMetadata(case_id=case_id, title=title)
    if note:
        from aegisforge.cases.findings import add_note  # deferred: avoids cycle

        add_note(case, note)
    save_case(case)
    return case


def load_case(case_id: str) -> CaseMetadata:
    """Load a case's metadata; raises CaseError when it does not exist."""
    path = case_dir(case_id) / CASE_FILE
    if not path.exists():
        raise CaseError(f"unknown case {case_id!r} (no {CASE_FILE} found)")
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (ValueError, OSError) as exc:
        raise CaseError(f"cannot read case {case_id!r}: {exc}") from exc
    return CaseMetadata.from_dict(data)


def save_case(case: CaseMetadata) -> None:
    """Persist a case's metadata atomically."""
    if case.status not in CASE_STATUSES:
        raise CaseError(f"invalid case status {case.status!r}")
    _atomic_write_json(case_dir(case.case_id) / CASE_FILE, case.to_dict())


def list_cases() -> list[CaseMetadata]:
    """All cases, oldest first."""
    cases: list[CaseMetadata] = []
    for child in sorted(cases_root().iterdir()):
        if child.is_dir() and (child / CASE_FILE).exists():
            try:
                cases.append(load_case(child.name))
            except CaseError:
                continue  # a broken case dir never blocks the listing
    return cases
