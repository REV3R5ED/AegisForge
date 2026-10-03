"""Shared helpers for CLI command modules."""

from __future__ import annotations

from typing import Any

from aegisforge.cases import store as cases_store_mod
from aegisforge.cases.store import CaseError
from aegisforge.core.events import Event
from aegisforge.core.results import Result


def _case_or_fail(result: Result, case_id: str) -> Any | None:
    try:
        return cases_store_mod.load_case(case_id)
    except CaseError as exc:
        result.fail(str(exc))
        return None


def _case_event(event_type: str, case_id: str, evidence: dict[str, Any]) -> Event:
    return Event(
        event_type=event_type,
        source="aegisforge",
        evidence={"case_id": case_id, **evidence},
    )


def _hist_lines(title: str, pairs: list[list[Any]]) -> list[str]:
    lines = [f"{title}:"]
    if not pairs:
        lines.append("  (none)")
        return lines
    width = max(len(str(p[0])) for p in pairs)
    for key, count in pairs:
        lines.append(f"  {str(key):<{width}}  {count}")
    return lines
