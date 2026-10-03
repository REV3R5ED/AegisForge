"""Case finding tracking, indicator linking, analyst notes, status changes.

These functions mutate a :class:`CaseMetadata` in memory; the caller
persists it with :func:`aegisforge.cases.store.save_case`.
"""

from __future__ import annotations

from aegisforge.cases import indicators as indicators_mod
from aegisforge.cases.models import (
    CASE_STATUSES,
    FINDING_STATUSES,
    FINDING_TRANSITIONS,
    AnalystNote,
    CaseFinding,
    CaseMetadata,
    IndicatorLink,
)
from aegisforge.cases.store import CaseError
from aegisforge.core.findings import SEVERITIES


def add_note(case: CaseMetadata, text: str, author: str = "analyst") -> AnalystNote:
    """Append an analyst note (append-only; notes are never edited)."""
    text = text.strip()
    if not text:
        raise CaseError("note text must not be empty")
    note = AnalystNote(text=text, author=author)
    case.notes.append(note)
    return note


def add_case_finding(
    case: CaseMetadata,
    title: str,
    severity: str,
    confidence: int,
    detail: str = "",
) -> CaseFinding:
    """Record a finding in the case; returns it with its ``Fnn`` ID."""
    title = title.strip()
    if not title:
        raise CaseError("finding title must not be empty")
    severity = severity.strip().lower()
    if severity not in SEVERITIES:
        raise CaseError(
            f"severity must be one of {', '.join(SEVERITIES)}, got {severity!r}"
        )
    if not 0 <= confidence <= 100:
        raise CaseError(f"confidence must be 0-100, got {confidence!r}")
    case.finding_seq += 1
    finding = CaseFinding(
        finding_id=f"{case.case_id}-F{case.finding_seq:02d}",
        title=title,
        severity=severity,
        confidence=confidence,
        detail=detail.strip(),
    )
    case.findings.append(finding)
    return finding


def set_finding_status(case: CaseMetadata, finding_id: str, status: str) -> CaseFinding:
    """Move a finding through its lifecycle; invalid moves raise CaseError."""
    status = status.strip().lower()
    if status not in FINDING_STATUSES:
        raise CaseError(
            f"finding status must be one of {', '.join(FINDING_STATUSES)}, "
            f"got {status!r}"
        )
    finding = case.get_finding(finding_id)
    if finding is None:
        raise CaseError(f"unknown finding {finding_id!r} in case {case.case_id}")
    allowed = FINDING_TRANSITIONS[finding.status]
    if status != finding.status and status not in allowed:
        raise CaseError(
            f"cannot move finding {finding_id} from {finding.status!r} "
            f"to {status!r} (allowed: {', '.join(allowed)})"
        )
    finding.status = status
    return finding


def link_indicator(
    case: CaseMetadata,
    finding_id: str,
    value: str,
    type_override: str | None = None,
) -> IndicatorLink:
    """Link an indicator string to a finding.

    The indicator type is guessed from the value's shape unless the
    analyst passes ``--type``; the record always says which happened.
    """
    value = value.strip()
    if not value:
        raise CaseError("indicator value must not be empty")
    finding = case.get_finding(finding_id)
    if finding is None:
        raise CaseError(f"unknown finding {finding_id!r} in case {case.case_id}")
    if type_override is not None:
        ind_type = indicators_mod.check_indicator_type(type_override)
        source = "specified"
    else:
        ind_type = indicators_mod.guess_indicator_type(value)
        source = "guessed"
    link = IndicatorLink(value=value, type=ind_type, type_source=source)
    finding.indicators.append(link)
    return link


def set_case_status(
    case: CaseMetadata, status: str, note: str | None = None
) -> CaseMetadata:
    """Change a case's status. Closing requires a closing note."""
    status = status.strip().lower()
    if status not in CASE_STATUSES:
        raise CaseError(
            f"case status must be one of {', '.join(CASE_STATUSES)}, got {status!r}"
        )
    if status == "closed" and not (note and note.strip()):
        raise CaseError(
            "closing a case requires a closing note "
            "(pass --note with the resolution summary)"
        )
    case.status = status
    if note and note.strip():
        add_note(case, note.strip())
    return case
