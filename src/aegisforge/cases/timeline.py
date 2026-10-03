"""Unified case timeline: merge every evidence source into one stream.

Sources merged, in chronological order with per-event source labels:

- ``logs`` evidence: parsed with the logs/ format auto-detection and
  streaming parsers; each log event becomes a timeline entry.
- ``files`` evidence: filesystem mtime claims from the forensics/
  inventory of the attached copy.
- ``network`` evidence: if the attached file is an AegisForge JSON
  result envelope, its ``events`` are merged; otherwise a single
  entry records the attachment itself.

Events without a parseable timestamp are listed in a separate
``untimed`` section — never dropped silently.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from aegisforge.cases.models import CaseMetadata, TimelineEntry
from aegisforge.cases.store import case_dir
from aegisforge.core.logging import utc_now_iso
from aegisforge.forensics import inventory as inventory_mod
from aegisforge.logs import detect as detect_mod
from aegisforge.logs.models import PARSER_UNKNOWN, LogEvent
from aegisforge.logs.parsers import get_parser, iter_parsed_file


def _log_entries(record: Any, stored: Path) -> list[TimelineEntry]:
    """Timeline entries from a logs-kind evidence file."""
    entries: list[TimelineEntry] = []
    try:
        detection = detect_mod.detect_file(str(stored))
    except OSError:
        return entries
    if detection.parser == PARSER_UNKNOWN:
        return entries
    parser = get_parser(detection.parser)
    label = f"logs:{stored.name}"
    try:
        for item in iter_parsed_file(str(stored), parser):
            if not isinstance(item, LogEvent):
                continue  # parse warnings are reported, not timeline entries
            entries.append(
                TimelineEntry(
                    timestamp=item.timestamp,
                    source=label,
                    kind="log-event",
                    summary=item.message[:160],
                    detail=f"severity={item.severity}"
                    + (f" host={item.host}" if item.host else "")
                    + f" line={item.line_number}",
                )
            )
    except OSError:
        pass  # an unreadable evidence copy yields no entries, never a crash
    return entries


def _file_entries(record: Any, stored: Path) -> list[TimelineEntry]:
    """Timeline entries from a files-kind evidence file (mtime claims)."""
    entries: list[TimelineEntry] = []
    try:
        inv = inventory_mod.run_inventory(str(stored), hash_algorithms=())
    except (ValueError, OSError):
        return entries
    for f in inv.files:
        if f.mtime:
            entries.append(
                TimelineEntry(
                    timestamp=f.mtime,
                    source=f"files:{stored.name}",
                    kind="file-mtime",
                    summary=f"mtime of {f.path}",
                    detail="filesystem timestamp claim — filesystem metadata, "
                    "not a content claim",
                )
            )
    return entries


def _network_entries(record: Any, stored: Path) -> list[TimelineEntry]:
    """Timeline entries from network-kind evidence.

    AegisForge JSON result envelopes contribute their ``events``;
    anything else contributes one entry for the attachment itself.
    """
    entries: list[TimelineEntry] = []
    label = f"network:{stored.name}"
    try:
        data = json.loads(stored.read_text(encoding="utf-8"))
    except (ValueError, OSError):
        data = None
    if isinstance(data, dict) and isinstance(data.get("events"), list):
        for ev in data["events"]:
            if not isinstance(ev, dict):
                continue
            entries.append(
                TimelineEntry(
                    timestamp=ev.get("timestamp"),
                    source=label,
                    kind="network-event",
                    summary=str(ev.get("event_type", "event")),
                    detail=json.dumps(
                        {
                            k: v
                            for k, v in ev.items()
                            if k in ("host", "src_ip", "dst_ip", "severity")
                        },
                        default=str,
                    ),
                )
            )
        return entries
    # Not a result envelope: record the attachment itself via its mtime.
    try:
        mtime = stored.stat().st_mtime
    except OSError:
        return entries
    from datetime import datetime, timezone

    entries.append(
        TimelineEntry(
            timestamp=datetime.fromtimestamp(mtime, tz=timezone.utc).strftime(
                "%Y-%m-%dT%H:%M:%SZ"
            ),
            source=label,
            kind="evidence-attached",
            summary=f"evidence attached: {stored.name}",
            detail=f"original path: {record.original_path}",
        )
    )
    return entries


def build_case_timeline(
    case: CaseMetadata,
) -> tuple[list[TimelineEntry], list[TimelineEntry]]:
    """Merge all evidence into timed and untimed timeline entries.

    Returns ``(timed, untimed)``: timed entries are chronological,
    untimed entries carry ``timestamp=None`` and are listed separately.
    """
    base = case_dir(case.case_id)
    timed: list[TimelineEntry] = []
    untimed: list[TimelineEntry] = []
    for record in case.evidence:
        stored = base / record.stored_path
        if record.kind == "logs":
            entries = _log_entries(record, stored)
        elif record.kind == "files":
            entries = _file_entries(record, stored)
        elif record.kind == "network":
            entries = _network_entries(record, stored)
        else:  # pragma: no cover - kinds are validated at attach time
            continue
        for entry in entries:
            (timed if entry.timestamp else untimed).append(entry)
    # UTC ISO-8601 strings sort chronologically as plain strings.
    timed.sort(key=lambda e: (e.timestamp or "", e.source, e.kind, e.summary))
    return timed, untimed


def timeline_to_dict(
    timed: list[TimelineEntry], untimed: list[TimelineEntry]
) -> dict[str, Any]:
    return {
        "timed": [e.to_dict() for e in timed],
        "untimed": [e.to_dict() for e in untimed],
        "timed_count": len(timed),
        "untimed_count": len(untimed),
        "note": "Filesystem timestamps are filesystem metadata claims, not "
        "content claims. Untimed events could not be placed chronologically "
        "and are listed separately, never dropped.",
        "generated": utc_now_iso(),
    }
