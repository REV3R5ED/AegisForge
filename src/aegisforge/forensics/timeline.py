"""Filesystem timeline (v0.4): mtime/atime/ctime claims in chronological order.

These are *filesystem* timestamp claims — what the filesystem records
about each file — not claims about file content. A copied file keeps
its content but gets new filesystem timestamps; the timeline shows the
former, never the latter.
"""

from __future__ import annotations

from aegisforge.forensics.models import FileRecord, TimelineEntry

_TIMESTAMP_KINDS = ("mtime", "atime", "ctime")


def build_timeline(files: list[FileRecord]) -> list[TimelineEntry]:
    """Build a chronological timeline of filesystem timestamp claims."""
    entries: list[TimelineEntry] = []
    for record in files:
        for kind in _TIMESTAMP_KINDS:
            stamp = getattr(record, kind)
            if stamp:
                entries.append(
                    TimelineEntry(timestamp=stamp, kind=kind, path=record.path)
                )
    # ISO-8601 UTC strings sort chronologically as plain strings.
    entries.sort(key=lambda e: (e.timestamp, e.kind, e.path))
    return entries
