"""Duplicate detection (v0.4): group files by SHA-256 digest.

Duplicates are an *observed* fact — two paths with identical bytes.
Whether that is expected (vendored copies) or suspicious is for the
analyst, not this module.
"""

from __future__ import annotations

from aegisforge.forensics.models import DuplicateGroup, FileRecord


def find_duplicates(files: list[FileRecord]) -> list[DuplicateGroup]:
    """Group files sharing a SHA-256 digest. Only groups of 2+ are returned."""
    by_digest: dict[str, list[str]] = {}
    for record in files:
        digest = record.hashes.get("sha256")
        if not digest:
            continue
        by_digest.setdefault(digest, []).append(record.path)
    groups = [
        DuplicateGroup(sha256=digest, paths=sorted(paths))
        for digest, paths in by_digest.items()
        if len(paths) > 1
    ]
    groups.sort(key=lambda g: (-g.count, g.sha256))
    return groups
