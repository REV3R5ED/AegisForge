"""Shared models for the forensics module (v0.4).

Every timestamp is UTC ISO-8601. File timestamps (mtime/atime/ctime) are
*filesystem* metadata — the filesystem's claims, not content claims.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

from aegisforge.core.logging import utc_now_iso

TYPE_SOURCE_MAGIC = "magic"
TYPE_SOURCE_EXTENSION = "extension"
TYPE_SOURCE_UNKNOWN = "unknown"


@dataclass
class FileRecord:
    """One inventoried file. ``path`` is relative to the scanned root."""

    path: str
    size: int
    mtime: str | None = None
    atime: str | None = None
    ctime: str | None = None
    hashes: dict[str, str] = field(default_factory=dict)
    file_type: str = "unknown"
    type_source: str = TYPE_SOURCE_UNKNOWN
    extension_mismatch: bool = False
    is_symlink: bool = False
    symlink_target: str | None = None
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class InventoryWarning:
    """A non-fatal problem: the path was skipped, never crashed on."""

    path: str
    reason: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class InventoryStats:
    files: int = 0
    directories: int = 0
    symlinks: int = 0
    skipped: int = 0
    total_bytes: int = 0
    warnings: int = 0

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class InventoryResult:
    """Outcome of a recursive inventory walk."""

    root: str
    files: list[FileRecord] = field(default_factory=list)
    warnings: list[InventoryWarning] = field(default_factory=list)
    stats: InventoryStats = field(default_factory=InventoryStats)
    started: str = field(default_factory=utc_now_iso)
    finished: str = field(default_factory=utc_now_iso)

    def to_dict(self) -> dict[str, Any]:
        return {
            "root": self.root,
            "started": self.started,
            "finished": self.finished,
            "stats": self.stats.to_dict(),
            "files": [f.to_dict() for f in self.files],
            "warnings": [w.to_dict() for w in self.warnings],
        }


@dataclass
class VerifyChange:
    """One file whose current state differs from the manifest."""

    path: str
    detail: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class VerifyResult:
    """Outcome of verifying a live tree against a manifest."""

    manifest_path: str
    root: str
    manifest_sha256: str
    verified: int = 0
    changed: list[VerifyChange] = field(default_factory=list)
    missing: list[VerifyChange] = field(default_factory=list)
    new: list[VerifyChange] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not (self.changed or self.missing or self.new)

    def to_dict(self) -> dict[str, Any]:
        return {
            "manifest_path": self.manifest_path,
            "root": self.root,
            "manifest_sha256": self.manifest_sha256,
            "verified": self.verified,
            "ok": self.ok,
            "changed": [c.to_dict() for c in self.changed],
            "missing": [c.to_dict() for c in self.missing],
            "new": [c.to_dict() for c in self.new],
        }


@dataclass
class DuplicateGroup:
    """Files sharing one SHA-256 digest."""

    sha256: str
    paths: list[str] = field(default_factory=list)

    @property
    def count(self) -> int:
        return len(self.paths)

    def to_dict(self) -> dict[str, Any]:
        return {"sha256": self.sha256, "count": self.count, "paths": self.paths}


@dataclass
class TimelineEntry:
    """One filesystem timestamp claim, sorted chronologically by the caller."""

    timestamp: str
    kind: str  # mtime | atime | ctime
    path: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
