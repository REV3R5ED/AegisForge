"""Recursive evidence inventory (v0.4): walk, identify, hash.

The walk is read-only and streaming: entries are yielded one at a time
and files are hashed with chunked reads, so inventories of large trees
stay memory-bounded. Unreadable files and directories become warnings,
never crashes. Directory symlinks are never followed.
"""

from __future__ import annotations

import fnmatch
import logging
import os
from collections.abc import Iterator
from datetime import datetime, timezone
from pathlib import Path

from aegisforge.core.logging import utc_now_iso
from aegisforge.forensics import hashing, identify
from aegisforge.forensics.models import (
    FileRecord,
    InventoryResult,
    InventoryStats,
    InventoryWarning,
)

log = logging.getLogger("aegisforge")


def _utc_iso(epoch: float) -> str:
    return (
        datetime.fromtimestamp(epoch, tz=timezone.utc)
        .isoformat()
        .replace("+00:00", "Z")
    )


def _matches_any(patterns: tuple[str, ...], rel_posix: str, name: str) -> bool:
    return any(
        fnmatch.fnmatch(rel_posix, pat) or fnmatch.fnmatch(name, pat)
        for pat in patterns
    )


def _stat_record(path: Path, rel: str) -> FileRecord:
    """Build a FileRecord for a regular file (stat + identify; hashing later)."""
    try:
        st = path.stat()
    except OSError as exc:
        return FileRecord(path=rel, size=0, error=f"stat failed: {exc}")
    record = FileRecord(
        path=rel,
        size=st.st_size,
        mtime=_utc_iso(st.st_mtime),
        atime=_utc_iso(st.st_atime),
        ctime=_utc_iso(st.st_ctime),
    )
    file_type, source, mismatch = identify.identify(str(path))
    record.file_type = file_type
    record.type_source = source
    record.extension_mismatch = mismatch
    return record


def _iter_file(
    root_path: Path,
    fpath: Path,
    rel: str,
    name: str,
    include: tuple[str, ...],
    exclude: tuple[str, ...],
    hash_algorithms: tuple[str, ...],
    stats: InventoryStats | None,
) -> Iterator[FileRecord | InventoryWarning]:
    """Inventory one directory entry (may raise OSError; caller converts)."""
    if include and not _matches_any(include, rel, name):
        return
    if exclude and _matches_any(exclude, rel, name):
        return
    if fpath.is_symlink():
        try:
            target = os.readlink(fpath)
        except OSError as exc:
            yield InventoryWarning(path=rel, reason=f"cannot read symlink: {exc}")
            return
        if stats is not None:
            stats.files += 1
            stats.symlinks += 1
        yield FileRecord(
            path=rel,
            size=0,
            file_type="symlink",
            type_source="filesystem",
            is_symlink=True,
            symlink_target=target,
        )
        return
    record = _stat_record(fpath, rel)
    if record.error is not None:
        yield InventoryWarning(path=rel, reason=record.error)
        return
    _hash_record(record, fpath, hash_algorithms)
    if record.error is not None:
        yield InventoryWarning(path=rel, reason=record.error)
        return
    if stats is not None:
        stats.files += 1
        stats.total_bytes += record.size
    yield record


def _hash_record(
    record: FileRecord, fpath: Path, hash_algorithms: tuple[str, ...]
) -> None:
    if not hash_algorithms:
        return  # path-only walk (e.g. new-file detection during verify)
    try:
        record.hashes = hashing.hash_file(str(fpath), hash_algorithms)
    except OSError as exc:
        record.error = f"hash failed: {exc}"
    except ValueError as exc:
        record.error = str(exc)


def iter_inventory(
    root: str | os.PathLike[str],
    include: tuple[str, ...] = (),
    exclude: tuple[str, ...] = (),
    hash_algorithms: tuple[str, ...] = hashing.DEFAULT_ALGORITHMS,
    stats: InventoryStats | None = None,
) -> Iterator[FileRecord | InventoryWarning]:
    """Yield FileRecords and InventoryWarnings for *root* (depth-first).

    ``include``/``exclude`` are glob patterns matched against the path
    relative to *root* (POSIX separators) and against the bare file
    name. When ``include`` is non-empty a file must match at least one
    pattern; ``exclude`` always wins. When *stats* is given it is
    updated as the walk proceeds.
    """
    root_path = Path(root)
    try:
        root_path = root_path.resolve()
    except OSError as exc:
        yield InventoryWarning(path=str(root), reason=f"cannot resolve root: {exc}")
        return
    if not root_path.exists():
        yield InventoryWarning(path=str(root), reason="root does not exist")
        return

    # A lone file (not a directory) is inventoried as a single entry.
    if root_path.is_file() and not root_path.is_symlink():
        record = _stat_record(root_path, root_path.name)
        if record.error is not None:
            yield InventoryWarning(path=record.path, reason=record.error)
            return
        _hash_record(record, root_path, hash_algorithms)
        if record.error is not None:
            yield InventoryWarning(path=record.path, reason=record.error)
            return
        if stats is not None:
            stats.files += 1
            stats.total_bytes += record.size
        yield record
        return

    if not root_path.is_dir():
        yield InventoryWarning(
            path=str(root), reason="root is not a directory or regular file"
        )
        return

    for dirpath, dirnames, filenames in os.walk(root_path, followlinks=False):
        dirnames.sort()
        filenames.sort()
        if stats is not None:
            stats.directories += 1
        current = Path(dirpath)
        # Never descend into symlinked directories.
        dirnames[:] = [d for d in dirnames if not (current / d).is_symlink()]
        for name in filenames:
            fpath = current / name
            rel = fpath.relative_to(root_path).as_posix()
            try:
                yield from _iter_file(
                    root_path,
                    fpath,
                    rel,
                    name,
                    include,
                    exclude,
                    hash_algorithms,
                    stats,
                )
            except OSError as exc:
                # is_symlink()/stat can raise on unreadable entries —
                # warn and keep walking.
                yield InventoryWarning(path=rel, reason=f"unreadable: {exc}")


def run_inventory(
    root: str | os.PathLike[str],
    include: tuple[str, ...] = (),
    exclude: tuple[str, ...] = (),
    hash_algorithms: tuple[str, ...] = hashing.DEFAULT_ALGORITHMS,
) -> InventoryResult:
    """Walk *root* and return a complete InventoryResult."""
    result = InventoryResult(root=str(root))
    stats = InventoryStats()
    for entry in iter_inventory(
        root,
        include=include,
        exclude=exclude,
        hash_algorithms=hash_algorithms,
        stats=stats,
    ):
        if isinstance(entry, InventoryWarning):
            result.warnings.append(entry)
            stats.warnings += 1
            stats.skipped += 1
            continue
        result.files.append(entry)
    result.stats = stats
    result.finished = utc_now_iso()
    return result
