"""Digital forensics command implementations."""

from __future__ import annotations

import argparse
import os

from aegisforge.core.config import AppConfig
from aegisforge.core.events import Event
from aegisforge.core.logging import audit_log
from aegisforge.core.results import EXIT_OK, Result
from aegisforge.forensics import duplicates as forensics_duplicates_mod
from aegisforge.forensics import hashing as forensics_hashing_mod
from aegisforge.forensics import inventory as forensics_inventory_mod
from aegisforge.forensics import manifest as forensics_manifest_mod
from aegisforge.forensics import timeline as forensics_timeline_mod
from aegisforge.network.validation import ValidationError


def _forensics_algorithms(args: argparse.Namespace) -> tuple[str, ...]:
    chosen = tuple(args.algorithms) if args.algorithms else ("sha256",)
    unknown = [a for a in chosen if a not in forensics_hashing_mod.SUPPORTED_ALGORITHMS]
    if unknown:
        raise ValidationError(f"unsupported hash algorithm(s): {', '.join(unknown)}")
    # Preserve order, drop duplicates.
    return tuple(dict.fromkeys(chosen))


def _check_root(path: str) -> str | None:
    """Return an error message when *path* cannot be scanned, else None."""
    if not os.path.exists(path):
        return f"path does not exist: {path}"
    if not os.access(path, os.R_OK):
        return f"path is not readable: {path}"
    return None


def cmd_forensics_inventory(args: argparse.Namespace, cfg: AppConfig) -> Result:
    result = Result(command="forensics inventory", target=args.path)
    problem = _check_root(args.path)
    if problem is not None:
        result.fail(problem)
        return result
    try:
        algos = _forensics_algorithms(args)
        inv = forensics_inventory_mod.run_inventory(
            args.path,
            include=tuple(args.include or ()),
            exclude=tuple(args.exclude or ()),
            hash_algorithms=algos,
        )
    except (ValidationError, ValueError, OSError) as exc:
        result.fail(str(exc))
        return result
    data = inv.to_dict()
    result.data = data
    stats = inv.stats
    result.summary = (
        f"{args.path}: {stats.files} file(s), {stats.total_bytes} byte(s), "
        f"{stats.warnings} warning(s)"
    )
    result.add_event(
        Event(
            event_type="forensics.inventory.completed",
            source="aegisforge",
            evidence={
                "root": args.path,
                "files": stats.files,
                "total_bytes": stats.total_bytes,
                "warnings": stats.warnings,
                "algorithms": list(algos),
            },
        )
    )
    return result


def cmd_forensics_manifest(args: argparse.Namespace, cfg: AppConfig) -> Result:
    result = Result(command="forensics manifest", target=args.path)
    problem = _check_root(args.path)
    if problem is not None:
        result.fail(problem)
        return result
    try:
        algos = _forensics_algorithms(args)
        inv = forensics_inventory_mod.run_inventory(
            args.path,
            include=tuple(args.include or ()),
            exclude=tuple(args.exclude or ()),
            hash_algorithms=algos,
        )
        manifest = forensics_manifest_mod.build_manifest(inv, operator_note=args.note)
        out_path = forensics_manifest_mod.write_manifest(manifest, args.output)
    except (ValidationError, ValueError, OSError) as exc:
        result.fail(str(exc))
        return result
    sha = manifest["manifest_sha256"]
    # Tamper-evidence seam: the manifest digest goes to the audit log.
    audit_log(
        {
            "command": "forensics manifest",
            "target": args.path,
            "manifest": out_path,
            "manifest_sha256": sha,
            "file_count": manifest["file_count"],
            "exit_code": EXIT_OK,
        }
    )
    result.data = {
        "manifest_path": out_path,
        "manifest_sha256": sha,
        "file_count": manifest["file_count"],
        "total_bytes": manifest["total_bytes"],
        "created": manifest["created"],
        "root": manifest["root"],
    }
    result.summary = (
        f"manifest written to {out_path}: {manifest['file_count']} file(s), "
        f"sha256 {sha[:16]}…"
    )
    result.add_event(
        Event(
            event_type="forensics.manifest.created",
            source="aegisforge",
            evidence={
                "root": args.path,
                "manifest": out_path,
                "manifest_sha256": sha,
                "file_count": manifest["file_count"],
            },
        )
    )
    return result


def cmd_forensics_verify(args: argparse.Namespace, cfg: AppConfig) -> Result:
    result = Result(command="forensics verify", target=args.manifest)
    try:
        manifest = forensics_manifest_mod.read_manifest(args.manifest)
    except ValueError as exc:
        result.fail(str(exc))
        return result
    try:
        vr = forensics_manifest_mod.verify_manifest(manifest, root=args.root)
    except (ValueError, OSError) as exc:
        result.fail(str(exc))
        return result
    for finding in forensics_manifest_mod.verify_findings(vr):
        result.add_finding(finding)
    result.data = vr.to_dict()
    result.summary = (
        f"{args.manifest}: {vr.verified} verified, {len(vr.changed)} changed, "
        f"{len(vr.missing)} missing, {len(vr.new)} new"
    )
    result.add_event(
        Event(
            event_type="forensics.verify.completed",
            source="aegisforge",
            evidence={
                "manifest": args.manifest,
                "root": vr.root,
                "verified": vr.verified,
                "changed": len(vr.changed),
                "missing": len(vr.missing),
                "new": len(vr.new),
                "ok": vr.ok,
            },
        )
    )
    return result


def cmd_forensics_duplicates(args: argparse.Namespace, cfg: AppConfig) -> Result:
    result = Result(command="forensics duplicates", target=args.path)
    problem = _check_root(args.path)
    if problem is not None:
        result.fail(problem)
        return result
    try:
        inv = forensics_inventory_mod.run_inventory(
            args.path,
            include=tuple(args.include or ()),
            exclude=tuple(args.exclude or ()),
            hash_algorithms=("sha256",),
        )
    except (ValidationError, ValueError, OSError) as exc:
        result.fail(str(exc))
        return result
    groups = forensics_duplicates_mod.find_duplicates(inv.files)
    dup_files = sum(g.count for g in groups)
    result.data = {
        "root": args.path,
        "groups": [g.to_dict() for g in groups],
        "group_count": len(groups),
        "duplicate_files": dup_files,
        "files_scanned": inv.stats.files,
    }
    result.summary = (
        f"{args.path}: {len(groups)} duplicate group(s), "
        f"{dup_files} file(s) sharing content"
    )
    result.add_event(
        Event(
            event_type="forensics.duplicates.completed",
            source="aegisforge",
            evidence={
                "root": args.path,
                "groups": len(groups),
                "duplicate_files": dup_files,
            },
        )
    )
    return result


def cmd_forensics_timeline(args: argparse.Namespace, cfg: AppConfig) -> Result:
    result = Result(command="forensics timeline", target=args.path)
    problem = _check_root(args.path)
    if problem is not None:
        result.fail(problem)
        return result
    try:
        inv = forensics_inventory_mod.run_inventory(
            args.path,
            include=tuple(args.include or ()),
            exclude=tuple(args.exclude or ()),
            hash_algorithms=(),  # timestamps only; no hashing needed
        )
    except (ValidationError, ValueError, OSError) as exc:
        result.fail(str(exc))
        return result
    entries = forensics_timeline_mod.build_timeline(inv.files)
    if args.limit is not None and args.limit >= 0:
        entries = entries[: args.limit]
    result.data = {
        "root": args.path,
        "timeline": [e.to_dict() for e in entries],
        "entries": len(entries),
        "note": "filesystem timestamps (mtime/atime/ctime) — filesystem "
        "metadata, not content claims",
    }
    result.summary = f"{args.path}: {len(entries)} filesystem timestamp(s)"
    result.add_event(
        Event(
            event_type="forensics.timeline.completed",
            source="aegisforge",
            evidence={"root": args.path, "entries": len(entries)},
        )
    )
    return result


def _short_sha(digest: str | None) -> str:
    return (digest or "")[:12]


def render_forensics_inventory(result: Result) -> str:
    """Human-readable rendering of a `forensics inventory` result."""
    data = result.data
    lines = [result.summary] if result.summary else []
    stats = data.get("stats", {})
    lines.append("")
    lines.append(
        f"Files: {stats.get('files', 0)}  Directories: {stats.get('directories', 0)}  "
        f"Total bytes: {stats.get('total_bytes', 0)}"
    )
    files = data.get("files", [])
    if files:
        lines.append("")
        lines.append(f"{'PATH':<44}{'SIZE':>10}  {'MTIME':<20}  {'SHA256':<12}  TYPE")
        for f in files[:50]:
            lines.append(
                f"{f.get('path', '')[:44]:<44}{f.get('size', 0):>10}  "
                f"{(f.get('mtime') or '-')[:19]:<20}  "
                f"{_short_sha(f.get('hashes', {}).get('sha256')):<12}  "
                f"{f.get('file_type', '')}"
                + ("  [extension mismatch]" if f.get("extension_mismatch") else "")
            )
        if len(files) > 50:
            lines.append(f"  ... and {len(files) - 50} more (see --json)")
    for w in data.get("warnings", [])[:10]:
        lines.append(f"warning: {w.get('path')}: {w.get('reason')}")
    return "\n".join(lines)


def render_forensics_manifest(result: Result) -> str:
    """Human-readable rendering of a `forensics manifest` result."""
    data = result.data
    lines = [result.summary] if result.summary else []
    lines.append("")
    lines.append(f"Manifest: {data.get('manifest_path')}")
    lines.append(f"SHA-256:  {data.get('manifest_sha256')}")
    lines.append(
        f"Files:    {data.get('file_count')} "
        f"({data.get('total_bytes')} bytes, sealed {data.get('created')})"
    )
    lines.append(
        "The manifest digest was recorded in the audit log "
        "(tamper-evidence seam, not a legal claim)."
    )
    return "\n".join(lines)


def render_forensics_verify(result: Result) -> str:
    """Human-readable rendering of a `forensics verify` result."""
    data = result.data
    lines = [result.summary] if result.summary else []
    if data.get("ok"):
        lines.append("")
        lines.append(f"OK: all {data.get('verified')} file(s) match the manifest.")
        return "\n".join(lines)
    for label, key in (
        ("Changed", "changed"),
        ("Missing", "missing"),
        ("New", "new"),
    ):
        items = data.get(key, [])
        if items:
            lines.append("")
            lines.append(f"{label} ({len(items)}):")
            for item in items[:20]:
                lines.append(f"  {item.get('path')}: {item.get('detail')}")
            if len(items) > 20:
                lines.append(f"  ... and {len(items) - 20} more (see --json)")
    if result.findings:
        lines.append("")
        lines.append("Findings:")
        for f in result.findings:
            lines.append(f"  [{f.severity}] {f.title} (confidence {f.confidence})")
            if f.reason:
                lines.append(f"    {f.reason}")
    return "\n".join(lines)


def render_forensics_duplicates(result: Result) -> str:
    """Human-readable rendering of a `forensics duplicates` result."""
    data = result.data
    lines = [result.summary] if result.summary else []
    for group in data.get("groups", [])[:20]:
        lines.append("")
        lines.append(
            f"sha256 {_short_sha(group.get('sha256'))}… ({group.get('count')} files):"
        )
        for path in group.get("paths", []):
            lines.append(f"  {path}")
    if len(data.get("groups", [])) > 20:
        lines.append(f"... and {len(data['groups']) - 20} more groups (see --json)")
    if not data.get("groups"):
        lines.append("")
        lines.append("No duplicate files found.")
    return "\n".join(lines)


def render_forensics_timeline(result: Result) -> str:
    """Human-readable rendering of a `forensics timeline` result."""
    data = result.data
    lines = [result.summary] if result.summary else []
    lines.append("")
    lines.append(
        "Filesystem timestamps (mtime/atime/ctime) — filesystem metadata, "
        "not content claims."
    )
    entries = data.get("timeline", [])
    if entries:
        lines.append("")
        lines.append(f"{'TIMESTAMP (UTC)':<28}{'KIND':<7}PATH")
        for e in entries[:100]:
            lines.append(
                f"{e.get('timestamp', ''):<28}{e.get('kind', ''):<7}{e.get('path', '')}"
            )
        if len(entries) > 100:
            lines.append(f"... and {len(entries) - 100} more (see --json)")
    return "\n".join(lines)
