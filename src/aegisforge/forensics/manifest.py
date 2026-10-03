"""Evidence manifests (v0.4): create, seal, verify.

A manifest is a JSON document describing one inventory run: every file
with its hashes, sizes and timestamps, plus run metadata. The manifest
is *sealed* with a SHA-256 over its canonical encoding (``manifest_sha256``,
stored inside the document and reported to the audit log) — a
tamper-evidence seam, not a claim of legal admissibility.

``verify_manifest`` re-hashes the live tree and reports changed /
missing / new files against the manifest.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
from pathlib import Path

from aegisforge import __version__
from aegisforge.core.findings import Finding
from aegisforge.core.logging import utc_now_iso
from aegisforge.forensics import hashing, inventory
from aegisforge.forensics.models import (
    InventoryResult,
    InventoryWarning,
    VerifyChange,
    VerifyResult,
)

log = logging.getLogger("aegisforge")

MANIFEST_VERSION = "1"


def _canonical(data: dict) -> bytes:
    """Canonical JSON encoding used for the manifest digest."""
    return json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")


def build_manifest(result: InventoryResult, operator_note: str | None = None) -> dict:
    """Build a sealed manifest dict from an InventoryResult."""
    files = sorted(
        (f.to_dict() for f in result.files if not f.is_symlink),
        key=lambda d: d["path"],
    )
    manifest = {
        "manifest_version": MANIFEST_VERSION,
        "tool": "aegisforge",
        "tool_version": __version__,
        "created": utc_now_iso(),
        "root": result.root,
        "operator_note": operator_note,
        "inventory_started": result.started,
        "inventory_finished": result.finished,
        "file_count": len(files),
        "total_bytes": sum(f["size"] for f in files),
        "hash_algorithms": sorted({algo for f in files for algo in f["hashes"]}),
        "files": files,
        "warnings": [w.to_dict() for w in result.warnings],
    }
    manifest["manifest_sha256"] = hashlib.sha256(_canonical(manifest)).hexdigest()
    return manifest


def write_manifest(manifest: dict, path: str | os.PathLike[str]) -> str:
    """Write *manifest* as pretty JSON. Returns the path written."""
    out = Path(path)
    payload = json.dumps(manifest, indent=2, sort_keys=True) + "\n"
    out.write_text(payload, encoding="utf-8")
    return str(out)


def read_manifest(path: str | os.PathLike[str]) -> dict:
    """Read and validate a manifest file. Raises ValueError when invalid."""
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except OSError as exc:
        raise ValueError(f"cannot read manifest {path}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise ValueError(f"manifest {path} is not valid JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise ValueError(f"manifest {path} is not a JSON object")
    for key in ("manifest_version", "files", "manifest_sha256"):
        if key not in data:
            raise ValueError(f"manifest {path} is missing required key {key!r}")
    # Verify the seal: recompute over the document minus the digest itself.
    sealed = data["manifest_sha256"]
    body = {k: v for k, v in data.items() if k != "manifest_sha256"}
    if hashlib.sha256(_canonical(body)).hexdigest() != sealed:
        raise ValueError(
            f"manifest {path} seal mismatch: content differs from its "
            "recorded manifest_sha256"
        )
    data["_source_path"] = str(path)
    return data


def verify_manifest(
    manifest: dict, root: str | os.PathLike[str] | None = None
) -> VerifyResult:
    """Re-hash the live tree and compare against *manifest*.

    Returns changed (hash mismatch), missing (in manifest, absent on
    disk) and new (on disk, absent from manifest) file lists. New-file
    detection walks the tree without hashing — only paths are compared.
    """
    manifest_path = manifest.get("_source_path", "")
    scan_root = Path(root) if root is not None else Path(manifest.get("root", ""))
    expected = {f["path"]: f for f in manifest.get("files", [])}
    result = VerifyResult(
        manifest_path=str(manifest_path),
        root=str(scan_root),
        manifest_sha256=manifest.get("manifest_sha256", ""),
    )
    seen: set[str] = set()
    for entry in inventory.iter_inventory(scan_root, hash_algorithms=()):
        if isinstance(entry, InventoryWarning):
            continue
        if entry.is_symlink:
            continue
        seen.add(entry.path)
        exp = expected.get(entry.path)
        if exp is None:
            result.new.append(
                VerifyChange(
                    path=entry.path,
                    detail="present on disk, absent from manifest",
                )
            )
            continue
        # Re-hash with the manifest's algorithms for a fair comparison.
        algos = tuple(exp.get("hashes", {}).keys()) or hashing.DEFAULT_ALGORITHMS
        try:
            current = hashing.hash_file(str(scan_root / entry.path), algos)
        except OSError as exc:
            result.changed.append(
                VerifyChange(path=entry.path, detail=f"unreadable during verify: {exc}")
            )
            continue
        mismatched = [
            algo
            for algo, digest in exp.get("hashes", {}).items()
            if current.get(algo) != digest
        ]
        if mismatched:
            result.changed.append(
                VerifyChange(
                    path=entry.path,
                    detail=(
                        "hash mismatch ("
                        + ", ".join(mismatched)
                        + " differ from manifest)"
                    ),
                )
            )
        else:
            result.verified += 1
    for path in sorted(expected):
        if path not in seen:
            result.missing.append(
                VerifyChange(path=path, detail="in manifest, absent on disk")
            )
    return result


def verify_findings(result: VerifyResult) -> list[Finding]:
    """Turn a VerifyResult into findings with observed/inferred discipline."""
    findings: list[Finding] = []
    for change in result.changed:
        findings.append(
            Finding(
                title=f"File changed since manifest: {change.path}",
                severity="high",
                confidence=90,
                reason=(
                    f"OBSERVED: {change.detail}. INFERRED: the file was "
                    "modified, replaced, or corrupted after the manifest "
                    "was created — confirm against backups/change records "
                    "before treating this as malicious."
                ),
                evidence=[f"manifest {result.manifest_path}", f"path {change.path}"],
            )
        )
    for missing in result.missing:
        findings.append(
            Finding(
                title=f"File missing since manifest: {missing.path}",
                severity="medium",
                confidence=85,
                reason=(
                    "OBSERVED: the file was listed in the manifest but is "
                    "absent on disk. INFERRED: it was deleted or moved "
                    "after the manifest was created."
                ),
                evidence=[f"manifest {result.manifest_path}", f"path {missing.path}"],
            )
        )
    for new in result.new:
        findings.append(
            Finding(
                title=f"New file since manifest: {new.path}",
                severity="low",
                confidence=80,
                reason=(
                    "OBSERVED: the file exists on disk but was not listed "
                    "in the manifest. INFERRED: it was created or copied "
                    "in after the manifest was created."
                ),
                evidence=[f"manifest {result.manifest_path}", f"path {new.path}"],
            )
        )
    return findings
