"""Evidence attachment: copy (never move) files into a case.

Attaching copies the source file into
``cases/<id>/evidence/<kind>/``, hashes the copy with SHA-256, and
records the hash, the original path and the UTC attach time. Sources
are opened for reading only and are never modified, moved or deleted.
"""

from __future__ import annotations

import shutil
from pathlib import Path

from aegisforge.cases.models import EVIDENCE_KINDS, CaseMetadata, EvidenceRecord
from aegisforge.cases.store import CaseError, case_dir, save_case
from aegisforge.core.logging import utc_now_iso
from aegisforge.forensics import hashing as hashing_mod


def _unique_name(directory: Path, name: str) -> str:
    """Avoid collisions inside the evidence folder: file, file_2, file_3..."""
    candidate = name
    stem, dot, suffix = name.partition(".")
    counter = 1
    while (directory / candidate).exists():
        counter += 1
        candidate = f"{stem}_{counter}{dot + suffix if dot else ''}"
    return candidate


def attach_evidence(case: CaseMetadata, kind: str, source: str) -> EvidenceRecord:
    """Copy *source* into the case's evidence folder and record it.

    Raises :class:`CaseError` for unknown kinds or unreadable sources.
    The source file itself is never modified.
    """
    kind = kind.strip().lower()
    if kind not in EVIDENCE_KINDS:
        raise CaseError(
            f"evidence kind must be one of {', '.join(EVIDENCE_KINDS)}, got {kind!r}"
        )
    src = Path(source)
    if not src.is_file():
        raise CaseError(f"evidence source not found (must be a file): {source!r}")
    dest_dir = case_dir(case.case_id) / "evidence" / kind
    dest_dir.mkdir(parents=True, exist_ok=True)
    stored_name = _unique_name(dest_dir, src.name)
    dest = dest_dir / stored_name
    try:
        with open(src, "rb") as fh_in, open(dest, "wb") as fh_out:
            shutil.copyfileobj(fh_in, fh_out)
        digests = hashing_mod.hash_file(str(dest), algorithms=("sha256",))
    except OSError as exc:
        # Never leave a partial copy behind.
        dest.unlink(missing_ok=True)
        raise CaseError(f"cannot attach {source!r}: {exc}") from exc
    case.evidence_seq += 1
    record = EvidenceRecord(
        evidence_id=f"{case.case_id}-E{case.evidence_seq:02d}",
        kind=kind,
        original_path=str(src.resolve()),
        stored_path=str(dest.relative_to(case_dir(case.case_id))),
        sha256=digests["sha256"],
        size=dest.stat().st_size,
        attached_at=utc_now_iso(),
    )
    case.evidence.append(record)
    save_case(case)
    return record
