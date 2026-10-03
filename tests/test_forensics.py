"""Tests for the v0.4 digital forensics module: identification, hashing,
inventory, manifests, verification, duplicates, timelines, and CLI wiring."""

from __future__ import annotations

import hashlib
import io
import json
import os
import tracemalloc
from contextlib import redirect_stdout
from pathlib import Path

import pytest

from aegisforge.cli import main as cli_main
from aegisforge.core.plugins import get_registry
from aegisforge.forensics import duplicates as duplicates_mod
from aegisforge.forensics import hashing as hashing_mod
from aegisforge.forensics import identify as identify_mod
from aegisforge.forensics import inventory as inventory_mod
from aegisforge.forensics import manifest as manifest_mod
from aegisforge.forensics import timeline as timeline_mod
from aegisforge.forensics.models import (
    InventoryWarning,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _run_cli(argv: list[str]) -> tuple[int, str]:
    buf = io.StringIO()
    with redirect_stdout(buf):
        code = cli_main.main(argv)
    return code, buf.getvalue()


def _write(path: Path, data: bytes) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return path


@pytest.fixture()
def tree(tmp_path: Path) -> Path:
    """Synthetic evidence tree: nested dirs, mixed types, unicode name."""
    root = tmp_path / "evidence"
    _write(root / "note.txt", b"hello world\n")
    _write(root / "sub" / "copy.txt", b"hello world\n")  # duplicate content
    _write(root / "sub" / "deep" / "img.png", b"\x89PNG\r\n\x1a\n" + b"\x00" * 64)
    _write(root / "evil.jpg", b"MZ\x90\x00" + b"\x00" * 32)  # MZ in a .jpg
    _write(root / "archive.zip", b"PK\x03\x04" + b"\x00" * 32)
    _write(root / "empty.bin", b"")
    _write(root / "données.txt", "données\n".encode())  # unicode name
    return root


# ---------------------------------------------------------------------------
# identify.py
# ---------------------------------------------------------------------------


def test_identify_magic_bytes(tmp_path: Path):
    cases = [
        (b"\x7fELF....", "elf executable"),
        (b"MZ\x90\x00", "pe executable"),
        (b"\x89PNG\r\n\x1a\n", "png image"),
        (b"\xff\xd8\xff\xe0", "jpeg image"),
        (b"GIF89a", "gif image"),
        (b"BM....", "bmp image"),
        (b"%PDF-1.7", "pdf document"),
        (b"PK\x03\x04", "zip archive"),
        (b"\x1f\x8b\x08\x00", "gzip archive"),
        (b"SQLite format 3\x00", "sqlite database"),
        (b"RIFF\x00\x00\x00\x00WEBP", "webp image"),
        (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "ole document"),
    ]
    for head, expected in cases:
        path = _write(tmp_path / f"f_{expected.replace(' ', '_')}.bin", head)
        label, source, _ = identify_mod.identify(str(path))
        assert label == expected, head
        assert source == "magic"


def test_identify_tar_offset_signature(tmp_path: Path):
    path = _write(tmp_path / "a.tar", b"\x00" * 257 + b"ustar\x00" + b"\x00" * 200)
    label, source, _ = identify_mod.identify(str(path))
    assert label == "tar archive"
    assert source == "magic"


def test_identify_extension_fallback(tmp_path: Path):
    path = _write(tmp_path / "readme.txt", b"just some words")
    label, source, mismatch = identify_mod.identify(str(path))
    assert label == "text"
    assert source == "extension"
    assert mismatch is False


def test_identify_unknown(tmp_path: Path):
    path = _write(tmp_path / "empty.bin", b"")
    label, source, mismatch = identify_mod.identify(str(path))
    assert label == "unknown"
    assert source == "unknown"
    assert mismatch is False


def test_identify_extension_mismatch_observed(tmp_path: Path):
    path = _write(tmp_path / "evil.jpg", b"MZ\x90\x00" + b"\x00" * 16)
    label, source, mismatch = identify_mod.identify(str(path))
    assert label == "pe executable"
    assert source == "magic"
    assert mismatch is True  # observed fact, not a verdict


def test_identify_missing_file_returns_unknown():
    label, source, _ = identify_mod.identify("/nonexistent/file.bin")
    assert label == "unknown"
    assert source == "unknown"


# ---------------------------------------------------------------------------
# hashing.py
# ---------------------------------------------------------------------------


def test_hash_file_correctness(tmp_path: Path):
    data = b"The quick brown fox jumps over the lazy dog" * 100
    path = _write(tmp_path / "fox.bin", data)
    got = hashing_mod.hash_file(str(path), ("sha256", "md5", "sha1"))
    assert got["sha256"] == hashlib.sha256(data).hexdigest()
    assert got["md5"] == hashlib.md5(data).hexdigest()
    assert got["sha1"] == hashlib.sha1(data).hexdigest()


def test_hash_file_default_is_sha256_only(tmp_path: Path):
    path = _write(tmp_path / "a.bin", b"data")
    assert set(hashing_mod.hash_file(str(path)).keys()) == {"sha256"}


def test_hash_file_empty(tmp_path: Path):
    path = _write(tmp_path / "empty.bin", b"")
    got = hashing_mod.hash_file(str(path))
    assert got["sha256"] == hashlib.sha256(b"").hexdigest()


def test_hash_file_unknown_algorithm(tmp_path: Path):
    path = _write(tmp_path / "a.bin", b"data")
    with pytest.raises(ValueError, match="unsupported hash algorithm"):
        hashing_mod.hash_file(str(path), ("sha512",))


def test_hash_file_missing_raises_oserror():
    with pytest.raises(OSError):
        hashing_mod.hash_file("/nonexistent/file.bin")


def test_hash_file_streaming_bounded_memory(tmp_path: Path):
    # 20 MiB file must hash with a small peak: chunked reads, one pass.
    path = tmp_path / "big.bin"
    with path.open("wb") as fh:
        for _ in range(20):
            fh.write(os.urandom(1024 * 1024))
    tracemalloc.start()
    try:
        got = hashing_mod.hash_file(str(path), ("sha256", "md5", "sha1"))
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert len(got) == 3
    assert peak < 2 * 1024 * 1024, f"peak {peak} too high for chunked hashing"


# ---------------------------------------------------------------------------
# inventory.py
# ---------------------------------------------------------------------------


def test_inventory_walks_and_counts(tree: Path):
    result = inventory_mod.run_inventory(tree)
    assert not result.warnings
    assert result.stats.files == 7
    assert result.stats.directories == 3  # evidence, sub, sub/deep
    assert result.stats.total_bytes == sum(f.size for f in result.files)
    paths = [f.path for f in result.files]
    assert paths == sorted(paths)  # deterministic order
    assert "sub/deep/img.png" in paths
    assert "données.txt" in paths  # unicode name survives


def test_inventory_hashes_all_three_algorithms(tree: Path):
    result = inventory_mod.run_inventory(
        tree, hash_algorithms=("sha256", "md5", "sha1")
    )
    for record in result.files:
        assert set(record.hashes) == {"sha256", "md5", "sha1"}


def test_inventory_identifies_types(tree: Path):
    result = inventory_mod.run_inventory(tree)
    by_path = {f.path: f for f in result.files}
    assert by_path["sub/deep/img.png"].file_type == "png image"
    assert by_path["sub/deep/img.png"].type_source == "magic"
    assert by_path["note.txt"].file_type == "text"
    assert by_path["note.txt"].type_source == "extension"
    assert by_path["empty.bin"].file_type == "unknown"
    evil = by_path["evil.jpg"]
    assert evil.file_type == "pe executable"
    assert evil.extension_mismatch is True


def test_inventory_records_filesystem_timestamps(tree: Path):
    result = inventory_mod.run_inventory(tree)
    for record in result.files:
        assert record.mtime and record.mtime.endswith("Z")
        assert record.atime and record.atime.endswith("Z")
        assert record.ctime and record.ctime.endswith("Z")


def test_inventory_include_exclude_globs(tree: Path):
    included = inventory_mod.run_inventory(tree, include=("*.txt",))
    assert {f.path for f in included.files} == {
        "note.txt",
        "sub/copy.txt",
        "données.txt",
    }
    excluded = inventory_mod.run_inventory(tree, exclude=("*.txt", "sub/*"))
    assert {f.path for f in excluded.files} == {
        "evil.jpg",
        "archive.zip",
        "empty.bin",
    }
    # exclude wins over include
    both = inventory_mod.run_inventory(
        tree, include=("sub/*",), exclude=("sub/deep/*",)
    )
    assert {f.path for f in both.files} == {"sub/copy.txt"}


def test_inventory_symlinks(tree: Path):
    (tree / "link.txt").symlink_to(tree / "note.txt")
    (tree / "dirlink").symlink_to(tree / "sub", target_is_directory=True)
    result = inventory_mod.run_inventory(tree)
    by_path = {f.path: f for f in result.files}
    link = by_path["link.txt"]
    assert link.is_symlink is True
    assert link.file_type == "symlink"
    assert link.symlink_target == str(tree / "note.txt")
    assert link.hashes == {}
    # symlinked dir is not descended into: no dirlink/... entries
    assert not any(p.startswith("dirlink/") for p in by_path)
    assert result.stats.symlinks >= 1


def test_inventory_permission_denied_becomes_warning(tree: Path, monkeypatch):
    real_stat = Path.stat

    def fake_stat(self, *args, **kwargs):
        if self.name == "note.txt":
            raise PermissionError("denied")
        return real_stat(self, *args, **kwargs)

    monkeypatch.setattr(Path, "stat", fake_stat)
    result = inventory_mod.run_inventory(tree)
    assert any(w.path == "note.txt" for w in result.warnings)
    assert "note.txt" not in {f.path for f in result.files}
    assert result.stats.warnings >= 1


def test_inventory_nonexistent_root():
    entries = list(inventory_mod.iter_inventory("/nonexistent/root"))
    assert len(entries) == 1
    assert isinstance(entries[0], InventoryWarning)
    assert "does not exist" in entries[0].reason


def test_inventory_lone_file(tree: Path):
    result = inventory_mod.run_inventory(tree / "note.txt")
    assert len(result.files) == 1
    assert result.files[0].path == "note.txt"
    assert result.files[0].hashes["sha256"]


def test_inventory_result_serializes(tree: Path):
    result = inventory_mod.run_inventory(tree)
    data = result.to_dict()
    assert data["stats"]["files"] == 7
    assert len(data["files"]) == 7
    json.dumps(data)  # must be JSON-serializable


# ---------------------------------------------------------------------------
# manifest.py
# ---------------------------------------------------------------------------


def test_manifest_round_trip(tree: Path, tmp_path: Path):
    result = inventory_mod.run_inventory(tree, hash_algorithms=("sha256", "md5"))
    manifest = manifest_mod.build_manifest(result, operator_note="case 42")
    out = tmp_path / "manifest.json"
    manifest_mod.write_manifest(manifest, out)
    loaded = manifest_mod.read_manifest(out)
    assert loaded["manifest_sha256"] == manifest["manifest_sha256"]
    assert loaded["file_count"] == 7
    assert loaded["operator_note"] == "case 42"
    assert loaded["tool"] == "aegisforge"
    assert loaded["_source_path"] == str(out)
    assert set(loaded["hash_algorithms"]) == {"md5", "sha256"}


def test_manifest_seal_detects_tampering(tree: Path, tmp_path: Path):
    result = inventory_mod.run_inventory(tree)
    manifest = manifest_mod.build_manifest(result)
    out = tmp_path / "manifest.json"
    manifest_mod.write_manifest(manifest, out)
    data = json.loads(out.read_text())
    data["files"][0]["size"] = 999999  # tamper
    out.write_text(json.dumps(data))
    with pytest.raises(ValueError, match="seal mismatch"):
        manifest_mod.read_manifest(out)


def test_manifest_rejects_invalid(tmp_path: Path):
    bad = tmp_path / "bad.json"
    bad.write_text("{not json")
    with pytest.raises(ValueError, match="not valid JSON"):
        manifest_mod.read_manifest(bad)
    not_object = tmp_path / "list.json"
    not_object.write_text("[1, 2, 3]")
    with pytest.raises(ValueError, match="not a JSON object"):
        manifest_mod.read_manifest(not_object)
    missing_key = tmp_path / "missing.json"
    missing_key.write_text(json.dumps({"files": []}))
    with pytest.raises(ValueError, match="missing required key"):
        manifest_mod.read_manifest(missing_key)
    with pytest.raises(ValueError, match="cannot read manifest"):
        manifest_mod.read_manifest(tmp_path / "nope.json")


def test_verify_clean_tree(tree: Path, tmp_path: Path):
    manifest = manifest_mod.build_manifest(inventory_mod.run_inventory(tree))
    out = tmp_path / "m.json"
    manifest_mod.write_manifest(manifest, out)
    loaded = manifest_mod.read_manifest(out)
    vr = manifest_mod.verify_manifest(loaded)
    assert vr.ok is True
    assert vr.verified == 7
    assert not vr.changed and not vr.missing and not vr.new
    assert manifest_mod.verify_findings(vr) == []


def test_verify_detects_changed_missing_new(tree: Path, tmp_path: Path):
    manifest = manifest_mod.build_manifest(inventory_mod.run_inventory(tree))
    out = tmp_path / "m.json"
    manifest_mod.write_manifest(manifest, out)
    loaded = manifest_mod.read_manifest(out)

    (tree / "note.txt").write_bytes(b"tampered!\n")  # changed
    (tree / "empty.bin").unlink()  # missing
    _write(tree / "planted.exe", b"MZ")  # new

    vr = manifest_mod.verify_manifest(loaded)
    assert vr.ok is False
    assert [c.path for c in vr.changed] == ["note.txt"]
    assert "sha256" in vr.changed[0].detail
    assert [m.path for m in vr.missing] == ["empty.bin"]
    assert [n.path for n in vr.new] == ["planted.exe"]
    assert vr.verified == 5

    findings = manifest_mod.verify_findings(vr)
    by_title = {f.title: f for f in findings}
    changed = by_title["File changed since manifest: note.txt"]
    assert changed.severity == "high"
    assert "OBSERVED" in changed.reason and "INFERRED" in changed.reason
    assert by_title["File missing since manifest: empty.bin"].severity == "medium"
    assert by_title["New file since manifest: planted.exe"].severity == "low"


def test_verify_with_root_override(tree: Path, tmp_path: Path):
    manifest = manifest_mod.build_manifest(inventory_mod.run_inventory(tree))
    out = tmp_path / "m.json"
    manifest_mod.write_manifest(manifest, out)
    loaded = manifest_mod.read_manifest(out)
    vr = manifest_mod.verify_manifest(loaded, root=tree)
    assert vr.ok is True


def test_verify_skips_symlinks_and_survives_warnings(
    tree: Path, tmp_path: Path, monkeypatch
):
    (tree / "link.txt").symlink_to(tree / "note.txt")
    manifest = manifest_mod.build_manifest(inventory_mod.run_inventory(tree))
    out = tmp_path / "m.json"
    manifest_mod.write_manifest(manifest, out)
    loaded = manifest_mod.read_manifest(out)

    # Symlinks are not part of the manifest and must not appear as new.
    vr = manifest_mod.verify_manifest(loaded)
    assert vr.ok is True
    assert "link.txt" not in [n.path for n in vr.new]

    # A warning mid-walk is skipped, not fatal.
    real_iter = inventory_mod.iter_inventory

    def iter_with_warning(*args, **kwargs):
        yield InventoryWarning(path="ghost", reason="boom")
        yield from real_iter(*args, **kwargs)

    monkeypatch.setattr(inventory_mod, "iter_inventory", iter_with_warning)
    vr = manifest_mod.verify_manifest(loaded)
    assert vr.ok is True


def test_verify_unreadable_file_reports_changed(
    tree: Path, tmp_path: Path, monkeypatch
):
    manifest = manifest_mod.build_manifest(inventory_mod.run_inventory(tree))
    out = tmp_path / "m.json"
    manifest_mod.write_manifest(manifest, out)
    loaded = manifest_mod.read_manifest(out)

    real_hash = hashing_mod.hash_file

    def fake_hash(path: str, algorithms=("sha256",)):
        if path.endswith("note.txt"):
            raise OSError("input/output error")
        return real_hash(path, algorithms)

    monkeypatch.setattr(hashing_mod, "hash_file", fake_hash)
    vr = manifest_mod.verify_manifest(loaded)
    assert [c.path for c in vr.changed] == ["note.txt"]
    assert "unreadable during verify" in vr.changed[0].detail


# ---------------------------------------------------------------------------
# duplicates.py / timeline.py
# ---------------------------------------------------------------------------


def test_find_duplicates_groups_by_sha256(tree: Path):
    result = inventory_mod.run_inventory(tree)
    groups = duplicates_mod.find_duplicates(result.files)
    assert len(groups) == 1
    group = groups[0]
    assert group.count == 2
    assert sorted(group.paths) == ["note.txt", "sub/copy.txt"]
    assert group.sha256 == hashlib.sha256(b"hello world\n").hexdigest()


def test_find_duplicates_none_unique(tmp_path: Path):
    _write(tmp_path / "a.txt", b"one")
    _write(tmp_path / "b.txt", b"two")
    result = inventory_mod.run_inventory(tmp_path)
    assert duplicates_mod.find_duplicates(result.files) == []


def test_build_timeline_ordered_and_labeled(tree: Path):
    result = inventory_mod.run_inventory(tree, hash_algorithms=())
    entries = timeline_mod.build_timeline(result.files)
    assert len(entries) == 7 * 3  # mtime + atime + ctime per file
    stamps = [e.timestamp for e in entries]
    assert stamps == sorted(stamps)
    assert {e.kind for e in entries} == {"mtime", "atime", "ctime"}
    assert all(e.timestamp.endswith("Z") for e in entries)


# ---------------------------------------------------------------------------
# CLI wiring
# ---------------------------------------------------------------------------


def test_plugin_registered_as_v040():
    info = get_registry().get("forensics")
    assert info.version == "0.4.0"
    assert "forensics inventory" in info.commands
    assert "forensics verify" in info.commands


def test_cli_inventory_human_json_csv(tree: Path):
    code, out = _run_cli(["forensics", "inventory", str(tree)])
    assert code == 0
    assert "7 file(s)" in out
    assert "evil.jpg" in out and "[extension mismatch]" in out

    code, out = _run_cli(["forensics", "inventory", str(tree), "--json"])
    assert code == 0
    envelope = json.loads(out)
    assert envelope["command"] == "forensics inventory"
    assert len(envelope["data"]["files"]) == 7

    code, out = _run_cli(["forensics", "inventory", str(tree), "--csv"])
    assert code == 0
    assert out.splitlines()[0].split(",") == [
        "path",
        "size",
        "mtime",
        "sha256",
        "md5",
        "sha1",
        "file_type",
        "type_source",
    ]


def test_cli_inventory_globs_and_algorithms(tree: Path):
    code, out = _run_cli(
        [
            "forensics",
            "inventory",
            str(tree),
            "--include",
            "*.txt",
            "--algorithms",
            "sha256",
            "--algorithms",
            "md5",
        ]
    )
    assert code == 0
    assert "3 file(s)" in out
    code, out = _run_cli(
        [
            "forensics",
            "inventory",
            str(tree),
            "--include",
            "*.txt",
            "--algorithms",
            "sha256",
            "--algorithms",
            "md5",
            "--json",
        ]
    )
    files = json.loads(out)["data"]["files"]
    assert all(set(f["hashes"]) == {"sha256", "md5"} for f in files)


def test_cli_inventory_missing_path():
    code, out = _run_cli(["forensics", "inventory", "/nonexistent/path"])
    assert code == 2
    assert "does not exist" in out


def test_cli_manifest_writes_and_audits(tree: Path, tmp_path: Path, monkeypatch):
    monkeypatch.setenv("AEGISFORGE_AUDIT_LOG", str(tmp_path / "audit.log"))
    out = tmp_path / "ev.json"
    code, text = _run_cli(
        [
            "forensics",
            "manifest",
            str(tree),
            "--output",
            str(out),
            "--note",
            "seizure 7",
        ]
    )
    assert code == 0
    assert "manifest written" in text
    manifest = manifest_mod.read_manifest(out)  # sealed and valid
    assert manifest["operator_note"] == "seizure 7"
    audit_lines = (tmp_path / "audit.log").read_text().strip().splitlines()
    manifest_records = [
        json.loads(line)
        for line in audit_lines
        if json.loads(line).get("manifest_sha256")
    ]
    assert len(manifest_records) == 1
    assert manifest_records[0]["manifest_sha256"] == manifest["manifest_sha256"]


def test_cli_verify_clean_and_dirty(tree: Path, tmp_path: Path):
    out = tmp_path / "ev.json"
    code, _ = _run_cli(["forensics", "manifest", str(tree), "--output", str(out)])
    assert code == 0

    code, text = _run_cli(["forensics", "verify", "--manifest", str(out)])
    assert code == 0
    assert "0 changed, 0 missing, 0 new" in text

    (tree / "note.txt").write_bytes(b"tampered\n")
    code, text = _run_cli(["forensics", "verify", "--manifest", str(out)])
    assert code == 1  # findings present
    assert "1 changed" in text
    assert "OBSERVED" in text and "INFERRED" in text

    code, text = _run_cli(["forensics", "verify", "--manifest", str(out), "--json"])
    assert code == 1
    envelope = json.loads(text)
    assert envelope["data"]["ok"] is False
    assert len(envelope["findings"]) == 1


def test_cli_verify_bad_manifest(tmp_path: Path):
    bad = tmp_path / "bad.json"
    bad.write_text("{}")
    code, _ = _run_cli(["forensics", "verify", "--manifest", str(bad)])
    assert code == 2
    code, _ = _run_cli(
        ["forensics", "verify", "--manifest", str(tmp_path / "nope.json")]
    )
    assert code == 2


def test_cli_duplicates(tree: Path):
    code, out = _run_cli(["forensics", "duplicates", str(tree)])
    assert code == 0
    assert "1 duplicate group(s)" in out
    assert "note.txt" in out and "sub/copy.txt" in out
    code, out = _run_cli(["forensics", "duplicates", str(tree), "--json"])
    groups = json.loads(out)["data"]["groups"]
    assert len(groups) == 1 and groups[0]["count"] == 2


def test_cli_timeline(tree: Path):
    code, out = _run_cli(["forensics", "timeline", str(tree)])
    assert code == 0
    assert "21 filesystem timestamp(s)" in out
    assert "filesystem metadata, not content claims" in out
    code, out = _run_cli(["forensics", "timeline", str(tree), "--limit", "5"])
    assert code == 0
    assert "5 filesystem timestamp(s)" in out
    code, out = _run_cli(["forensics", "timeline", str(tree), "--csv"])
    assert code == 0
    assert out.splitlines()[0] == "timestamp,kind,path"


def test_cli_forensics_read_only(tree: Path, tmp_path: Path):
    """Scanning must not modify anything under the root."""
    before = {
        p: (p.stat().st_mtime_ns, p.stat().st_size)
        for p in tree.rglob("*")
        if p.is_file()
    }
    _run_cli(["forensics", "inventory", str(tree), "--algorithms", "sha256"])
    out = tmp_path / "ev.json"
    _run_cli(["forensics", "manifest", str(tree), "--output", str(out)])
    _run_cli(["forensics", "verify", "--manifest", str(out)])
    _run_cli(["forensics", "duplicates", str(tree)])
    _run_cli(["forensics", "timeline", str(tree)])
    after = {
        p: (p.stat().st_mtime_ns, p.stat().st_size)
        for p in tree.rglob("*")
        if p.is_file()
    }
    assert before == after
