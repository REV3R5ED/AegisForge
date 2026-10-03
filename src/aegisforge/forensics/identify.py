"""File-type identification (v0.4): magic bytes first, extension fallback.

Identification is an *observation* about the file's leading bytes. When
no signature matches, the file extension is used as a clearly-labeled
fallback (``type_source="extension"``); when neither applies the type
is ``"unknown"``. ``extension_mismatch`` is a plain observed fact —
magic says one thing, the extension suggests another — not an
accusation.
"""

from __future__ import annotations

import os

# (offset, signature, type label). Checked in order; first match wins.
_SIGNATURES: list[tuple[int, bytes, str]] = [
    (0, b"\x7fELF", "elf executable"),
    (0, b"MZ", "pe executable"),
    (0, b"\x89PNG\r\n\x1a\n", "png image"),
    (0, b"\xff\xd8\xff", "jpeg image"),
    (0, b"GIF87a", "gif image"),
    (0, b"GIF89a", "gif image"),
    (0, b"BM", "bmp image"),
    (0, b"II*\x00", "tiff image"),
    (0, b"MM\x00*", "tiff image"),
    (4, b"ftyp", "mp4 video"),
    (0, b"RIFF", "riff container"),  # refined below (WEBP/WAVE/AVI)
    (0, b"%PDF-", "pdf document"),
    (0, b"PK\x03\x04", "zip archive"),
    (0, b"PK\x05\x06", "zip archive"),
    (0, b"PK\x07\x08", "zip archive"),
    (0, b"\x1f\x8b", "gzip archive"),
    (0, b"BZh", "bzip2 archive"),
    (0, b"7z\xbc\xaf'\x1c", "7z archive"),
    (0, b"Rar!\x1a\x07", "rar archive"),
    (0, b"\xfd7zXZ\x00", "xz archive"),
    (0, b"\x28\xb5\x2f\xfd", "zstd archive"),
    (257, b"ustar", "tar archive"),
    (0, b"SQLite format 3\x00", "sqlite database"),
    (0, b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "ole document"),
    (0, b"#!/", "script"),
    (0, b"<?xml", "xml document"),
    (0, b"%!PS", "postscript document"),
]

# Extension fallback: extension -> type label. Only consulted when no
# magic signature matches, and the source is labeled "extension".
_EXTENSION_TYPES: dict[str, str] = {
    ".txt": "text",
    ".md": "text",
    ".log": "text",
    ".csv": "text",
    ".json": "text",
    ".xml": "text",
    ".html": "text",
    ".htm": "text",
    ".css": "text",
    ".js": "text",
    ".py": "text",
    ".sh": "text",
    ".c": "text",
    ".h": "text",
    ".rs": "text",
    ".go": "text",
    ".java": "text",
    ".yaml": "text",
    ".yml": "text",
    ".toml": "text",
    ".ini": "text",
    ".cfg": "text",
    ".jpg": "jpeg image",
    ".jpeg": "jpeg image",
    ".png": "png image",
    ".gif": "gif image",
    ".bmp": "bmp image",
    ".tif": "tiff image",
    ".tiff": "tiff image",
    ".webp": "webp image",
    ".mp4": "mp4 video",
    ".avi": "avi video",
    ".mkv": "matroska video",
    ".mp3": "mp3 audio",
    ".wav": "wav audio",
    ".ogg": "ogg audio",
    ".pdf": "pdf document",
    ".doc": "word document",
    ".docx": "word document",
    ".xls": "excel document",
    ".xlsx": "excel document",
    ".ppt": "powerpoint document",
    ".pptx": "powerpoint document",
    ".zip": "zip archive",
    ".gz": "gzip archive",
    ".tgz": "gzip archive",
    ".bz2": "bzip2 archive",
    ".xz": "xz archive",
    ".tar": "tar archive",
    ".rar": "rar archive",
    ".7z": "7z archive",
    ".exe": "pe executable",
    ".dll": "pe executable",
    ".so": "elf executable",
    ".elf": "elf executable",
    ".db": "sqlite database",
    ".sqlite": "sqlite database",
    ".sqlite3": "sqlite database",
}

# Extensions whose label implies executability — used only to describe
# the mismatch observation, never to infer intent.
_EXECUTABLE_EXTENSIONS = {
    ".exe",
    ".dll",
    ".so",
    ".elf",
    ".bat",
    ".cmd",
    ".ps1",
    ".sh",
    ".com",
    ".scr",
    ".msi",
}

#: How many leading bytes are read for signature matching (covers tar's
#: "ustar" at offset 257 plus margin).
HEAD_BYTES = 512


def read_head(path: str, size: int = HEAD_BYTES) -> bytes:
    """Read up to *size* leading bytes. Empty bytes on any read failure."""
    try:
        with open(path, "rb") as fh:
            return fh.read(size)
    except OSError:
        return b""


def identify_bytes(head: bytes) -> str | None:
    """Identify by magic bytes. Returns the type label or None."""
    for offset, signature, label in _SIGNATURES:
        if (
            len(head) >= offset + len(signature)
            and head[offset : offset + len(signature)] == signature
        ):
            if label == "riff container":
                # RIFF....WEBP / RIFF....WAVE / RIFF....AVI
                if len(head) >= 12:
                    form = head[8:12]
                    if form == b"WEBP":
                        return "webp image"
                    if form == b"WAVE":
                        return "wav audio"
                    if form == b"AVI ":
                        return "avi video"
                return label
            return label
    return None


def identify_extension(path: str) -> str | None:
    """Identify by file extension. Returns the type label or None."""
    ext = os.path.splitext(path)[1].lower()
    return _EXTENSION_TYPES.get(ext)


def identify(path: str) -> tuple[str, str, bool]:
    """Identify *path*.

    Returns ``(type_label, type_source, extension_mismatch)`` where
    ``type_source`` is ``"magic"``, ``"extension"`` or ``"unknown"``.
    ``extension_mismatch`` is True when magic identification succeeded
    but the extension suggests a *different* type — an observed fact,
    not a verdict.
    """
    head = read_head(path)
    magic_type = identify_bytes(head) if head else None
    ext_type = identify_extension(path)
    if magic_type is not None:
        mismatch = ext_type is not None and ext_type != magic_type
        return magic_type, "magic", mismatch
    if ext_type is not None:
        return ext_type, "extension", False
    return "unknown", "unknown", False


def looks_executable_extension(path: str) -> bool:
    """True if the file extension is conventionally executable."""
    return os.path.splitext(path)[1].lower() in _EXECUTABLE_EXTENSIONS
