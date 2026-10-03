"""File hashing (v0.4): single-pass, chunked, bounded memory.

All requested digests are computed in one sequential read of the file,
so hashing a multi-gigabyte image never loads it into memory. SHA-256
is the default and primary digest; MD5 and SHA-1 are offered for
cross-referencing legacy hash sets (both are broken for collision
resistance — never rely on them alone).
"""

from __future__ import annotations

import hashlib

#: Chunk size for streaming reads (64 KiB).
CHUNK_SIZE = 65536

SUPPORTED_ALGORITHMS = ("sha256", "md5", "sha1")
DEFAULT_ALGORITHMS = ("sha256",)


def hash_file(
    path: str, algorithms: tuple[str, ...] = DEFAULT_ALGORITHMS
) -> dict[str, str]:
    """Hash *path* with every algorithm in one streaming pass.

    Returns ``{algorithm: hexdigest}``. Raises :class:`ValueError` for
    unknown algorithms and :class:`OSError` when the file cannot be read
    (callers convert that into a warning, never a crash).
    """
    unknown = [a for a in algorithms if a not in SUPPORTED_ALGORITHMS]
    if unknown:
        raise ValueError(f"unsupported hash algorithm(s): {', '.join(unknown)}")
    if not algorithms:
        raise ValueError("at least one hash algorithm is required")
    hashers = {name: hashlib.new(name) for name in algorithms}
    with open(path, "rb") as fh:
        while True:
            chunk = fh.read(CHUNK_SIZE)
            if not chunk:
                break
            for hasher in hashers.values():
                hasher.update(chunk)
    return {name: hasher.hexdigest() for name, hasher in hashers.items()}


def hash_bytes(
    data: bytes, algorithms: tuple[str, ...] = DEFAULT_ALGORITHMS
) -> dict[str, str]:
    """Hash an in-memory byte string (manifest digests, tests)."""
    hashers = {name: hashlib.new(name) for name in algorithms}
    for hasher in hashers.values():
        hasher.update(data)
    return {name: hasher.hexdigest() for name, hasher in hashers.items()}
