"""SQLite-backed intel cache.

Cache key: (provider name, normalized indicator value). Each entry
carries the provider's record plus a TTL; expired entries are treated
as misses and pruned lazily. Lives under the shared state dir so it
survives invocations (override with ``AEGISFORGE_STATE_DIR``).
"""

from __future__ import annotations

import json
import sqlite3
import time
from pathlib import Path
from typing import Any

from aegisforge.core.logging import state_dir
from aegisforge.intel.models import IntelRecord


def cache_path() -> Path:
    root = state_dir() / "intel"
    root.mkdir(parents=True, exist_ok=True)
    return root / "cache.sqlite3"


class IntelCache:
    """Tiny SQLite cache for :class:`IntelRecord` dicts."""

    def __init__(self, path: Path | None = None, ttl_seconds: int = 86400) -> None:
        self.path = Path(path) if path else cache_path()
        self.ttl_seconds = max(0, ttl_seconds)
        self._conn = sqlite3.connect(str(self.path))
        self._conn.execute(
            """CREATE TABLE IF NOT EXISTS intel_cache (
                   provider TEXT NOT NULL,
                   itype TEXT NOT NULL,
                   indicator TEXT NOT NULL,
                   fetched_at REAL NOT NULL,
                   record TEXT NOT NULL,
                   PRIMARY KEY (provider, itype, indicator)
               )"""
        )
        self._conn.commit()

    def close(self) -> None:
        self._conn.close()

    def get(
        self, provider: str, indicator_type: str, indicator: str
    ) -> dict[str, Any] | None:
        """Return the cached record dict, or None on miss/expiry.

        The key is (provider, type, value): a URL indicator and a domain
        indicator may share the same host string but are different
        queries.
        """
        row = self._conn.execute(
            "SELECT fetched_at, record FROM intel_cache "
            "WHERE provider = ? AND itype = ? AND indicator = ?",
            (provider, indicator_type, indicator),
        ).fetchone()
        if row is None:
            return None
        fetched_at, record_json = row
        if self.ttl_seconds and (time.time() - fetched_at) > self.ttl_seconds:
            self._conn.execute(
                "DELETE FROM intel_cache "
                "WHERE provider = ? AND itype = ? AND indicator = ?",
                (provider, indicator_type, indicator),
            )
            self._conn.commit()
            return None
        try:
            record: dict[str, Any] = json.loads(record_json)
        except json.JSONDecodeError:
            return None
        record["cached"] = True
        return record

    def put(
        self, provider: str, indicator_type: str, indicator: str, record: IntelRecord
    ) -> None:
        data = record.to_dict()
        data["cached"] = False  # the stored copy is fresh; served copies are marked
        self._conn.execute(
            "INSERT OR REPLACE INTO intel_cache "
            "(provider, itype, indicator, fetched_at, record) "
            "VALUES (?, ?, ?, ?, ?)",
            (provider, indicator_type, indicator, time.time(), json.dumps(data)),
        )
        self._conn.commit()

    def clear(self) -> int:
        cur = self._conn.execute("DELETE FROM intel_cache")
        self._conn.commit()
        return cur.rowcount

    def stats(self) -> dict[str, Any]:
        row = self._conn.execute(
            "SELECT COUNT(*), MIN(fetched_at), MAX(fetched_at) FROM intel_cache"
        ).fetchone()
        return {
            "entries": row[0] if row else 0,
            "oldest_fetched_at": row[1] if row else None,
            "newest_fetched_at": row[2] if row else None,
            "ttl_seconds": self.ttl_seconds,
            "path": str(self.path),
        }
