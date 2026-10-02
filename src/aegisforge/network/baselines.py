"""Scan baselines: save, load, list, and diff port-scan results.

A baseline is a JSON snapshot of one scan stored under the user state
directory (``~/.aegisforge/baselines/<name>.json``). Re-scanning and
diffing surfaces NEW, CLOSED and CHANGED ports — the change-detection
half of the v0.2 port-analysis milestone.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from aegisforge.core.logging import state_dir, utc_now_iso
from aegisforge.network.scanner import OPEN, ScanResult
from aegisforge.network.validation import (
    ValidationError,
    validate_baseline_name,
)

BASELINE_SCHEMA_VERSION = 1


class BaselineError(ValidationError):
    """Raised when a baseline cannot be loaded or parsed."""


def baseline_dir() -> Path:
    """Directory holding baseline files (override via AEGISFORGE_STATE_DIR)."""
    return state_dir() / "baselines"


def _path_for(name: str) -> Path:
    return baseline_dir() / f"{validate_baseline_name(name)}.json"


def _port_record(port_result: Any) -> dict[str, Any]:
    """Compact comparable record for one scanned port."""
    data = (
        port_result.to_dict() if hasattr(port_result, "to_dict") else dict(port_result)
    )
    tls = data.get("tls") or {}
    return {
        "port": data["port"],
        "state": data.get("state"),
        "service": data.get("service"),
        "banner": data.get("banner"),
        "tls_not_after": tls.get("not_after"),
        "http_status": (data.get("http") or {}).get("status_code"),
    }


def save_baseline(name: str, scan: ScanResult) -> Path:
    """Persist *scan* as the baseline called *name*. Overwrites existing."""
    cleaned = validate_baseline_name(name)
    payload = {
        "schema_version": BASELINE_SCHEMA_VERSION,
        "name": cleaned,
        "target": scan.target,
        "resolved_ip": scan.resolved_ip,
        "created": utc_now_iso(),
        "tool": "aegisforge",
        "ports": [_port_record(p) for p in scan.ports],
    }
    path = _path_for(cleaned)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    return path


def load_baseline(name: str) -> dict[str, Any]:
    """Load a baseline; raises BaselineError when missing or corrupt."""
    cleaned = validate_baseline_name(name)
    path = _path_for(cleaned)
    if not path.exists():
        raise BaselineError(
            f"no baseline named {cleaned!r}; "
            "save one with `aegisforge network baseline save`"
        )
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise BaselineError(f"baseline {cleaned!r} is corrupt: {exc}") from exc
    if not isinstance(payload, dict) or "ports" not in payload:
        raise BaselineError(f"baseline {cleaned!r} has an unexpected format")
    return payload


def list_baselines() -> list[dict[str, Any]]:
    """Summaries of all stored baselines, sorted by name."""
    directory = baseline_dir()
    if not directory.exists():
        return []
    summaries = []
    for path in sorted(directory.glob("*.json")):
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        ports = payload.get("ports", []) if isinstance(payload, dict) else []
        summaries.append(
            {
                "name": path.stem,
                "target": payload.get("target") if isinstance(payload, dict) else None,
                "created": payload.get("created")
                if isinstance(payload, dict)
                else None,
                "ports_scanned": len(ports),
                "ports_open": sum(1 for p in ports if p.get("state") == OPEN),
            }
        )
    return summaries


def delete_baseline(name: str) -> bool:
    """Delete a baseline; returns True when something was removed."""
    path = _path_for(name)
    if path.exists():
        path.unlink()
        return True
    return False


@dataclass
class ChangeEntry:
    """One port that differs between baseline and rescan."""

    port: int
    change: str  # "new" | "closed" | "changed"
    previous: dict[str, Any] | None = None
    current: dict[str, Any] | None = None
    detail: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class BaselineDiff:
    """Result of diffing a stored baseline against a fresh scan."""

    name: str
    target: str
    baseline_created: str | None = None
    entries: list[ChangeEntry] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @property
    def summary(self) -> str:
        counts: dict[str, int] = {}
        for entry in self.entries:
            counts[entry.change] = counts.get(entry.change, 0) + 1
        if not counts:
            return "no changes since baseline"
        parts = [
            f"{counts[k]} {k}" for k in ("new", "closed", "changed") if k in counts
        ]
        return ", ".join(parts) + " port(s) since baseline"


def _describe_change(old: dict[str, Any], new: dict[str, Any]) -> str:
    bits = []
    if old.get("service") != new.get("service"):
        bits.append(f"service: {old.get('service')} -> {new.get('service')}")
    if (old.get("banner") or "") != (new.get("banner") or ""):
        bits.append("banner changed")
    if old.get("tls_not_after") != new.get("tls_not_after"):
        bits.append("TLS certificate changed")
    if old.get("http_status") != new.get("http_status"):
        bits.append(
            f"HTTP status: {old.get('http_status')} -> {new.get('http_status')}"
        )
    return "; ".join(bits) or "attributes changed"


def diff_baseline(baseline: dict[str, Any], scan: ScanResult) -> BaselineDiff:
    """Compare a stored baseline against a fresh scan."""
    old_ports = {p["port"]: p for p in baseline.get("ports", [])}
    new_ports = {p.port: _port_record(p) for p in scan.ports}
    entries: list[ChangeEntry] = []
    for port in sorted(set(old_ports) | set(new_ports)):
        old = old_ports.get(port)
        new = new_ports.get(port)
        old_open = bool(old and old.get("state") == OPEN)
        new_open = bool(new and new.get("state") == OPEN)
        if new_open and not old_open:
            assert new is not None
            entries.append(
                ChangeEntry(
                    port=port,
                    change="new",
                    previous=old,
                    current=new,
                    detail=f"port {port} is now open ({new.get('service')})",
                )
            )
        elif old_open and not new_open:
            assert old is not None
            new_state = new.get("state") if new else "unscanned"
            entries.append(
                ChangeEntry(
                    port=port,
                    change="closed",
                    previous=old,
                    current=new,
                    detail=f"port {port} was open ({old.get('service')}) "
                    f"and is now {new_state}",
                )
            )
        elif old_open and new_open and old is not None and new is not None:
            if old != new:
                entries.append(
                    ChangeEntry(
                        port=port,
                        change="changed",
                        previous=old,
                        current=new,
                        detail=_describe_change(old, new),
                    )
                )
    return BaselineDiff(
        name=str(baseline.get("name", "")),
        target=scan.target,
        baseline_created=baseline.get("created"),
        entries=entries,
    )
