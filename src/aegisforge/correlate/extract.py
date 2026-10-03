"""Entity extraction from case evidence.

Each evidence kind contributes entity observations:

- ``logs``: parsed with the logs/ format auto-detection and streaming
  parsers (the same path as the case timeline). From every log event we
  extract IPs, users and domains from the message, plus the log host
  as a hostname. Entities seen in the same event become
  ``observed-together`` edges.
- ``network``: pcap files go through ``pcap.extract_indicators``;
  AegisForge JSON envelopes are scanned for entity-shaped strings in
  their events. Anything else yields no entities (never a crash).
- ``files``: the file's own SHA-256 becomes a ``hash`` entity.
- findings: linked indicators become entities sourced to the finding.

Extraction is read-only: evidence files are opened for reading only,
and a missing or unreadable file simply contributes nothing.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from pathlib import Path
from typing import Any

from aegisforge.cases.models import CaseMetadata
from aegisforge.cases.store import case_dir
from aegisforge.correlate.entities import normalize_entity
from aegisforge.correlate.models import Edge, Entity, Observation
from aegisforge.logs import detect as detect_mod
from aegisforge.logs.models import PARSER_UNKNOWN, LogEvent
from aegisforge.logs.parsers import get_parser, iter_parsed_file

_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_FQDN_RE = re.compile(
    r"\b(?=[a-z0-9.-]{4,253}\b)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"[a-z]{2,}\b",
    re.IGNORECASE,
)
_USER_PATTERNS = (
    re.compile(r"Failed password for (?:invalid user )?(\S+)", re.IGNORECASE),
    re.compile(r"Accepted \S+ for (\S+)", re.IGNORECASE),
    re.compile(r"\buser[=:]\s*([^\s,;'\"]+)", re.IGNORECASE),
    re.compile(r"account\s+[\"']([^\"']+)[\"']", re.IGNORECASE),
)


def _valid_ipv4(text: str) -> str | None:
    try:
        addr = ipaddress.ip_address(text)
    except ValueError:
        return None
    return str(addr) if addr.version == 4 else None


def extract_from_text(text: str) -> list[Entity]:
    """Entities found in free text: IPs, users, domains (deduped)."""
    found: dict[tuple[str, str], Entity] = {}
    for match in _IPV4_RE.finditer(text):
        ip = _valid_ipv4(match.group(0))
        if ip:
            found[("ip", ip)] = Entity(value=ip, type="ip")
    for pattern in _USER_PATTERNS:
        for match in pattern.finditer(text):
            entity = normalize_entity(match.group(1), type_hint="user")
            if entity is not None:
                found[entity.key()] = entity
    for match in _FQDN_RE.finditer(text):
        entity = normalize_entity(match.group(0), type_hint="domain")
        if entity is not None:
            found[entity.key()] = entity
    return list(found.values())


def _log_observations(
    case: CaseMetadata, record: Any, stored: Path
) -> tuple[list[Observation], list[Edge]]:
    """Observations (and co-occurrence edges) from a logs evidence file."""
    observations: list[Observation] = []
    edges: list[Edge] = []
    try:
        detection = detect_mod.detect_file(str(stored))
    except OSError:
        return observations, edges
    if detection.parser == PARSER_UNKNOWN:
        return observations, edges
    parser = get_parser(detection.parser)
    label = f"logs:{stored.name}"
    try:
        items = iter_parsed_file(str(stored), parser)
    except OSError:
        return observations, edges
    for item in items:
        if not isinstance(item, LogEvent):
            continue
        entities = extract_from_text(item.message or "")
        if item.host:
            host = normalize_entity(item.host, type_hint="hostname")
            if host is not None and host.key() not in {e.key() for e in entities}:
                entities.append(host)
        line_ref = f"line {item.line_number}" if item.line_number else "log event"
        for entity in entities:
            observations.append(
                Observation(
                    entity=entity,
                    source_type="logs",
                    source_label=label,
                    evidence_id=record.evidence_id,
                    timestamp=item.timestamp,
                    detail=line_ref,
                )
            )
        # Entities in the same event were observed together.
        for i, first in enumerate(entities):
            for second in entities[i + 1 :]:
                edges.append(
                    Edge(
                        entity_a=first,
                        entity_b=second,
                        evidence_refs=[f"{label} [{record.evidence_id}] {line_ref}"],
                        timestamps=[item.timestamp],
                    )
                )
    return observations, edges


def _is_pcap(path: Path) -> bool:
    try:
        with open(path, "rb") as fh:
            magic = fh.read(4)
    except OSError:
        return False
    return magic in (
        b"\xd4\xc3\xb2\xa1",  # LE microsecond
        b"\xa1\xb2\xc3\xd4",  # BE microsecond
        b"\x4d\x3c\xb2\xa1",  # LE nanosecond
        b"\xa1\xb2\x3c\x4d",  # BE nanosecond
    )


def _network_observations(
    case: CaseMetadata, record: Any, stored: Path
) -> list[Observation]:
    """Observations from a network evidence file (pcap or JSON envelope)."""
    from aegisforge.pcap import analyze as pcap_analyze_mod
    from aegisforge.pcap.analyze import AnalyzeOptions

    observations: list[Observation] = []
    label = f"network:{stored.name}"
    if _is_pcap(stored):
        try:
            result = pcap_analyze_mod.extract_indicators(str(stored), AnalyzeOptions())
        except Exception:  # noqa: BLE001 - a broken capture never blocks correlation
            return observations
        for item in result.indicators:
            entity = normalize_entity(item.value, type_hint=item.itype)
            if entity is None:
                continue
            observations.append(
                Observation(
                    entity=entity,
                    source_type="network",
                    source_label=label,
                    evidence_id=record.evidence_id,
                    timestamp=item.first_seen or None,
                    detail=f"pcap indicator ({item.observation})",
                )
            )
        return observations
    # AegisForge JSON envelope: scan event strings for entity shapes.
    try:
        envelope = json.loads(stored.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return observations
    if not isinstance(envelope, dict) or "events" not in envelope:
        return observations
    for event in envelope.get("events", []):
        if not isinstance(event, dict):
            continue
        ts = event.get("timestamp") if isinstance(event.get("timestamp"), str) else None
        for value in event.values():
            if not isinstance(value, str) or len(value) > 256:
                continue
            for entity in extract_from_text(value):
                observations.append(
                    Observation(
                        entity=entity,
                        source_type="network",
                        source_label=label,
                        evidence_id=record.evidence_id,
                        timestamp=ts,
                        detail="network scan event",
                    )
                )
    return observations


def _file_observations(
    case: CaseMetadata, record: Any, stored: Path
) -> list[Observation]:
    """The file's own SHA-256 becomes a hash entity."""
    try:
        digest = hashlib.sha256(stored.read_bytes()).hexdigest()
    except OSError:
        return []
    try:
        mtime = stored.stat().st_mtime
    except OSError:
        mtime = None
    from datetime import datetime, timezone

    ts = (
        datetime.fromtimestamp(mtime, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        if mtime is not None
        else None
    )
    return [
        Observation(
            entity=Entity(value=digest, type="hash"),
            source_type="files",
            source_label=f"files:{stored.name}",
            evidence_id=record.evidence_id,
            timestamp=ts,
            detail="sha256 of evidence file",
        )
    ]


def _finding_observations(case: CaseMetadata) -> list[Observation]:
    """Entities from indicators linked to case findings."""
    observations: list[Observation] = []
    for finding in case.findings:
        for link in finding.indicators:
            entity = normalize_entity(link.value)
            if entity is None:
                continue
            observations.append(
                Observation(
                    entity=entity,
                    source_type="findings",
                    source_label=f"findings:{finding.finding_id}",
                    evidence_id=finding.finding_id,
                    timestamp=finding.created,
                    detail=f"indicator linked to finding ({link.type_source} type)",
                )
            )
    return observations


def extract_observations(
    case: CaseMetadata,
) -> tuple[list[Observation], list[Edge], list[str]]:
    """All entity observations (and edges) for a case.

    Returns ``(observations, edges, warnings)``. Read-only: evidence
    files are never written, and unreadable files are skipped with a
    warning, never an exception.
    """
    observations: list[Observation] = []
    edges: list[Edge] = []
    warnings: list[str] = []
    base = case_dir(case.case_id)
    for record in case.evidence:
        stored = base / record.stored_path
        if not stored.exists():
            warnings.append(f"evidence {record.evidence_id} missing on disk; skipped")
            continue
        if record.kind == "logs":
            obs, edg = _log_observations(case, record, stored)
            observations.extend(obs)
            edges.extend(edg)
        elif record.kind == "network":
            observations.extend(_network_observations(case, record, stored))
        elif record.kind == "files":
            observations.extend(_file_observations(case, record, stored))
        else:  # pragma: no cover - kinds are validated at attach time
            warnings.append(
                f"evidence {record.evidence_id}: unknown kind {record.kind!r}"
            )
    observations.extend(_finding_observations(case))
    return observations, edges, warnings
