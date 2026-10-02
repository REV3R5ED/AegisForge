"""Shared result envelope: every command returns this shape.

Human-readable rendering, ``--json`` and ``--csv`` all derive from the
same envelope so automation consumers see a stable contract:

    {
      "tool": "aegisforge",
      "version": "0.1.0",
      "command": "network ping",
      "timestamp": "2026-10-02T22:00:00Z",
      "target": "example.com",
      "status": "ok" | "warning" | "error",
      "summary": "human one-liner",
      "data": {... command-specific ...},
      "findings": [...],
      "events": [...]
    }
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Literal

from aegisforge import __version__
from aegisforge.core.events import Event
from aegisforge.core.findings import Finding
from aegisforge.core.logging import utc_now_iso

Status = Literal["ok", "warning", "error"]


@dataclass
class Result:
    command: str
    target: str | None = None
    status: Status = "ok"
    summary: str = ""
    data: dict[str, Any] = field(default_factory=dict)
    findings: list[Finding] = field(default_factory=list)
    events: list[Event] = field(default_factory=list)
    tool: str = "aegisforge"
    version: str = __version__
    timestamp: str = field(default_factory=utc_now_iso)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        return d

    def add_finding(self, finding: Finding) -> None:
        self.findings.append(finding)
        if self.status == "ok":
            self.status = "warning"

    def add_event(self, event: Event) -> None:
        self.events.append(event)

    def fail(self, summary: str) -> None:
        self.status = "error"
        self.summary = summary


# Structured exit codes shared by every command.
EXIT_OK = 0  # success, nothing of concern
EXIT_FINDINGS = 1  # success, but findings/warnings were produced
EXIT_ERROR = 2  # usage or operational error


def exit_code_for(result: Result) -> int:
    if result.status == "error":
        return EXIT_ERROR
    if result.status == "warning":
        return EXIT_FINDINGS
    return EXIT_OK
