"""Incident-response engine (v0.6): timeline and case management.

Cases are working folders under the AegisForge state directory
(``~/.aegisforge/cases/``, override with ``AEGISFORGE_STATE_DIR``).
Evidence is attached by *copying* source files into the case —
sources are opened for reading only and are never modified, moved
or deleted.

The unified timeline merges every evidence source into one
chronological stream: log events (via the logs/ parsers), file
mtime claims (via the forensics/ inventory) and network scan
events (from AegisForge JSON result envelopes). Events without a
parseable timestamp land in a separate untimed section, never
dropped silently.
"""

from aegisforge.core.plugins import ModuleInfo, register

register(
    ModuleInfo(
        name="cases",
        description=(
            "Incident-response engine: case creation and metadata, "
            "evidence attachment (copied, hashed, read-only sources), "
            "unified timelines across log/file/network evidence, "
            "finding tracking with lifecycle states, indicator linking, "
            "analyst notes and reproducible report artifacts"
        ),
        version="0.6.0",
        commands=[
            "case create",
            "case list",
            "case show",
            "case attach",
            "case timeline",
            "case finding",
            "case findings",
            "case link",
            "case note",
            "case report",
            "case status",
        ],
    )
)
