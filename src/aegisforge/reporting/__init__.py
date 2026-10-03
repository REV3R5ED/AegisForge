"""Professional reporting (v1.0): JSON/CSV exports, HTML and PDF reports.

The report data model is built in :mod:`aegisforge.reporting.model`,
rendered to HTML (:mod:`aegisforge.reporting.html`) and a minimal
stdlib-only PDF (:mod:`aegisforge.reporting.pdf`), and written to disk
by :mod:`aegisforge.reporting.exports`.

The observed-vs-inferred distinction is carried through every section:
findings keep their observations separate from their inferences, and
the executive summary carries a "what this report does not claim" box.
"""

from __future__ import annotations

from aegisforge.core.plugins import ModuleInfo, register
from aegisforge.reporting import exports, html, model, pdf  # noqa: F401

register(
    ModuleInfo(
        name="reporting",
        description=(
            "Professional reporting: report data model with observed-vs-"
            "inferred findings, executive summaries, methodology, HTML and "
            "stdlib-only PDF rendering, JSON/CSV exports"
        ),
        version="1.0.0",
        commands=[
            "report case",
            "report pcap",
            "report logs",
            "report forensics",
            "report domain",
            "version",
        ],
    )
)

__all__ = ["exports", "html", "model", "pdf"]
