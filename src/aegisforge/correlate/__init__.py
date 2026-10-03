"""Correlation engine (v0.9): entity normalization, cross-source matching,
temporal correlation, evidence-backed relationships, explainable scoring,
and incident timelines.

Everything here is read-only over cases and evidence: correlation builds
an in-memory entity graph from case evidence (logs, network, files,
findings) and reports pivots — entities observed in multiple sources —
with transparent, arithmetic confidence scores. Scores describe the
strength of the *observation*, never causation.
"""

from aegisforge.core.plugins import ModuleInfo, register

register(
    ModuleInfo(
        name="correlate",
        description=(
            "Correlation engine: entity normalization (ip/domain/url/hash/"
            "user/hostname), in-memory entity graph over case evidence, "
            "cross-source pivot detection, temporal correlation, "
            "evidence-backed relationships, explainable confidence scores, "
            "and incident timeline generation"
        ),
        version="0.9.0",
        commands=[
            "correlate run",
            "correlate entities",
            "correlate timeline",
        ],
    )
)
