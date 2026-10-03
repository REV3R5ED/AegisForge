"""Log analysis module (v0.4): parsers and normalized event model.

Heterogeneous logs — syslog (RFC 3164/5424), Apache/Nginx access logs,
JSON lines, Windows Event Log XML exports, generic key=value — are
parsed in a streaming fashion (never loaded wholly into memory) and
normalized into :class:`LogEvent`, the AegisForge-native log event
model. Analysis (timeline, top talkers, histograms, burst detection)
and detection findings build on top of it.

Later phases (correlation, cases) consume the normalized events.
"""

from aegisforge.core.plugins import ModuleInfo, register

register(
    ModuleInfo(
        name="logs",
        description=(
            "Log analysis: streaming parsers for syslog (RFC 3164/5424), "
            "Apache/Nginx access logs, JSON lines, Windows Event Log XML "
            "exports and key=value; format auto-detection; timeline, top "
            "talkers, histograms, error extraction and burst detection "
            "with observed-vs-inferred findings"
        ),
        version="0.5.0",
        commands=[
            "logs detect",
            "logs analyze",
        ],
    )
)
