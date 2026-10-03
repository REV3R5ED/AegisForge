"""Digital forensics module (v0.4): file inventory, hashing, evidence manifests.

Evidence is treated as **read-only**: this module opens files for reading
only and never modifies, moves, or deletes anything under the scanned
root. All timestamps are filesystem metadata (UTC ISO-8601) — they
describe the filesystem's claims about a file, not the file's content.
"""

from aegisforge.core.plugins import ModuleInfo, register

register(
    ModuleInfo(
        name="forensics",
        description=(
            "Digital forensics: recursive file inventory with magic-byte "
            "identification, single-pass multi-algorithm hashing (SHA-256, "
            "MD5, SHA-1), evidence manifests with tamper-evidence hashing, "
            "manifest verification (changed/missing/new), duplicate "
            "detection and filesystem timelines"
        ),
        version="0.4.0",
        commands=[
            "forensics inventory",
            "forensics manifest",
            "forensics verify",
            "forensics duplicates",
            "forensics timeline",
        ],
    )
)
