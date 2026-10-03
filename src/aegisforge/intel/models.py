"""Intel data models: normalized indicators and intel records.

An :class:`IntelRecord` carries a verdict drawn from a strictly limited
vocabulary. This is enforced in :meth:`IntelRecord.__post_init__` so no
provider — built-in or third-party — can smuggle in rogue verdict words
like "evil" or "bad". The vocabulary is:

- ``unknown`` — provider has no information
- ``clean`` — provider reports no malicious association
- ``suspicious`` — provider reports a weak/possible association
- ``malicious`` — provider reports a strong association
- ``no-verdict`` — provider did not return a verdict (machine-readable
  form of "provider did not return a verdict")

A verdict describes what the *provider* reported about the indicator. It
is never, by itself, a conclusion about the indicator's role in an
investigation — that inference belongs in findings.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

from aegisforge.core.logging import utc_now_iso

INDICATOR_TYPES = ("ip", "domain", "url", "hash")

VERDICTS = ("unknown", "clean", "suspicious", "malicious")
NO_VERDICT = "no-verdict"
NO_VERDICT_LABEL = "provider did not return a verdict"

HASH_LENGTHS = {32: "md5", 40: "sha1", 64: "sha256"}


@dataclass
class NormalizedIndicator:
    """One indicator after normalization.

    ``value`` is the canonical form (lowercased domain, refanged URL/IP,
    validated hash). ``original`` is the raw input. ``domain`` is set for
    ``url`` indicators (the extracted host); ``url`` keeps the full URL.
    ``defanged`` records that the input was obfuscated (``hxxp://``,
    ``1.2.3[.]4``) and had to be refanged — always labeled, never silent.
    """

    value: str
    type: str
    original: str
    domain: str | None = None
    url: str | None = None
    hash_kind: str | None = None
    defanged: bool = False
    rejected: bool = False
    reject_reason: str = ""

    def __post_init__(self) -> None:
        if self.rejected:
            # Rejected indicators carry the raw input for reporting; the
            # type/value are placeholders and are not validated.
            return
        if self.type not in INDICATOR_TYPES:
            raise ValueError(
                f"indicator type must be one of {INDICATOR_TYPES}, got {self.type!r}"
            )
        if not self.value:
            raise ValueError("normalized indicator value must not be empty")

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class IntelRecord:
    """One provider's answer about one indicator.

    ``verdict`` is restricted to :data:`VERDICTS` plus :data:`NO_VERDICT`;
    anything else raises :class:`ValueError`. ``confidence`` (0-100) scores
    the provider's certainty in its own data, not a judgment of intent.
    ``raw`` keeps the provider's original response verbatim. ``cached``
    marks records served from the local cache rather than a live lookup.
    """

    indicator: str
    indicator_type: str
    provider: str
    verdict: str = NO_VERDICT
    confidence: int = 50
    detail: str = ""
    raw: dict[str, Any] = field(default_factory=dict)
    cached: bool = False
    skipped: bool = False
    skip_reason: str = ""
    looked_up_at: str = field(default_factory=utc_now_iso)

    def __post_init__(self) -> None:
        allowed = (*VERDICTS, NO_VERDICT)
        if self.verdict not in allowed:
            raise ValueError(
                f"verdict must be one of {allowed}, got {self.verdict!r} "
                f"(provider {self.provider!r})"
            )
        if not 0 <= self.confidence <= 100:
            raise ValueError(f"confidence must be 0-100, got {self.confidence!r}")
        if self.indicator_type not in INDICATOR_TYPES:
            raise ValueError(
                f"indicator type must be one of {INDICATOR_TYPES}, "
                f"got {self.indicator_type!r}"
            )

    def verdict_label(self) -> str:
        """Human-readable verdict (expands the ``no-verdict`` sentinel)."""
        if self.verdict == NO_VERDICT:
            return NO_VERDICT_LABEL
        return self.verdict

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["verdict_label"] = self.verdict_label()
        return d
