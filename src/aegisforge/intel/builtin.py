"""Built-in intel providers (all stdlib, all opt-in).

- ``local-blocklist`` — user-supplied CSV blocklist (local file read;
  works fully offline). A blocklist hit means verdict ``malicious``.
- ``team-cymru`` — IP → ASN/org via Team Cymru's DNS service (reuses the
  v0.3 lookup). ASN data is *ownership*, not reputation, so the verdict
  is always ``unknown`` with high data confidence.
- ``dns-resolve`` — forward-resolves domains to their current IPs.
  The record says "currently resolves to" — never a verdict.
- ``http-reputation-stub`` — a clearly labeled STUB showing the
  provider interface for API-backed sources. It never makes network
  calls and always reports "not configured": subclass
  :class:`~aegisforge.intel.providers.IntelProvider` to add a real API
  provider. API keys come from environment variables only.

Network providers (``team-cymru``, ``dns-resolve``) run only when the
provider is configured *and* the user passed ``--enrich``.
"""

from __future__ import annotations

import csv
import os
import socket
from typing import Any

from aegisforge.core.logging import utc_now_iso
from aegisforge.intel.models import IntelRecord, NormalizedIndicator
from aegisforge.intel.normalize import normalize_indicator
from aegisforge.intel.providers import IntelProvider, register_provider


@register_provider
class LocalBlocklistProvider(IntelProvider):
    """CSV blocklist on local disk.

    CSV columns: ``indicator,type,source,confidence,note`` (header row
    required). A hit returns verdict ``malicious`` — that is what a
    blocklist means — with the CSV's confidence (default 80) and source.
    """

    name = "local-blocklist"
    supported_types = ("ip", "domain", "url", "hash")
    network = False
    default_confidence = 80

    def __init__(self) -> None:
        super().__init__()
        self._entries: dict[tuple[str, str], dict[str, str]] = {}
        self._path = ""
        self._load_ok = False

    def configure(self, config: dict[str, Any]) -> None:
        super().configure(config)
        path = str(config.get("path", "") or "")
        if path and path != self._path:
            entries, ok = self._load(path)
            self._entries = entries
            self._load_ok = ok
            self._path = path

    def _load(self, path: str) -> tuple[dict[tuple[str, str], dict[str, str]], bool]:
        entries: dict[tuple[str, str], dict[str, str]] = {}
        try:
            with open(path, encoding="utf-8", newline="") as fh:
                reader = csv.DictReader(fh)
                for row in reader:
                    raw = (row.get("indicator") or "").strip()
                    if not raw:
                        continue
                    norm = normalize_indicator(raw)
                    if norm.rejected:
                        continue
                    key = (norm.type, norm.value)
                    entries[key] = {
                        "type": (row.get("type") or "").strip(),
                        "source": (row.get("source") or "local blocklist").strip(),
                        "confidence": (row.get("confidence") or "").strip(),
                        "note": (row.get("note") or "").strip(),
                    }
        except OSError:
            return {}, False
        return entries, True

    def is_configured(self) -> bool:
        return bool(self._path) and self._load_ok

    def lookup(self, indicator: NormalizedIndicator) -> IntelRecord:
        entry = self._entries.get((indicator.type, indicator.value))
        if entry is None and indicator.type == "url" and indicator.domain:
            # A URL matches when its domain is blocklisted.
            entry = self._entries.get(("domain", indicator.domain))
        if entry is None:
            return IntelRecord(
                indicator=indicator.value,
                indicator_type=indicator.type,
                provider=self.name,
                verdict="unknown",
                confidence=self.default_confidence,
                detail="not present in the local blocklist",
            )
        try:
            confidence = int(entry["confidence"])
        except ValueError:
            confidence = self.default_confidence
        confidence = max(0, min(100, confidence))
        return IntelRecord(
            indicator=indicator.value,
            indicator_type=indicator.type,
            provider=self.name,
            verdict="malicious",
            confidence=confidence,
            detail=(
                f"blocklisted by {entry['source']}"
                + (f": {entry['note']}" if entry["note"] else "")
            ),
            raw={"blocklist_entry": entry},
        )


@register_provider
class TeamCymruProvider(IntelProvider):
    """IP → ASN/org ownership via Team Cymru's DNS service.

    DNS-based, no API key. The answer is *ownership data*, not
    reputation: the verdict is always ``unknown``. Requires ``--enrich``.
    """

    name = "team-cymru"
    supported_types = ("ip",)
    network = True
    default_confidence = 90

    def is_configured(self) -> bool:
        # DNS-based: no key needed; enabled by being selected + --enrich.
        return True

    def lookup(self, indicator: NormalizedIndicator) -> IntelRecord:
        from aegisforge.domain.asn import asn_lookup

        info = asn_lookup(indicator.value)
        if info.error:
            return IntelRecord(
                indicator=indicator.value,
                indicator_type=indicator.type,
                provider=self.name,
                verdict="unknown",
                confidence=0,
                detail=f"Team Cymru lookup failed: {info.error}",
                raw={"error": info.error},
            )
        detail = " | ".join(
            part
            for part in (
                f"AS{info.asn}" if info.asn else None,
                info.prefix,
                info.country,
                info.registry,
            )
            if part
        )
        return IntelRecord(
            indicator=indicator.value,
            indicator_type=indicator.type,
            provider=self.name,
            verdict="unknown",
            confidence=self.default_confidence,
            detail=f"ownership data (not reputation): {detail or 'no data'}",
            raw={
                "asn": info.asn,
                "prefix": info.prefix,
                "country": info.country,
                "registry": info.registry,
                "allocated": info.allocated,
            },
        )


@register_provider
class DnsResolveProvider(IntelProvider):
    """Forward-resolve a domain to its current IPs (stdlib socket).

    The record is labeled "currently resolves to" — resolution is an
    observation, never a verdict. Requires ``--enrich``.
    """

    name = "dns-resolve"
    supported_types = ("domain",)
    network = True
    default_confidence = 70

    def is_configured(self) -> bool:
        return True

    def lookup(self, indicator: NormalizedIndicator) -> IntelRecord:
        try:
            infos = socket.getaddrinfo(indicator.value, None, type=socket.SOCK_STREAM)
        except OSError as exc:
            return IntelRecord(
                indicator=indicator.value,
                indicator_type=indicator.type,
                provider=self.name,
                verdict="unknown",
                confidence=0,
                detail=f"DNS resolution failed: {exc}",
                raw={"error": str(exc)},
            )
        ips = sorted({str(info[4][0]) for info in infos})
        if not ips:
            return IntelRecord(
                indicator=indicator.value,
                indicator_type=indicator.type,
                provider=self.name,
                verdict="unknown",
                confidence=0,
                detail="domain did not resolve",
            )
        return IntelRecord(
            indicator=indicator.value,
            indicator_type=indicator.type,
            provider=self.name,
            verdict="unknown",
            confidence=self.default_confidence,
            detail=f"currently resolves to: {', '.join(ips)}",
            raw={"resolved_ips": ips, "resolved_at": utc_now_iso()},
        )


@register_provider
class HttpReputationStubProvider(IntelProvider):
    """STUB for API-backed reputation providers.

    This provider demonstrates the interface without shipping any API
    key or making any network call. To add a real provider, subclass
    :class:`~aegisforge.intel.providers.IntelProvider`, read the API key
    from an environment variable (e.g.
    ``AEGISFORGE_INTEL_<NAME>_API_KEY``), implement ``lookup``, and call
    :func:`~aegisforge.intel.providers.register_provider`.
    """

    name = "http-reputation-stub"
    supported_types = ("ip", "domain", "url", "hash")
    network = False
    default_confidence = 50

    #: Environment variable a real implementation would read its key from.
    api_key_env = "AEGISFORGE_INTEL_REPUTATION_API_KEY"

    def is_configured(self) -> bool:
        # A stub is never "configured": there is no real backend.
        return False

    def lookup(self, indicator: NormalizedIndicator) -> IntelRecord:
        key_present = bool(os.environ.get(self.api_key_env))
        return IntelRecord(
            indicator=indicator.value,
            indicator_type=indicator.type,
            provider=self.name,
            verdict="no-verdict",
            confidence=0,
            detail=(
                "STUB provider: not configured — no API backend. "
                f"Set {self.api_key_env} and implement a real provider; "
                f"API key present in environment: {'yes' if key_present else 'no'}."
            ),
        )
