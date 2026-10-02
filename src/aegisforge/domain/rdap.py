"""RDAP lookups via the stdlib :mod:`urllib`.

The authoritative RDAP server for a TLD is discovered through the IANA
bootstrap file (https://data.iana.org/rdap/dns.json), then queried for
the domain's registration record: registrar, status, lifecycle events
and nameservers. All HTTP is bounded (timeout + size cap); any failure
degrades gracefully to an error note — the caller decides whether to
fall back to WHOIS.
"""

from __future__ import annotations

import json
import ssl
import urllib.error
import urllib.request
from dataclasses import asdict, dataclass, field
from typing import Any

IANA_DNS_BOOTSTRAP = "https://data.iana.org/rdap/dns.json"
IANA_IP_BOOTSTRAP = "https://data.iana.org/rdap/ipv4.json"
_MAX_BODY_BYTES = 1_000_000


class RDAPError(Exception):
    """Raised when an RDAP lookup cannot complete."""


@dataclass
class RDAPResult:
    """Parsed registration data for one domain."""

    domain: str
    rdap_server: str | None = None
    registrar: str | None = None
    status: list[str] = field(default_factory=list)
    events: dict[str, str] = field(default_factory=dict)
    nameservers: list[str] = field(default_factory=list)
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _https_get_json(url: str, timeout: float) -> dict[str, Any]:
    """GET *url* over HTTPS and parse the JSON body (size-capped)."""
    context = ssl.create_default_context()
    request = urllib.request.Request(
        url, headers={"Accept": "application/rdap+json, application/json"}
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout, context=context) as reply:
            raw = reply.read(_MAX_BODY_BYTES + 1)
    except (urllib.error.URLError, OSError, ssl.SSLError, TimeoutError) as exc:
        raise RDAPError(f"HTTPS request to {url} failed: {exc}") from exc
    if len(raw) > _MAX_BODY_BYTES:
        raise RDAPError(f"response from {url} exceeds size cap")
    try:
        parsed = json.loads(raw.decode("utf-8", errors="replace"))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise RDAPError(f"could not parse RDAP JSON from {url}: {exc}") from exc
    if not isinstance(parsed, dict):
        raise RDAPError(f"unexpected RDAP payload from {url}")
    return parsed


def find_rdap_server(
    domain: str, timeout: float = 5.0, bootstrap_url: str = IANA_DNS_BOOTSTRAP
) -> str | None:
    """Find the authoritative RDAP server for *domain*'s TLD.

    Returns the server base URL (with trailing slash) or None when the
    bootstrap cannot be fetched or lists no match.
    """
    payload = _https_get_json(bootstrap_url, timeout)
    services = payload.get("services")
    if not isinstance(services, list):
        raise RDAPError("IANA bootstrap has no services list")
    needle = domain.strip().lower().rstrip(".")
    best: tuple[int, str] | None = None
    for entry in services:
        if not isinstance(entry, list) or len(entry) != 2:
            continue
        suffixes, urls = entry
        if not isinstance(suffixes, list) or not isinstance(urls, list) or not urls:
            continue
        for suffix in suffixes:
            if not isinstance(suffix, str):
                continue
            clean = suffix.lower().rstrip(".")
            if needle == clean or needle.endswith("." + clean):
                candidate = (len(clean), str(urls[0]))
                if best is None or candidate[0] > best[0]:
                    best = candidate
    if best is None:
        return None
    server = best[1]
    return server if server.endswith("/") else server + "/"


def _vcard_name(entity: dict[str, Any]) -> str | None:
    vcard = entity.get("vcardArray")
    if isinstance(vcard, list) and len(vcard) == 2 and isinstance(vcard[1], list):
        for item in vcard[1]:
            if isinstance(item, list) and len(item) >= 4 and item[0] == "fn":
                return str(item[3])
    return entity.get("handle")


def rdap_lookup(
    domain: str, timeout: float = 10.0, rdap_server: str | None = None
) -> RDAPResult:
    """Look up *domain* via RDAP; degrade gracefully on any failure."""
    result = RDAPResult(domain=domain)
    try:
        server = rdap_server or find_rdap_server(domain, timeout=min(timeout, 10.0))
    except RDAPError as exc:
        result.error = f"RDAP bootstrap lookup failed: {exc}"
        return result
    if not server:
        result.error = "no authoritative RDAP server found in IANA bootstrap"
        return result
    result.rdap_server = server
    try:
        payload = _https_get_json(f"{server}domain/{domain}", timeout)
    except RDAPError as exc:
        result.error = f"RDAP query failed: {exc}"
        return result
    status = payload.get("status")
    if isinstance(status, list):
        result.status = [str(item) for item in status]
    events = payload.get("events")
    if isinstance(events, list):
        for event in events:
            if not isinstance(event, dict):
                continue
            action = event.get("eventAction")
            date = event.get("eventDate")
            if isinstance(action, str) and isinstance(date, str):
                result.events[action] = date
    for entity in payload.get("entities", []) or []:
        if not isinstance(entity, dict):
            continue
        roles = entity.get("roles") or []
        if "registrar" in roles and result.registrar is None:
            result.registrar = _vcard_name(entity)
    nameservers = payload.get("nameservers")
    if isinstance(nameservers, list):
        for item in nameservers:
            if isinstance(item, dict) and isinstance(item.get("ldhName"), str):
                result.nameservers.append(item["ldhName"])
    return result
