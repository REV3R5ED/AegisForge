# Changelog

All notable changes to this project will be documented in this file.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

## [0.5.0] - 2026-10-02

### Added

- Log analysis module (`logs/`, v0.5): `aegisforge logs detect FILE`
  auto-detects the format (syslog RFC 3164/5424, Apache/Nginx combined
  and common, JSON lines, Windows Event Log XML exports, generic
  key=value) and reports the chosen parser with confidence scores;
  `aegisforge logs analyze FILE` streams the file (never loaded wholly
  into memory) and builds a UTC timeline, severity and HTTP-status
  histograms, top talkers (IPs/hosts), error extraction with context
  lines, and burst detection with configurable window/threshold.
- Composable filters: `--since`/`--until`, `--level`, `--contains`/
  `--not-contains`, `--host`, `--limit`; malformed lines become
  warnings with line numbers, never crash the parse.
- Detections feed `core/findings.py` with the observed-vs-inferred
  discipline: auth-failure bursts (syslog patterns + Windows 4625),
  HTTP 5xx spikes, and exception clusters. A burst of 404s is
  *observed*; calling it an attack is *inferred* — labeled as such in
  every finding reason.
- `--redact` flag masks IPv4/IPv6 addresses and email-like tokens in
  *output only* (human, `--json`, `--csv`); source files are never
  modified and in-memory analysis keeps original values.
- New config knobs: `logs_burst_window`, `logs_burst_threshold`,
  `logs_context_lines`.
- Scenario guide (`docs/USAGE.md`) extended with a log-analysis step
  and a real terminal screenshot.

## [0.3.0] - 2026-10-02

### Added

- Domain investigation module (`domain/`, v0.3): `aegisforge domain
  investigate DOMAIN` runs a consolidated passive report — DNS record
  collection, reverse DNS, nameserver/MX analysis, DNSSEC presence, TLS
  certificate inspection, RDAP (with WHOIS fallback), ASN ownership and
  HTTP/HTTPS header/redirect collection — with per-section findings that
  keep the observed-vs-inferred discipline.
- Minimal DNS wire-protocol client (`domain/dns_client.py`, stdlib
  only): `struct`-built queries and hand-parsed answers (with
  compression-pointer handling) for A, AAAA, MX, NS, TXT, SOA, CNAME,
  DNSKEY and DS over UDP with automatic TCP retry on truncation.
  `socket.getaddrinfo` only exposes A/AAAA/PTR, so the raw client is the
  point. Failed queries become warnings, never crashes.
- `aegisforge domain dns NAME [--type MX] [--resolver IP]`: single
  record-type queries through the wire client, with `--json`/`--csv`.
- Nameserver analysis (`domain/nameservers.py`): lists NS records,
  resolves each to A/AAAA, flags nameservers with no addresses as
  possible lame delegations.
- MX analysis (`domain/mx.py`): exchangers ordered by preference with
  address resolution; null MX (RFC 7505) noted explicitly.
- DNSSEC presence reporting (`domain/dnssec.py`): DNSKEY/DS publication
  reported as present/partial/absent. Chain validation is deliberately
  out of scope — the report says what is published, never claims
  validation.
- RDAP (`domain/rdap.py`): IANA bootstrap discovery + domain lookup via
  stdlib `urllib` (registrar, status, lifecycle events, nameservers);
  bounded reads, graceful degradation when offline.
- WHOIS fallback (`domain/whois.py`): TCP port 43 with one referral
  level, best-effort field extraction; raw text always kept.
- ASN/IP ownership (`domain/asn.py`): Team Cymru DNS TXT lookups
  (`origin.asn.cymru.com`), reusing the wire client — no API key, no
  extra protocol.
- HTTP/HTTPS collection (`domain/web.py`): `http.client` header fetch
  with manual redirect following (max 5), Server header, final URL;
  bodies never read.
- Safety distinction documented in README: domain investigation is
  passive directory lookups (no `--allow-remote` gate), unlike v0.2's
  active port scanning.
- New config knobs: `domain_dns_timeout`, `domain_resolver`,
  `domain_http_timeout`, `rdap_timeout`, `whois_timeout`.
- Domain module registered in `core/plugins.py` as v0.3.0 with
  `domain dns` and `domain investigate` commands.

## [0.2.0] - 2026-10-02

### Added

- Authorized TCP port/service analysis (`network/scan*.py`):
  `aegisforge network scan TARGET` with `--ports 22,80,443` and/or
  `--port-range 1-1024`, bounded ThreadPoolExecutor (default 50, hard
  max 100), per-connection timeouts with configurable retries,
  open/closed/filtered states with per-port RTT.
- Active-scan safety: loopback/private/link-local targets scan by
  default; globally routable targets (every resolved address checked)
  require explicit `--allow-remote`, otherwise refused with a clear
  error (exit 2). All invocations audit-logged.
- Service identification and banner grabbing (`network/services.py`):
  passive banners for SSH/SMTP/FTP-style services, minimal HEAD
  request for HTTP-ish ports, size-capped reads, sanitized one-line
  display, port-map fallback.
- TLS certificate inspection (`network/tls.py`): subject/issuer,
  validity window, days-until-expiry, SANs, protocol/cipher, and
  wildcard-aware hostname verification. Non-verifying capture context
  by design — the scanner records what the peer presents.
  Findings raised for expired (high) and soon-expiring (medium, ≤30d)
  certificates.
- HTTP/HTTPS metadata (`network/http.py`): status line, server header,
  redirect targets, content type — parsed from the already-captured
  response head, no extra connections.
- Scan baselines with change detection (`network/baselines.py`):
  `network baseline save/diff/list/show/delete`, JSON snapshots under
  `~/.aegisforge/baselines/`, diffs report NEW / CLOSED / CHANGED
  ports; new/closed ports raise findings on diff.
- New config knobs: `scan_timeout`, `scan_retries`,
  `scan_max_parallel`, `scan_banner_timeout`, `scan_max_ports`.
- Network module re-registered in `core/plugins.py` as v0.2.0 with
  `network scan` and `network baseline` commands.

### Changed

- Version bumped to 0.2.0 across package, CLI, and plugin registry.

## [0.1.0] - 2026-10-02

### Added

- Core foundation: JSON config profiles (`core/config.py`), normalized
  UTC event model (`core/events.py`), findings with severity/confidence
  (`core/findings.py`), evidence with chain-of-custody and sha256
  (`core/evidence.py`), module registry with entry-point discovery stub
  (`core/plugins.py`), centralized logging and audit log
  (`core/logging.py`), shared result envelope and exit codes
  (`core/results.py`).
- Trial license seam (`core/license.py`): first-run timestamp tracking,
  days-remaining status, friendly startup notice on stderr, dormant
  `LicenseExpiredError` and license-key validation stub (no enforcement
  in v0.1).
- Network discovery module: IPv4/IPv6 subnet calculator with bounded
  CIDR expansion, ICMP ping via OS utility (single + concurrent, max 20
  workers), forward/reverse DNS via stdlib socket, bounded traceroute,
  cross-platform interface/route/neighbour discovery, local asset
  inventory.
- CLI: `aegisforge network {subnet,ping,dns,trace,interfaces,inventory}`,
  `aegisforge config show`; human-readable default output, `--json` and
  `--csv` modes; structured exit codes 0/1/2; audit logging of every
  invocation; `--version`, `--verbose`, `--config`, `--profile`.
- Proprietary commercial license with 7-day free trial (see LICENSE).
- Docs: README, CHANGELOG, SECURITY, CONTRIBUTING.
- Packaging: `pyproject.toml` (stdlib-only, Python 3.10–3.13), console
  script + `python -m aegisforge`, ruff/mypy/coverage/pytest tooling.
- CI: ruff, mypy, pytest across 3.10–3.13 on ubuntu, a Windows smoke
  job, build + twine check, Dependabot.
- 97 pytest tests with mocked subprocess/network (no real network in
  tests); coverage gate 80%.
