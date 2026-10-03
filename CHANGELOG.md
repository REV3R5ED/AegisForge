# Changelog

All notable changes to this project will be documented in this file.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

## [0.9.0] - 2026-10-03

### Added

- Correlation engine (`correlate/`, v0.9): entity normalization, an
  in-memory entity graph, cross-source pivot detection, temporal
  correlation, explainable scoring, and incident timelines.
- Entity normalization (`correlate/entities.py`): canonical forms for
  IPs (v4/v6), domains (lowercase, trailing-dot strip), users
  (`DOMAIN\user` → `user@domain`), hashes (lowercase hex, kind by
  length), and hostnames. Reuses `intel/normalize.py` for the shared
  types instead of duplicating it.
- `correlate run --case CASE-ID [--window 1h] [--min-sources 2]
  [--explain]`: builds the entity graph from a case's log events,
  pcap indicators, intel records and findings; the same entity in ≥2
  source types becomes a **pivot**. Pivots rank by distinct source
  count, recency, and intel verdict. High-confidence pivots
  (score ≥ `correlate_pivot_threshold`, default 70) become findings
  under the observed-vs-inferred discipline. Read-only over the case
  store — cases and evidence are never modified.
- Explainable 0–100 pivot scores, plain addition, never ML:
  `score = min(100, sources + verdict + temporal + recency)` where
  sources is +10 per distinct source type (cap +40), verdict is +20
  `malicious` / +10 `suspicious`, temporal is +10 when cross-source
  observations fall within `--window`, and recency is +10 when the
  latest observation is within 24h. `--explain` prints the full
  per-pivot breakdown; the formula is documented in the README and
  printed with every run.
- Temporal correlation: entities observed within the configurable
  window across sources are "temporally linked"; output says
  "observed within X of each other" and never claims causation.
- Evidence-backed relationships by construction: every edge and pivot
  lists its evidence (source type, evidence ID, timestamp), enforced
  in the model layer (`Pivot`/`Edge` reject empty evidence).
  Conflicting intel verdicts are reported as "conflicting", never
  averaged; skipped records are ignored.
- `correlate entities --case CASE-ID`: list all normalized entities
  with observation and source counts.
- `correlate timeline --case CASE-ID`: incident timeline merging the
  case timeline with pivot events — chronological, pivot points
  highlighted, every entry evidence-backed.
- New config knobs: `correlate_window_seconds` (default 3600),
  `correlate_min_sources` (default 2), `correlate_pivot_threshold`
  (default 70).

## [0.8.0] - 2026-10-03

### Added

- Threat-intel enrichment (`intel/`, v0.8): provider-neutral interface.
  Indicator normalization first (lowercased domains, refanged defang
  forms, URL host extraction, validated md5/sha1/sha256 hashes);
  invalid input is rejected with a reason, never silently kept.
- `IntelProvider` ABC (`name`, `supported_types`, `lookup`,
  `configure`) with a name registry. Built-in providers, all stdlib and
  opt-in: `local-blocklist` (user-supplied CSV, works offline),
  `team-cymru` (DNS-based ASN ownership — verdict always "unknown",
  ownership is not reputation), `dns-resolve` (forward resolution,
  labeled "currently resolves to"), and `http-reputation-stub` (a
  clearly labeled stub showing the interface; API keys come from
  environment variables only, never config files).
- Network providers run only when configured AND the user passes
  `--enrich`; `intel lookup` prints a one-line notice naming every
  network provider contacted. Without `--enrich` the tool is fully
  offline (blocklist + cache).
- `IntelRecord` verdict vocabulary strictly enforced in code:
  `unknown` / `clean` / `suspicious` / `malicious` / `no-verdict`
  ("provider did not return a verdict"). `malicious` verdicts become
  high findings with observed-vs-inferred reasoning.
- SQLite cache (TTL 24h default, `intel cache-clear`), per-provider
  token-bucket rate limits (lookups beyond budget are skipped with a
  clear message, never hammering).
- `intel correlate --case CASE-ID [--pcap FILE]`: enriches case and
  pcap indicators and combines verdicts — conflicting provider
  verdicts are reported as "conflicting", never averaged.
- New config knobs: `intel_providers`, `intel_cache_ttl`,
  `intel_rate_limit`, `intel_blocklist`.

## [0.7.0] - 2026-10-03

### Added

- Offline PCAP analysis (`pcap/`, v0.7): stdlib-only streaming reader
  for classic pcap (all four magic variants; pcapng refused with a
  clean error), Ethernet + Linux-cooked link layers, IPv4/IPv6, TCP,
  UDP, ICMP/ICMPv6 header decoders. No payload reassembly — payload
  lengths recorded, never contents.
- `aegisforge pcap summary FILE`: packet count, bytes, time range,
  protocol histogram, top talkers (packets/bytes), top ports, unusual
  ports (labeled "unusual", never "malicious"), plus observed-vs-
  inferred findings for unusual-port activity and connection-frequency
  bursts (configurable thresholds).
- `aegisforge pcap conversations FILE [--top N]`: 5-tuple flows with
  packet/byte counts, duration and TCP flags seen.
- `aegisforge pcap dns FILE [--top N]`: DNS queries/responses on
  UDP/53 via the v0.3 stdlib wire parser; malformed messages counted,
  never fatal.
- `aegisforge pcap http FILE [--top N]`: HTTP request lines, Host
  headers, User-Agent and status codes on TCP/80 — truncated to 200
  chars, bodies never read.
- `aegisforge pcap tls FILE [--top N]`: TLS ClientHello SNI + offered
  version on TCP/443 (metadata only; handshake failures counted).
- `aegisforge pcap indicators FILE`: deduped observed indicators —
  IPs, domains (DNS/HTTP Host/SNI), URLs — with first/last seen and
  sources. Every indicator is labeled "observed in capture", never a
  verdict (verdicts are threat intel's job, v0.8).
- `aegisforge pcap timeline FILE`: flow-start and DNS-query events
  feeding the core event model; attach capture summaries to cases
  with `case attach --kind network` (documented in the usage guide).
- New config knobs: `pcap_burst_window`, `pcap_burst_threshold`,
  `pcap_unusual_port_packets`, `pcap_top_n`.

## [0.6.0] - 2026-10-03

### Added

- Incident-response engine (`cases/`, v0.6): case creation and metadata,
  evidence folders and manifests, unified timelines, finding tracking,
  indicator linking, analyst notes and reproducible report artifacts.
- `aegisforge case create --title "..." [--note "..."]` allocates
  `CASE-2026-001`-style IDs (year prefix + zero-padded persisted
  sequence) and a case folder layout
  (`evidence/{network,logs,files}/`, `timeline/`, `findings/`,
  `report/`, `case.json`); `case list` / `case show` inspect cases.
- `aegisforge case attach CASE-ID --kind [network|logs|files]
  --source PATH` copies (never moves) the file into the case, hashes
  it with SHA-256, and records hash + original path + UTC attach time.
  Sources are opened read-only and never modified.
- `aegisforge case timeline CASE-ID` merges every evidence source into
  one chronological stream with per-event source labels: log events
  (logs/ auto-detection + streaming parsers), file mtime claims
  (forensics/ inventory), network scan events (AegisForge JSON result
  envelopes). Events without parseable timestamps land in a separate
  untimed section — never dropped silently.
- `aegisforge case finding CASE-ID --title --severity --confidence
  --detail` tracks findings with lifecycle states
  (`open` → `investigating` → `resolved`/`false-positive`);
  `case findings` lists them (filterable by `--status`).
- `aegisforge case link CASE-ID --finding F-ID --indicator VALUE
  [--type ...]` links indicators; the type is guessed from the value's
  shape (ip/domain/hash/url/email) unless the analyst specifies it,
  and the record always says which happened.
- `aegisforge case note CASE-ID "text"` appends analyst notes
  (append-only, UTC timestamps).
- `aegisforge case report CASE-ID --output DIR` builds a reproducible
  bundle (`case.json`, `evidence-manifest.json`, `timeline.json` +
  `timeline.csv`, `findings.json`, `notes.txt`,
  `report-manifest.json` with SHA-256 of every artifact). A non-empty
  output directory is refused unless `--force` is passed.
- `aegisforge case status CASE-ID [open|in-progress|closed]` shows or
  changes the case status; closing requires `--note` (exit 2 otherwise).

## [0.4.0] - 2026-10-03

> **Numbering note:** this is the master plan's v0.4 (Digital Forensics).
> It was built and merged after v0.5 (Log Analysis) shipped, so it
> appears above v0.5.0 in this file. The package version stays 0.5.0;
> the forensics module registers itself as v0.4.0 in the plugin
> registry.

### Added

- Digital forensics module (`forensics/`, v0.4): read-only recursive
  file inventory — the module opens files for reading only and never
  modifies, moves, or deletes anything under the scanned root.
- `aegisforge forensics inventory PATH` walks the tree (streaming,
  memory-bounded) with `--include`/`--exclude` glob filters, identifies
  each file by magic bytes (30+ signatures; extension fallback is
  clearly labeled, `extension_mismatch` flags magic/extension
  disagreements as an observed fact), and hashes with SHA-256 (default),
  MD5 and SHA-1 computed in a single chunked pass.
- `aegisforge forensics manifest PATH --output MANIFEST.json`
  writes a sealed evidence manifest (file list with hashes, sizes and
  UTC filesystem timestamps, tool version, run timestamps, operator
  note); the manifest's SHA-256 over its canonical encoding is stored
  inside the document and recorded in the audit log as a
  tamper-evidence seam (not a claim of legal admissibility).
- `aegisforge forensics verify --manifest MANIFEST.json` re-hashes the
  live tree and reports changed / missing / new files, each as a
  finding with the observed-vs-inferred discipline (a hash mismatch is
  *observed*; calling it tampering is *inferred*).
- `aegisforge forensics duplicates PATH` groups files by identical
  SHA-256; `aegisforge forensics timeline PATH` lists mtime/atime/ctime
  chronologically, labeled as filesystem metadata rather than content
  claims.
- Unreadable files, dangling symlinks and permission errors become
  warnings, never crashes; directory symlinks are never followed.
- Scenario guide (`docs/USAGE.md`) extended with a forensics step and
  a real terminal screenshot.

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
