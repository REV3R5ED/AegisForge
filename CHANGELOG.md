# Changelog

All notable changes to this project will be documented in this file.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

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
