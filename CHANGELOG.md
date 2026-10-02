# Changelog

All notable changes to this project will be documented in this file.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

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
