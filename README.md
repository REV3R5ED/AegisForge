# AegisForge

A modular defensive-security and incident-response (DFIR) platform for
operators who need trustworthy, auditable network and host discovery.

> **Commercial software — 1-week free trial.** You may evaluate
> AegisForge free for **7 days from first use**. Continued use after the
> trial requires purchasing a commercial license from the author.
> Redistribution and sublicensing are not permitted. See [LICENSE](LICENSE)
> for the full terms. Provided as-is, without warranty.
>
> Copyright (c) 2026 Pouya Shini Karim.

The CLI prints a friendly `Trial: N days remaining` notice on startup.
In v0.1 there is **no lockout** — the licensing seam is in place
(`aegisforge/core/license.py`) and commercial enforcement activates in a
later release.

## What v0.1 does

Core + Network Discovery:

| Command | What it does |
|---|---|
| `aegisforge network subnet CIDR [--expand]` | IPv4/IPv6 subnet calculator; bounded CIDR expansion |
| `aegisforge network ping TARGET...` | ICMP reachability, concurrent (max 20 workers by default) |
| `aegisforge network dns TARGET` | Forward/reverse DNS via stdlib socket |
| `aegisforge network trace TARGET` | Bounded traceroute via OS utility |
| `aegisforge network interfaces` | Local interfaces, optionally routes and ARP/neighbour table |
| `aegisforge network inventory` | Local asset inventory record |
| `aegisforge config show` | Show effective configuration |

Every command emits human-readable output by default, `--json` and
`--csv` for automation, and structured exit codes:

- `0` — ok, no findings
- `1` — completed with findings (e.g. host unreachable, packet loss)
- `2` — error (bad input, tool failure)

Every invocation is audit-logged (best effort, `~/.aegisforge/audit.log`).
No `shell=True` anywhere; all targets are validated; expansion and
concurrency are hard-capped.

## Install

Python 3.10–3.13, zero dependencies (stdlib only).

```bash
pip install aegisforge          # from PyPI, when published
# or from a source checkout:
pip install .
aegisforge --version
```

## Quickstart

```console
$ aegisforge network subnet 192.168.1.0/24
Trial: 7 day(s) of free trial remaining.
192.168.1.0/24: 256 addresses (254 usable)

calculator:
  cidr: 192.168.1.0/24
  version: 4
  network_address: 192.168.1.0
  broadcast_address: 192.168.1.255
  netmask: 255.255.255.0
  prefixlen: 24
  num_addresses: 256
  num_usable_hosts: 254
  first_usable: 192.168.1.1
  last_usable: 192.168.1.254
  is_private: True
```

```console
$ aegisforge network ping 127.0.0.1 example.com --count 2
1/2 hosts reachable

count: 2
timeout: 2.0
results: (2 items)
  - target=127.0.0.1, reachable=True, transmitted=2, received=2, loss_percent=0.0, ...
  - target=example.com, reachable=False, transmitted=2, received=0, loss_percent=100.0, ...

Findings:
  [low] host unreachable: example.com (confidence 90)
    no ICMP replies from example.com
$ echo $?
1
```

```console
$ aegisforge network dns 93.184.216.34 --json
{
  "command": "network dns",
  "target": "93.184.216.34",
  "status": "ok",
  "summary": "93.184.216.34 -> example-host",
  "data": {
    "query": "93.184.216.34",
    "addresses": [{"ip": "93.184.216.34", "family": "IPv4"}],
    "reverse_name": "example-host"
  },
  ...
}
```

## Configuration

JSON config files (`~/.aegisforge/config.json`, overridable with
`--config` / `AEGISFORGE_CONFIG`), with named profiles and per-flag
overrides:

```json
{
  "profiles": {
    "default": {"ping_count": 3, "ping_timeout": 2.0, "max_parallel": 20},
    "quick": {"ping_count": 1, "ping_timeout": 1.0}
  }
}
```

## Architecture (built for the roadmap)

```
aegisforge/
  core/        config, events, findings, evidence, plugins, logging, results, license
  network/     subnet, ping, dns, trace, interfaces, inventory
  cli/         argparse surface, human/JSON/CSV rendering
```

- **events**: normalized UTC-timestamped observations every command emits.
- **findings**: observed-vs-inferred results with severity and 0–100 confidence.
- **evidence**: chain-of-custody records with sha256 hashing.
- **plugins**: `ModuleRegistry` + the `aegisforge.modules` entry-point
  group — later phases register here without touching the CLI.

Roadmap: host forensics, log analysis, PCAP analysis, threat intel,
correlation engine, case management, reporting.

## Development

```bash
pip install -e ".[dev]"
pytest                    # 97 tests, coverage gate 80%
ruff check . && ruff format --check .
mypy src
```

See [CONTRIBUTING.md](CONTRIBUTING.md) and [SECURITY.md](SECURITY.md).
