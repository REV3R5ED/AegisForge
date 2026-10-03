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
In v0.2 there is **no lockout** — the licensing seam is in place
(`aegisforge/core/license.py`) and commercial enforcement activates in a
later release.

## What v0.6 does

Core + Network Discovery + authorized port/service analysis + domain
investigation + **log analysis** + **digital forensics** (v0.4, shipped
right after v0.5 per the master plan's numbering) + **incident-response
engine** (case management):

| Command | What it does |
|---|---|
| `aegisforge network subnet CIDR [--expand]` | IPv4/IPv6 subnet calculator; bounded CIDR expansion |
| `aegisforge network ping TARGET...` | ICMP reachability, concurrent (max 20 workers by default) |
| `aegisforge network dns TARGET` | Forward/reverse DNS via stdlib socket |
| `aegisforge network trace TARGET` | Bounded traceroute via OS utility |
| `aegisforge network interfaces` | Local interfaces, optionally routes and ARP/neighbour table |
| `aegisforge network inventory` | Local asset inventory record |
| `aegisforge network scan TARGET [--ports ...] [--port-range ...]` | TCP connect scan: open/closed/filtered, banner grabbing, service ID, TLS cert inspection, HTTP metadata |
| `aegisforge network baseline save NAME TARGET` | Scan a target and store the result as a named baseline |
| `aegisforge network baseline diff NAME TARGET` | Rescan and report NEW / CLOSED / CHANGED ports vs the baseline |
| `aegisforge network baseline list` | List stored baselines |
| `aegisforge network baseline show NAME` | Show a stored baseline |
| `aegisforge network baseline delete NAME` | Delete a stored baseline |
| `aegisforge domain dns NAME [--type MX]` | Raw DNS records (A/AAAA/MX/NS/TXT/SOA/CNAME/DNSKEY/DS) via a stdlib wire-protocol client |
| `aegisforge domain investigate DOMAIN` | Consolidated report: DNS records, reverse DNS, NS/MX analysis, DNSSEC presence, TLS cert, RDAP (+WHOIS fallback), ASN ownership, HTTP/HTTPS headers & redirects |
| `aegisforge logs detect FILE` | Auto-detect the log format (syslog, Apache/Nginx, JSON lines, Windows Event XML, key=value) with confidence scores |
| `aegisforge logs analyze FILE [--format auto] [--since ...] [--until ...] [--level ...] [--contains ...] [--host ...] [--redact]` | Streaming analysis: timeline, severity/HTTP-status histograms, top talkers, error extraction with context, burst detection, observed-vs-inferred findings |
| `aegisforge forensics inventory PATH [--include GLOB] [--exclude GLOB] [--algorithms sha256]` | Read-only recursive file inventory: magic-byte identification (extension fallback labeled), single-pass multi-algorithm hashing, sizes, UTC filesystem timestamps |
| `aegisforge forensics manifest PATH --output MANIFEST.json [--note TEXT]` | Inventory a tree and write a sealed evidence manifest (SHA-256 over canonical JSON, digest recorded in the audit log) |
| `aegisforge forensics verify --manifest MANIFEST.json [--root PATH]` | Re-hash the live tree; report changed / missing / new files as observed-vs-inferred findings |
| `aegisforge forensics duplicates PATH` | Group files with identical SHA-256 content |
| `aegisforge forensics timeline PATH` | Chronological filesystem timestamps (mtime/atime/ctime) — filesystem metadata, not content claims |
| `aegisforge case create --title "..." [--note "..."]` | Create an incident case (`CASE-2026-001`-style ID, year + persisted sequence) with evidence/timeline/findings/report folders |
| `aegisforge case list` / `aegisforge case show CASE-ID` | List all cases / show case metadata, evidence, findings |
| `aegisforge case attach CASE-ID --kind [network\|logs\|files] --source PATH` | Copy (never move) a file into the case evidence folder; SHA-256 recorded; sources untouched |
| `aegisforge case timeline CASE-ID` | Unified chronological timeline across log/file/network evidence (untimed events listed separately, never dropped) |
| `aegisforge case finding CASE-ID --title --severity --confidence --detail` | Record a finding (`CASE-2026-001-F01`-style ID) with lifecycle status |
| `aegisforge case findings CASE-ID [--status ...]` | List tracked findings, optionally filtered by lifecycle state |
| `aegisforge case link CASE-ID --finding F-ID --indicator VALUE [--type ...]` | Link an indicator; type guessed from shape unless specified (recorded either way) |
| `aegisforge case note CASE-ID "text"` | Append an analyst note (append-only) |
| `aegisforge case report CASE-ID --output DIR [--force]` | Reproducible report bundle with per-artifact SHA-256 manifest |
| `aegisforge case status CASE-ID [open\|in-progress\|closed]` | Show/change case status (closing requires `--note`) |
| `aegisforge config show` | Show effective configuration |

### Investigation safety: passive lookups, no consent gate

Domain investigation is **passive**: DNS, RDAP, WHOIS and HTTP header
lookups only ask public directory services for information they already
publish to any client. Unlike port scanning (v0.2), which sends probes
to the target itself, nothing here requires `--allow-remote`:

- `network scan` → **active** → public targets need `--allow-remote`.
- `domain investigate` → **passive** → no gate; every step is a lookup
  against DNS resolvers, the IANA RDAP bootstrap, WHOIS port 43, or the
  domain's public web server headers.

```console
$ aegisforge domain dns example.com --type MX
example.com/MX: 1 record(s) (NOERROR)

name: example.com
qtype: MX
resolver: (system)
rcode: NOERROR
records: (1 items)
  - name=example.com, rtype=MX, ttl=300, data={'preference': 0, 'exchange': '.'}, detail=0 .
warnings: (0 items)

$ aegisforge domain investigate example.com
domain investigation of example.com: 2 finding(s), 0 error(s)

domain: example.com
dns:
  records:
    A: (1 items)
      - name=example.com, rtype=A, ttl=300, data={'address': '93.184.216.34'}
    MX: (1 items)
      - name=example.com, rtype=MX, ttl=300, data={'preference': 0, 'exchange': '.'}
    ...
reverse_dns: (1 items)
  - query=93.184.216.34, reverse_name=93-184-216-34.example.net
nameservers:
  nameservers: (1 items)
    - hostname=a.iana-servers.net, ipv4=['199.43.135.53'], issues=[]
tls:
  not_after: 2027-06-01T00:00:00Z
  days_until_expiry: 242
  hostname_verified: True
rdap:
  registrar: Example Registrar
  status: (1 items)
    - active
asn: (1 items)
  - ip=93.184.216.34, asn=15169, prefix=93.184.216.0/24, country=US, registry=arin
...

Findings:
  [low] mail exchanger problem: . (confidence 85)
    null MX (RFC 7505): domain explicitly accepts no mail
  [info] example.com publishes no DNSSEC signing evidence (confidence 90)
    no DNSKEY or DS records were published for the zone; DNS answers for
    this domain are not cryptographically signed (observation only —
    absence of evidence, and AegisForge does not validate chains)
```

Findings keep the observed-vs-inferred discipline: what was seen goes
in the evidence, what it might mean goes in the reason.

### Log analysis: streaming parsers, honest findings

`logs analyze` parses syslog (RFC 3164/5424), Apache/Nginx combined
and common logs, JSON lines, Windows Event Log XML exports, and
generic `key=value` — streaming, never loading the whole file into
memory. The format is auto-detected (with reported confidence) unless
you pass `--format`. Analysis builds a UTC timeline, severity and
HTTP-status histograms, top talkers, error extraction with context
lines, and burst detection. Detections (auth-failure bursts, 5xx
spikes, exception clusters) keep the observed-vs-inferred discipline:
a burst of 404s is *observed*; calling it an attack is *inferred* and
is labeled as such.

```console
$ aegisforge logs detect /var/log/auth.log
/var/log/auth.log: detected syslog format (confidence 0.93)

$ aegisforge logs analyze /var/log/auth.log --since 2026-10-02T16:00:00Z
/var/log/auth.log: 14 event(s) matched (syslog), 1 finding(s), 1 warning(s)

Format: syslog (confidence 0.933)
Lines: 14 parsed, 14 matched, 1 warnings
Time range: 2026-10-02T16:00:01Z .. 2026-10-02T16:10:00Z

Parse warnings (showing 1):
  line 14: not a recognized syslog line

Severity:
  info  14

Top IPs:
  203.0.113.7    12
  198.51.100.23  1

Findings:
  [medium] authentication-failure burst from 203.0.113.7 (confidence 70)
    OBSERVED: 12 failed authentication attempts from 203.0.113.7 within
    300s (window starting 2026-10-02T16:00:01Z). INFERRED: pattern is
    consistent with password-guessing (brute-force) activity —
    corroborate before concluding.
```

Logs often contain PII. `--redact` masks IPv4/IPv6 addresses and
email-like tokens in the *output* (human, `--json`, `--csv`) — the
source files are never modified, and analysis keeps the original
values so counts stay accurate:

```console
$ aegisforge logs analyze /var/log/auth.log --redact | grep -A3 "Top IPs"
Top IPs:
  xxx.xxx.xxx.xxx  12
  xxx.xxx.xxx.xxx  1
```

### Scan safety: authorized targets only

Port scanning is an **active** technique, so v0.2 enforces target
scoping:

- **Local targets scan freely**: loopback, RFC 1918 / ULA private
  addresses, link-local, and other non-routable addresses.
- **Public targets require explicit consent**: scanning anything
  globally routable refuses with an error unless you pass
  `--allow-remote` — a deliberate, audit-logged acknowledgement that
  you are authorized to scan the target. Hostnames are resolved first
  and *every* resolved address is checked.

```console
$ aegisforge network scan 93.184.216.34 --ports 80,443
aegisforge: error: refusing to scan public target '93.184.216.34'
(resolves to 93.184.216.34) without --allow-remote: confirm you are
authorized to scan this target, then re-run with --allow-remote
$ echo $?
2
```

Concurrency is capped (default 50 workers, hard max 100), every
connection carries a timeout, retries are bounded, and banner reads
are size-capped. No `shell=True` anywhere; all targets and port
specs are validated before any packet is sent.

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
$ aegisforge network scan 127.0.0.1 --ports 22,80,443
127.0.0.1 (127.0.0.1): 1/3 ports open in 4ms

target: 127.0.0.1
resolved_ip: 127.0.0.1
ports_scanned: 3
ports_open: 1
duration_ms: 4.12
allow_remote: False

PORT   STATE     SERVICE     BANNER
22     open      ssh         SSH-2.0-OpenSSH_9.6
80     closed
443    closed
```

```console
$ aegisforge network baseline save office-lan 192.168.1.10 --port-range 1-1024
baseline 'office-lan' saved for 192.168.1.10: 3/1024 ports open
$ aegisforge network baseline diff office-lan 192.168.1.10 --port-range 1-1024
baseline 'office-lan': 1 new port(s) since baseline

name: office-lan
target: 192.168.1.10
baseline_created: 2026-10-02T23:00:00Z

NEW:
  8080: port 8080 is now open (http)

Findings:
  [medium] new open port since baseline: 8080 (confidence 90)
    port 8080 is now open (http)
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

```console
$ aegisforge logs analyze /var/log/auth.log --redact --level info --limit 5
/var/log/auth.log: 14 event(s) matched (syslog), 1 finding(s), 1 warning(s)

Format: syslog (confidence 0.933)
...
Top IPs:
  xxx.xxx.xxx.xxx  12
  xxx.xxx.xxx.xxx  1
$ echo $?
1
```

See [docs/USAGE.md](docs/USAGE.md) for a scenario walkthrough with
screenshots: documenting an undocumented network step by step.

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
  network/     subnet, ping, dns, trace, interfaces, inventory,
               scanner, services, tls, http, baselines
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
pytest                    # 178 tests, coverage gate 80%
ruff check . && ruff format --check .
mypy src
```

See [CONTRIBUTING.md](CONTRIBUTING.md) and [SECURITY.md](SECURITY.md).
