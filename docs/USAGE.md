# AegisForge in action — scenario walkthrough

> **Scenario:** you've just been given access to a machine on a network
> nobody documented. Before you touch anything else, build a picture of
> where you are and what's around you — passively, without scanning
> anything you don't own.
>
> Every command below is real output from AegisForge v0.1.0.

## Step 1 — Where am I?

Start with your own interfaces, then pull the full local asset record:
hostname, gateways, DNS servers.

```
$ aegisforge network interfaces
$ aegisforge network inventory
```

![Where am I — interfaces and inventory](images/01-where-am-i.png)

You now know the machine's addresses, its gateway, and which DNS servers
it uses. That is the foundation everything else builds on.

## Step 2 — What does this address space look like?

Take the network you found yourself on and map it out. The subnet
calculator shows usable range, broadcast, and netmask — the boundaries
of "your" network.

```
$ aegisforge network subnet 192.168.1.0/24
192.168.1.0/24: 256 addresses (254 usable)

calculator:
  network_address: 192.168.1.0
  broadcast_address: 192.168.1.255
  netmask: 255.255.255.0
  first_usable: 192.168.1.1
  last_usable: 192.168.1.254
  is_private: True
```

## Step 3 — Who's alive?

Check reachability of explicit targets with bounded, concurrent pings.
AegisForge never sweeps a subnet unprompted — you name the targets.

```
$ aegisforge network ping 127.0.0.1 localhost --count 2
2/2 hosts reachable

results: (2 items)
  - target=127.0.0.1, reachable=True, transmitted=2, received=2,
    loss_percent=0.0, rtt_avg_ms=0.035
  - target=localhost, reachable=True, transmitted=2, received=2,
    loss_percent=0.0, rtt_avg_ms=0.092
```

![What's around me — subnet, ping, DNS](images/02-whats-around-me.png)

## Step 4 — Who are they, by name?

Resolve names to addresses and addresses back to names:

```
$ aegisforge network dns localhost
localhost -> ::1, 127.0.0.1

query: localhost
addresses: (2 items)
  - ip=::1, family=IPv6
  - ip=127.0.0.1, family=IPv4
```

## Take it further — machine-readable output

Every command also emits the same result as structured data for
automation, dashboards, or evidence files:

```
$ aegisforge network ping 127.0.0.1 --count 1 --json
$ aegisforge network subnet 192.168.1.0/24 --csv
```

JSON follows a stable envelope (`tool`, `version`, `command`,
`timestamp`, `status`, `summary`, `data`, `findings`, `events`) with
exit codes `0` = ok, `1` = findings, `2` = error.

## What's next — v0.2: authorized scanning and change detection

> **Scenario continues:** a week later, you want to know if anything
> changed on that machine. Save a baseline, then rescan and diff.

Scanning is an *active* step, so AegisForge makes you name your target
explicitly — and refuses public IPs unless you pass `--allow-remote`
to confirm you're authorized:

```
$ aegisforge network scan 127.0.0.1 --ports 22,80,443
127.0.0.1 (127.0.0.1): 0/3 ports open

PORT   STATE     SERVICE     BANNER
22     closed
80     closed
443    closed
```

Save the known-good state, then let the diff catch drift:

```
$ aegisforge network baseline save webserver 127.0.0.1 --ports 18080
baseline 'webserver' saved for 127.0.0.1: 0/1 ports open

$ # ... later, something starts listening ...

$ aegisforge network baseline diff webserver 127.0.0.1 --ports 18080
```

![Scan baseline diff catching a new open port](images/03-scan-and-baseline.png)

The diff doesn't just print the change — it raises a proper finding
with severity and confidence, ready for the case timeline. Scan
results include service banners, TLS certificate details, and
HTTP metadata where available.

## What's next — v0.3: domain investigation

> **Scenario continues:** the scan found a web server, and now you
> want the full picture on its domain — who runs it, how mail and DNS
> are set up, whether the certificate is healthy.

One command runs every passive lookup and consolidates the report:

```
$ aegisforge domain investigate example.com
domain investigation of example.com: 2 finding(s), 0 error(s)
```

![Domain investigation report with findings](images/04-domain-investigate.png)

Behind that summary: A/AAAA/MX/NS/TXT/SOA/CNAME records (via a
stdlib DNS wire client — `socket` alone can't query MX or TXT),
reverse DNS for each address, nameserver resolution with lame
delegation flags, MX preference ordering, DNSSEC *presence* (reported,
never claimed as validated), TLS certificate inspection on 443,
RDAP registration data with WHOIS fallback, ASN ownership via Team
Cymru, and HTTP/HTTPS header + redirect chains. For a single record
type, `aegisforge domain dns example.com --type MX` is the quick
version.

Unlike port scanning, all of this is passive directory lookups —
nothing is sent to the target that its public services don't already
answer for anyone, so there's no `--allow-remote` gate here.

## What's next — v0.5: log analysis

> **Scenario continues:** the domain checks out, but the server's
> auth log tells a different story. Point AegisForge at the log file
> — it detects the format, parses it streaming, and hunts for
> trouble.

```console
$ aegisforge logs detect auth.log
auth.log: detected syslog format (confidence 0.93)

$ aegisforge logs analyze auth.log
auth.log: 13 event(s) matched (syslog), 1 finding(s), 1 warning(s)
```

![Log analysis catching an authentication-failure burst](images/05-logs-analysis.png)

Behind that summary: syslog (RFC 3164/5424), Apache/Nginx, JSON
lines, Windows Event XML exports and `key=value` parsers — all
streaming, so multi-gigabyte files never get loaded into memory.
Malformed lines become warnings with line numbers instead of
crashing the parse. Analysis builds a UTC timeline, severity and
HTTP-status histograms, top talkers, error extraction with context
lines, and burst detection. Detections keep the observed-vs-inferred
discipline you see above: 12 failed logins is *observed*; calling it
brute-force is *inferred* — and labeled as such.

Filters compose freely — `--since`, `--until`, `--level`,
`--contains`/`--not-contains`, `--host`, `--limit` — and because logs
carry PII, `--redact` masks IPs and emails in the output while the
source file stays untouched:

```console
$ aegisforge logs analyze auth.log --redact --since 2026-10-02T16:00:00Z
```
