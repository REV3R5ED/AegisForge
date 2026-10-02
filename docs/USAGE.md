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

## What's next

v0.1 covers passive discovery. v0.2 adds **authorized** TCP port and
service scanning with service banners, TLS inspection, and
baseline/diff change detection — with an explicit `--allow-remote` gate
before any public IP can be scanned.
