"""AegisForge CLI: ``aegisforge network ...`` (v0.2).

Every command returns a shared result envelope, renders human-readable
text by default (``--json`` / ``--csv`` for automation), uses structured
exit codes (0 ok / 1 findings / 2 error), and writes an audit record.
Diagnostics go to stderr; stdout carries only the requested output.

v0.2 adds authorized TCP port/service scanning (``network scan``) with
explicit remote-target consent (``--allow-remote``) and scan baselines
with change detection (``network baseline``).
"""

from __future__ import annotations

import argparse
import csv
import io
import json
import sys
from collections.abc import Sequence
from typing import Any

from aegisforge import __version__
from aegisforge.core import config as config_mod
from aegisforge.core.config import AppConfig, ConfigError
from aegisforge.core.events import Event
from aegisforge.core.findings import Finding
from aegisforge.core.license import print_trial_notice, trial_status
from aegisforge.core.logging import audit_log, configure_logging, get_logger
from aegisforge.core.results import EXIT_ERROR, Result, exit_code_for
from aegisforge.network import baselines as baselines_mod
from aegisforge.network import dns as dns_mod
from aegisforge.network import interfaces as interfaces_mod
from aegisforge.network import inventory as inventory_mod
from aegisforge.network import ping as ping_mod
from aegisforge.network import scanner as scanner_mod
from aegisforge.network import subnet as subnet_mod
from aegisforge.network import trace as trace_mod
from aegisforge.network import validation as validation_mod
from aegisforge.network.validation import ValidationError

log = get_logger()


# ---------------------------------------------------------------------------
# Command implementations (each returns a Result)
# ---------------------------------------------------------------------------


def cmd_subnet(args: argparse.Namespace, cfg: AppConfig) -> Result:
    result = Result(command="network subnet", target=args.cidr)
    try:
        info = subnet_mod.describe_subnet(args.cidr)
    except ValidationError as exc:
        result.fail(str(exc))
        return result
    data: dict[str, Any] = {"calculator": info}
    if args.expand:
        try:
            hosts = subnet_mod.expand_cidr(args.cidr, max_hosts=args.max_hosts)
        except ValidationError as exc:
            result.fail(str(exc))
            return result
        data["hosts"] = hosts
        data["host_count"] = len(hosts)
    result.data = data
    result.summary = (
        f"{info['cidr']}: {info['num_addresses']} addresses "
        f"({info['num_usable_hosts']} usable)"
    )
    result.add_event(
        Event(
            event_type="network.subnet.calculated",
            source="aegisforge",
            host=None,
            evidence={"cidr": args.cidr},
        )
    )
    return result


def cmd_ping(args: argparse.Namespace, cfg: AppConfig) -> Result:
    count = args.count if args.count is not None else cfg["ping_count"]
    timeout = args.timeout if args.timeout is not None else cfg["ping_timeout"]
    max_parallel = (
        args.max_parallel if args.max_parallel is not None else cfg["max_parallel"]
    )
    result = Result(command="network ping", target=", ".join(args.targets))
    try:
        results = ping_mod.ping_many(
            args.targets, count=count, timeout=timeout, max_parallel=max_parallel
        )
    except ValidationError as exc:
        result.fail(str(exc))
        return result
    rows = [r.to_dict() for r in results]
    result.data = {"count": count, "timeout": timeout, "results": rows}
    reachable = sum(1 for r in results if r.reachable)
    result.summary = f"{reachable}/{len(results)} hosts reachable"
    for r in results:
        result.add_event(
            Event(
                event_type="network.ping.completed",
                source="aegisforge",
                host=r.target,
                evidence={
                    "reachable": r.reachable,
                    "loss_percent": r.loss_percent,
                    "rtt_avg_ms": r.rtt_avg_ms,
                },
            )
        )
        if not r.reachable:
            result.add_finding(
                Finding(
                    title=f"host unreachable: {r.target}",
                    severity="low",
                    confidence=90,
                    reason=f"no ICMP replies from {r.target}",
                    evidence=[r.error or "0 packets received"],
                )
            )
        elif r.loss_percent > 0:
            result.add_finding(
                Finding(
                    title=f"packet loss on {r.target}",
                    severity="low",
                    confidence=80,
                    reason=f"{r.loss_percent:.0f}% packet loss",
                    evidence=[f"{r.received}/{r.transmitted} replies received"],
                )
            )
    return result


def cmd_dns(args: argparse.Namespace, cfg: AppConfig) -> Result:
    timeout = args.timeout if args.timeout is not None else cfg["dns_timeout"]
    result = Result(command="network dns", target=args.target)
    try:
        answer = dns_mod.lookup(args.target, timeout=timeout)
    except (ValidationError, dns_mod.DNSError) as exc:
        result.fail(str(exc))
        return result
    result.data = answer.to_dict()
    addrs = ", ".join(a["ip"] for a in answer.addresses)
    if answer.reverse_name:
        result.summary = f"{args.target} -> {answer.reverse_name}"
    else:
        result.summary = f"{args.target} -> {addrs}"
    result.add_event(
        Event(
            event_type="network.dns.resolved",
            source="aegisforge",
            host=args.target,
            evidence={"addresses": addrs},
        )
    )
    return result


def cmd_trace(args: argparse.Namespace, cfg: AppConfig) -> Result:
    max_hops = args.max_hops if args.max_hops is not None else cfg["trace_max_hops"]
    timeout = args.timeout if args.timeout is not None else cfg["trace_timeout"]
    result = Result(command="network trace", target=args.target)
    try:
        trace = trace_mod.traceroute(args.target, max_hops=max_hops, timeout=timeout)
    except ValidationError as exc:
        result.fail(str(exc))
        return result
    if trace.error:
        result.fail(trace.error)
        return result
    result.data = trace.to_dict()
    hops = len(trace.hops)
    result.summary = (
        f"{args.target}: {'reached' if trace.reached else 'not reached'} in {hops} hops"
    )
    result.add_event(
        Event(
            event_type="network.trace.completed",
            source="aegisforge",
            host=args.target,
            evidence={"hops": hops, "reached": trace.reached},
        )
    )
    if not trace.reached:
        result.add_finding(
            Finding(
                title=f"traceroute did not reach {args.target}",
                severity="low",
                confidence=70,
                reason="no hop matched the target address",
                evidence=[f"{hops} hops recorded"],
            )
        )
    return result


def cmd_interfaces(args: argparse.Namespace, cfg: AppConfig) -> Result:
    result = Result(command="network interfaces")
    data = interfaces_mod.list_interfaces()
    if args.include_routes:
        data.update(interfaces_mod.list_routes())
    if args.include_neighbours:
        data.update(interfaces_mod.list_neighbours())
    result.data = data
    names = [i["name"] for i in data["interfaces"]]
    result.summary = (
        f"{len(names)} interface(s): {', '.join(names) if names else 'none'}"
    )
    result.add_event(
        Event(
            event_type="network.interfaces.discovered",
            source="aegisforge",
            evidence={"interface_count": len(names)},
        )
    )
    return result


def cmd_inventory(args: argparse.Namespace, cfg: AppConfig) -> Result:
    result = Result(command="network inventory")
    data = inventory_mod.local_inventory()
    result.data = data
    result.summary = (
        f"{data['hostname']} ({data['platform']}): "
        f"{len(data['interfaces'])} interface(s), "
        f"{len(data['default_gateways'])} gateway(s)"
    )
    result.add_event(
        Event(
            event_type="network.inventory.collected",
            source="aegisforge",
            host=data["hostname"],
            evidence={"platform": data["platform"]},
        )
    )
    return result


def cmd_config_show(args: argparse.Namespace, cfg: AppConfig) -> Result:
    result = Result(command="config show")
    result.data = cfg.to_dict()
    result.summary = f"profile {cfg.profile!r} from {cfg.source}"
    return result


def _scan_options_from_args(
    args: argparse.Namespace, cfg: AppConfig
) -> scanner_mod.ScanOptions:
    timeout = args.timeout if args.timeout is not None else cfg["scan_timeout"]
    retries = args.retries if args.retries is not None else cfg["scan_retries"]
    max_parallel = (
        args.max_parallel if args.max_parallel is not None else cfg["scan_max_parallel"]
    )
    return scanner_mod.ScanOptions(
        timeout=timeout,
        retries=retries,
        max_parallel=max_parallel,
        banner=not args.no_banner,
        banner_timeout=cfg["scan_banner_timeout"],
        tls_probe=not args.no_service_probes,
        http_probe=not args.no_service_probes,
    )


def _tls_findings(scan: scanner_mod.ScanResult, result: Result) -> None:
    for port_result in scan.open_ports:
        tls = port_result.tls or {}
        days = tls.get("days_until_expiry")
        if not isinstance(days, int):
            continue
        if days < 0:
            result.add_finding(
                Finding(
                    title=f"TLS certificate expired on port {port_result.port}",
                    severity="high",
                    confidence=95,
                    reason=f"certificate expired {-days} day(s) ago",
                    evidence=[
                        f"not_after={tls.get('not_after')}",
                        f"subject={tls.get('subject', {}).get('CN', '?')}",
                    ],
                )
            )
        elif days <= 30:
            result.add_finding(
                Finding(
                    title=f"TLS certificate expiring on port {port_result.port}",
                    severity="medium",
                    confidence=90,
                    reason=f"certificate expires in {days} day(s)",
                    evidence=[f"not_after={tls.get('not_after')}"],
                )
            )


def cmd_scan(args: argparse.Namespace, cfg: AppConfig) -> Result:
    result = Result(command="network scan", target=args.target)
    try:
        ports = validation_mod.parse_port_spec(
            args.ports,
            args.port_range,
            max_ports=cfg["scan_max_ports"],
            default=scanner_mod.DEFAULT_PORTS,
        )
        options = _scan_options_from_args(args, cfg)
        scan = scanner_mod.scan_host(
            args.target, ports, options, allow_remote=args.allow_remote
        )
    except ValidationError as exc:
        result.fail(str(exc))
        return result
    result.data = {
        "target": scan.target,
        "resolved_ip": scan.resolved_ip,
        "ports_scanned": len(scan.ports),
        "ports_open": len(scan.open_ports),
        "duration_ms": scan.duration_ms,
        "allow_remote": scan.allow_remote,
        "ports": [p.to_dict() for p in scan.ports],
    }
    result.summary = (
        f"{scan.target} ({scan.resolved_ip}): "
        f"{len(scan.open_ports)}/{len(scan.ports)} ports open "
        f"in {scan.duration_ms:.0f}ms"
    )
    result.add_event(
        Event(
            event_type="network.scan.completed",
            source="aegisforge",
            host=scan.target,
            evidence={
                "resolved_ip": scan.resolved_ip,
                "ports_scanned": len(scan.ports),
                "ports_open": len(scan.open_ports),
                "open_ports": [p.port for p in scan.open_ports],
                "allow_remote": scan.allow_remote,
            },
        )
    )
    _tls_findings(scan, result)
    return result


def cmd_baseline(args: argparse.Namespace, cfg: AppConfig) -> Result:
    action = args.baseline_command
    result = Result(command=f"network baseline {action}")
    if action == "list":
        entries = baselines_mod.list_baselines()
        result.data = {"baselines": entries}
        result.summary = f"{len(entries)} baseline(s) stored"
        return result
    if action == "show":
        try:
            payload = baselines_mod.load_baseline(args.name)
        except ValidationError as exc:
            result.fail(str(exc))
            return result
        result.data = payload
        result.summary = (
            f"baseline {payload.get('name')!r}: target {payload.get('target')}, "
            f"{len(payload.get('ports', []))} ports, "
            f"created {payload.get('created')}"
        )
        return result
    if action == "delete":
        try:
            removed = baselines_mod.delete_baseline(args.name)
        except ValidationError as exc:
            result.fail(str(exc))
            return result
        result.data = {"name": args.name, "deleted": removed}
        result.summary = (
            f"baseline {args.name!r} deleted"
            if removed
            else f"no baseline named {args.name!r}"
        )
        return result
    # save / diff: run a scan first.
    try:
        name = validation_mod.validate_baseline_name(args.name)
        ports = validation_mod.parse_port_spec(
            args.ports,
            args.port_range,
            max_ports=cfg["scan_max_ports"],
            default=scanner_mod.DEFAULT_PORTS,
        )
        options = _scan_options_from_args(args, cfg)
        scan = scanner_mod.scan_host(
            args.target, ports, options, allow_remote=args.allow_remote
        )
    except ValidationError as exc:
        result.fail(str(exc))
        return result
    result.target = args.target
    if action == "save":
        path = baselines_mod.save_baseline(name, scan)
        result.data = {
            "name": name,
            "path": str(path),
            "target": scan.target,
            "ports_scanned": len(scan.ports),
            "ports_open": len(scan.open_ports),
        }
        result.summary = (
            f"baseline {name!r} saved for {scan.target}: "
            f"{len(scan.open_ports)}/{len(scan.ports)} ports open"
        )
        result.add_event(
            Event(
                event_type="network.baseline.saved",
                source="aegisforge",
                host=scan.target,
                evidence={"name": name, "ports_open": len(scan.open_ports)},
            )
        )
        return result
    # diff
    try:
        baseline = baselines_mod.load_baseline(name)
    except ValidationError as exc:
        result.fail(str(exc))
        return result
    diff = baselines_mod.diff_baseline(baseline, scan)
    result.data = {
        "name": name,
        "target": scan.target,
        "baseline_created": diff.baseline_created,
        "changes": [e.to_dict() for e in diff.entries],
    }
    result.summary = f"baseline {name!r}: {diff.summary}"
    result.add_event(
        Event(
            event_type="network.baseline.diffed",
            source="aegisforge",
            host=scan.target,
            evidence={
                "name": name,
                "changes": [{"port": e.port, "change": e.change} for e in diff.entries],
            },
        )
    )
    for entry in diff.entries:
        if entry.change == "new":
            result.add_finding(
                Finding(
                    title=f"new open port since baseline: {entry.port}",
                    severity="medium",
                    confidence=90,
                    reason=entry.detail,
                    evidence=[f"baseline {name!r} taken {diff.baseline_created}"],
                )
            )
        elif entry.change == "closed":
            result.add_finding(
                Finding(
                    title=f"port closed since baseline: {entry.port}",
                    severity="low",
                    confidence=90,
                    reason=entry.detail,
                    evidence=[f"baseline {name!r} taken {diff.baseline_created}"],
                )
            )
        else:
            result.add_finding(
                Finding(
                    title=f"service changed on port {entry.port} since baseline",
                    severity="low",
                    confidence=80,
                    reason=entry.detail,
                    evidence=[f"baseline {name!r} taken {diff.baseline_created}"],
                )
            )
    _tls_findings(scan, result)
    return result


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------


def _kv_lines(data: dict[str, Any], indent: int = 0) -> list[str]:
    pad = "  " * indent
    lines = []
    for key, value in data.items():
        if isinstance(value, dict):
            lines.append(f"{pad}{key}:")
            lines.extend(_kv_lines(value, indent + 1))
        elif isinstance(value, list):
            lines.append(f"{pad}{key}: ({len(value)} items)")
            for item in value[:20]:
                if isinstance(item, dict):
                    lines.append(
                        f"{pad}  - " + ", ".join(f"{k}={v}" for k, v in item.items())
                    )
                else:
                    lines.append(f"{pad}  - {item}")
            if len(value) > 20:
                lines.append(f"{pad}  ... and {len(value) - 20} more")
        else:
            lines.append(f"{pad}{key}: {value}")
    return lines


def render_human(result: Result) -> str:
    lines = [result.summary] if result.summary else []
    if result.status == "error":
        return "\n".join(lines) if lines else "error"
    data = dict(result.data)
    data.pop("events", None)
    ports = data.pop("ports", None)
    changes = data.pop("changes", None)
    baselines = data.pop("baselines", None)
    if data:
        lines.append("")
        lines.extend(_kv_lines(data))
    if isinstance(ports, list):
        lines.append("")
        lines.append(f"{'PORT':<7}{'STATE':<10}{'SERVICE':<12}BANNER")
        for p in ports:
            banner = (p.get("banner") or "")[:64]
            lines.append(
                f"{p.get('port'):<7}{p.get('state'):<10}"
                f"{(p.get('service') or ''):<12}{banner}"
            )
    if isinstance(changes, list):
        lines.append("")
        for change in ("new", "closed", "changed"):
            group = [c for c in changes if c.get("change") == change]
            if group:
                lines.append(f"{change.upper()}:")
                for c in group:
                    lines.append(f"  {c.get('port')}: {c.get('detail')}")
    if isinstance(baselines, list):
        lines.append("")
        lines.append(f"{'NAME':<24}{'TARGET':<20}{'OPEN':<6}CREATED")
        for b in baselines:
            lines.append(
                f"{str(b.get('name')):<24}{str(b.get('target')):<20}"
                f"{str(b.get('ports_open')):<6}{b.get('created')}"
            )
    if result.findings:
        lines.append("")
        lines.append("Findings:")
        for f in result.findings:
            lines.append(f"  [{f.severity}] {f.title} (confidence {f.confidence})")
            if f.reason:
                lines.append(f"    {f.reason}")
    return "\n".join(lines)


def _csv_rows(result: Result) -> tuple[list[str], list[list[Any]]]:
    """Flatten the primary list in result.data to CSV rows."""
    data = result.data
    if "results" in data:  # ping
        rows = data["results"]
        headers = [
            "target",
            "reachable",
            "transmitted",
            "received",
            "loss_percent",
            "rtt_min_ms",
            "rtt_avg_ms",
            "rtt_max_ms",
            "error",
        ]
    elif "hops" in data:  # trace
        rows = data["hops"]
        headers = ["hop", "ip", "hostname", "rtt_ms"]
    elif "interfaces" in data:  # interfaces / inventory
        rows = data["interfaces"]
        headers = ["name", "mac", "mtu", "status", "ipv4", "ipv6"]
    elif "hosts" in data:  # subnet expand
        rows = [{"host": h} for h in data["hosts"]]
        headers = ["host"]
    elif "ports" in data:  # scan
        rows = [
            {
                "target": data.get("target", ""),
                "port": p.get("port"),
                "state": p.get("state"),
                "service": p.get("service"),
                "rtt_ms": p.get("rtt_ms"),
                "banner": p.get("banner"),
            }
            for p in data["ports"]
        ]
        headers = ["target", "port", "state", "service", "rtt_ms", "banner"]
    elif "changes" in data:  # baseline diff
        rows = data["changes"]
        headers = ["port", "change", "detail"]
    elif "baselines" in data:  # baseline list
        rows = data["baselines"]
        headers = ["name", "target", "ports_scanned", "ports_open", "created"]
    elif "addresses" in data:  # dns
        rows = data["addresses"]
        headers = ["ip", "family"]
    else:
        rows = [data]
        headers = sorted(data.keys())
    table = [[row.get(h, "") for h in headers] for row in rows]
    # Flatten list values for CSV cells.
    table = [
        [(";".join(map(str, c)) if isinstance(c, list) else c) for c in row]
        for row in table
    ]
    return headers, table


def render(result: Result, args: argparse.Namespace) -> str:
    if args.json:
        return json.dumps(result.to_dict(), indent=2)
    if args.csv:
        headers, rows = _csv_rows(result)
        buf = io.StringIO()
        writer = csv.writer(buf)
        writer.writerow(headers)
        writer.writerows(rows)
        return buf.getvalue().rstrip("\n")
    return render_human(result)


# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------


def _add_output_flags(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--json", action="store_true", help="emit the result envelope as JSON"
    )
    parser.add_argument("--csv", action="store_true", help="emit primary data as CSV")


def _add_timeout_flags(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--timeout",
        type=float,
        default=None,
        help="per-operation timeout in seconds (overrides config)",
    )


def _add_scan_flags(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--ports",
        default=None,
        help="comma-separated ports, e.g. 22,80,443",
    )
    parser.add_argument(
        "--port-range",
        default=None,
        help="inclusive port range, e.g. 1-1024 (combinable with --ports)",
    )
    parser.add_argument(
        "--retries",
        type=int,
        default=None,
        help="connect retries on timeout (max 5)",
    )
    parser.add_argument(
        "--max-parallel",
        type=int,
        default=None,
        help="concurrent connections (max 100)",
    )
    parser.add_argument(
        "--no-banner",
        action="store_true",
        help="skip banner grabbing on open ports",
    )
    parser.add_argument(
        "--no-service-probes",
        action="store_true",
        help="skip TLS/HTTP/banner probing (port states only)",
    )
    parser.add_argument(
        "--allow-remote",
        action="store_true",
        help="permit scanning public targets; confirm you are authorized first",
    )
    _add_timeout_flags(parser)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="aegisforge",
        description="AegisForge — modular defensive-security and DFIR platform "
        "(v0.2: core + network discovery + port/service analysis). "
        "Commercial software: 1-week free trial, see LICENSE.",
    )
    parser.add_argument(
        "--version", action="version", version=f"%(prog)s {__version__}"
    )
    parser.add_argument(
        "--verbose", action="store_true", help="debug diagnostics on stderr"
    )
    parser.add_argument("--config", default=None, help="path to JSON config file")
    parser.add_argument("--profile", default="default", help="config profile name")
    _add_output_flags(parser)

    # Output flags must also work after the subcommand
    # (e.g. `aegisforge network dns x --json`).
    output_parent = argparse.ArgumentParser(add_help=False)
    _add_output_flags(output_parent)
    parents = [output_parent]

    sub = parser.add_subparsers(dest="group", required=True)

    # config group
    config_p = sub.add_parser("config", help="configuration")
    config_sub = config_p.add_subparsers(dest="command", required=True)
    config_show = config_sub.add_parser(
        "show", help="show effective configuration", parents=parents
    )
    config_show.set_defaults(func=cmd_config_show)

    # network group
    net_p = sub.add_parser("network", help="network discovery")
    net_sub = net_p.add_subparsers(dest="command", required=True)

    p_subnet = net_sub.add_parser(
        "subnet", help="IPv4/IPv6 subnet calculator", parents=parents
    )
    p_subnet.add_argument("cidr", help="CIDR block, e.g. 192.168.1.0/24")
    p_subnet.add_argument(
        "--expand", action="store_true", help="list host addresses (bounded)"
    )
    p_subnet.add_argument(
        "--max-hosts",
        type=int,
        default=1024,
        help="max addresses for --expand (hard cap 65536)",
    )
    p_subnet.set_defaults(func=cmd_subnet)

    p_ping = net_sub.add_parser(
        "ping", help="ICMP reachability for explicit targets", parents=parents
    )
    p_ping.add_argument(
        "targets", nargs="+", help="one or more hostnames/IPs (max 256)"
    )
    p_ping.add_argument(
        "--count", type=int, default=None, help="echo requests per host"
    )
    _add_timeout_flags(p_ping)
    p_ping.add_argument(
        "--max-parallel", type=int, default=None, help="concurrent hosts (max 50)"
    )
    p_ping.set_defaults(func=cmd_ping)

    p_dns = net_sub.add_parser(
        "dns", help="forward/reverse DNS lookup", parents=parents
    )
    p_dns.add_argument("target", help="DNS name or IP address")
    _add_timeout_flags(p_dns)
    p_dns.set_defaults(func=cmd_dns)

    p_trace = net_sub.add_parser(
        "trace", help="bounded traceroute to an explicit target", parents=parents
    )
    p_trace.add_argument("target", help="hostname or IP address")
    p_trace.add_argument(
        "--max-hops", type=int, default=None, help="max hops (hard cap 64)"
    )
    _add_timeout_flags(p_trace)
    p_trace.set_defaults(func=cmd_trace)

    p_if = net_sub.add_parser(
        "interfaces", help="local interface discovery", parents=parents
    )
    p_if.add_argument(
        "--include-routes", action="store_true", help="include routing table"
    )
    p_if.add_argument(
        "--include-neighbours",
        action="store_true",
        help="include ARP/neighbour table (Linux)",
    )
    p_if.set_defaults(func=cmd_interfaces)

    p_inv = net_sub.add_parser(
        "inventory", help="local asset inventory", parents=parents
    )
    p_inv.set_defaults(func=cmd_inventory)

    p_scan = net_sub.add_parser(
        "scan",
        help="authorized TCP port/service scan of one target",
        parents=parents,
    )
    p_scan.add_argument("target", help="hostname or IP address to scan")
    _add_scan_flags(p_scan)
    p_scan.set_defaults(func=cmd_scan)

    p_base = net_sub.add_parser(
        "baseline",
        help="scan baselines: save, diff, list",
        parents=parents,
    )
    base_sub = p_base.add_subparsers(dest="baseline_command", required=True)

    b_save = base_sub.add_parser(
        "save", help="scan a target and store it as a baseline", parents=parents
    )
    b_save.add_argument("name", help="baseline name (letters, digits, - and _)")
    b_save.add_argument("target", help="hostname or IP address to scan")
    _add_scan_flags(b_save)
    b_save.set_defaults(func=cmd_baseline)

    b_diff = base_sub.add_parser(
        "diff", help="rescan a target and diff against a baseline", parents=parents
    )
    b_diff.add_argument("name", help="baseline name to compare against")
    b_diff.add_argument("target", help="hostname or IP address to rescan")
    _add_scan_flags(b_diff)
    b_diff.set_defaults(func=cmd_baseline)

    b_list = base_sub.add_parser("list", help="list stored baselines", parents=parents)
    b_list.set_defaults(func=cmd_baseline)

    b_show = base_sub.add_parser("show", help="show a stored baseline", parents=parents)
    b_show.add_argument("name", help="baseline name")
    b_show.set_defaults(func=cmd_baseline)

    b_delete = base_sub.add_parser(
        "delete", help="delete a stored baseline", parents=parents
    )
    b_delete.add_argument("name", help="baseline name")
    b_delete.set_defaults(func=cmd_baseline)

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    configure_logging(args.verbose)

    # Friendly trial notice on startup (stderr, non-blocking, no lockout in v0.1).
    print_trial_notice(trial_status())

    try:
        overrides: dict[str, Any] = {}
        cfg = config_mod.load_config(
            path=args.config, profile=args.profile, overrides=overrides or None
        )
    except ConfigError as exc:
        print(f"aegisforge: error: {exc}", file=sys.stderr)
        audit_log(
            {
                "command": "config-load",
                "argv": list(argv or []),
                "exit_code": EXIT_ERROR,
            }
        )
        return EXIT_ERROR

    try:
        result: Result = args.func(args, cfg)
    except ValidationError as exc:
        print(f"aegisforge: error: {exc}", file=sys.stderr)
        audit_log(
            {
                "command": getattr(args, "command", "?"),
                "argv": list(argv or []),
                "exit_code": EXIT_ERROR,
            }
        )
        return EXIT_ERROR
    except KeyboardInterrupt:
        print("aegisforge: interrupted", file=sys.stderr)
        return EXIT_ERROR

    output = render(result, args)
    if output:
        print(output)
    code = exit_code_for(result)
    if result.status == "error" and result.summary:
        print(f"aegisforge: error: {result.summary}", file=sys.stderr)
    audit_log(
        {
            "command": result.command,
            "target": result.target,
            "status": result.status,
            "exit_code": code,
        }
    )
    return code
