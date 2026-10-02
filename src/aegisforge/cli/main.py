"""AegisForge CLI: ``aegisforge network ...`` (v0.1).

Every command returns a shared result envelope, renders human-readable
text by default (``--json`` / ``--csv`` for automation), uses structured
exit codes (0 ok / 1 findings / 2 error), and writes an audit record.
Diagnostics go to stderr; stdout carries only the requested output.
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
from aegisforge.network import dns as dns_mod
from aegisforge.network import interfaces as interfaces_mod
from aegisforge.network import inventory as inventory_mod
from aegisforge.network import ping as ping_mod
from aegisforge.network import subnet as subnet_mod
from aegisforge.network import trace as trace_mod
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
    if data:
        lines.append("")
        lines.extend(_kv_lines(data))
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


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="aegisforge",
        description="AegisForge — modular defensive-security and DFIR platform "
        "(v0.1: core + network discovery). Commercial software: "
        "1-week free trial, see LICENSE.",
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
