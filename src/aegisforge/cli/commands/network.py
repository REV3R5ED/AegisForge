"""Network discovery command implementations."""

from __future__ import annotations

import argparse
from typing import Any

from aegisforge.core.config import AppConfig
from aegisforge.core.events import Event
from aegisforge.core.findings import Finding
from aegisforge.core.results import Result
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
