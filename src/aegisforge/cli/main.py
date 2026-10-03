"""AegisForge CLI: ``aegisforge network ...`` / ``aegisforge domain ...`` /
``aegisforge logs ...`` / ``aegisforge forensics ...`` /
``aegisforge case ...``.

Every command returns a shared result envelope, renders human-readable
text by default (``--json`` / ``--csv`` for automation), uses structured
exit codes (0 ok / 1 findings / 2 error), and writes an audit record.
Diagnostics go to stderr; stdout carries only the requested output.

v0.2 adds authorized TCP port/service scanning (``network scan``) with
explicit remote-target consent (``--allow-remote``) and scan baselines
with change detection (``network baseline``).

v0.3 adds domain investigation (``domain dns``, ``domain investigate``):
passive DNS/RDAP/WHOIS/HTTP lookups consolidated into one report.
Unlike port scanning, these are directory lookups the target's public
services already answer for any client, so no ``--allow-remote`` gate
is required.

v0.5 adds log analysis (``logs detect``, ``logs analyze``): streaming
parsers for syslog, Apache/Nginx, JSON lines, Windows Event XML
exports and key=value, with format auto-detection, timeline,
histograms, top talkers, error extraction and burst detection.
``--redact`` masks IPs/emails in output only (source files untouched).

v0.4 adds digital forensics (``forensics inventory``, ``forensics
manifest``, ``forensics verify``, ``forensics duplicates``,
``forensics timeline``): read-only recursive file inventory with
magic-byte identification, single-pass multi-algorithm hashing,
sealed evidence manifests, manifest verification
(changed/missing/new), duplicate detection and filesystem timelines.
Numbered v0.4 per the master plan; it shipped after v0.5.

v0.6 adds the incident-response engine (``case create``, ``case
attach``, ``case timeline``, ``case finding``/``case findings``,
``case link``, ``case note``, ``case report``, ``case status``):
case folders with copied (never moved) hashed evidence, a unified
chronological timeline across log/file/network evidence, finding
tracking with lifecycle states, indicator linking with
guessed-vs-specified types, append-only analyst notes and
reproducible report bundles with per-artifact SHA-256 manifests.
"""

from __future__ import annotations

import argparse
import csv
import io
import json
import os
import sys
from collections.abc import Sequence
from typing import Any

from aegisforge import __version__
from aegisforge.cases import evidence as cases_evidence_mod
from aegisforge.cases import findings as cases_findings_mod
from aegisforge.cases import report as cases_report_mod
from aegisforge.cases import store as cases_store_mod
from aegisforge.cases import timeline as cases_timeline_mod
from aegisforge.cases.store import CaseError
from aegisforge.core import config as config_mod
from aegisforge.core.config import AppConfig, ConfigError
from aegisforge.core.events import Event
from aegisforge.core.findings import Finding
from aegisforge.core.license import print_trial_notice, trial_status
from aegisforge.core.logging import audit_log, configure_logging, get_logger
from aegisforge.core.results import EXIT_ERROR, EXIT_OK, Result, exit_code_for
from aegisforge.domain import dns_client as domain_dns_client
from aegisforge.domain import investigate as investigate_mod
from aegisforge.forensics import duplicates as forensics_duplicates_mod
from aegisforge.forensics import hashing as forensics_hashing_mod
from aegisforge.forensics import inventory as forensics_inventory_mod
from aegisforge.forensics import manifest as forensics_manifest_mod
from aegisforge.forensics import timeline as forensics_timeline_mod
from aegisforge.intel import engine as intel_engine_mod
from aegisforge.intel.cache import IntelCache
from aegisforge.intel.normalize import normalize_indicator
from aegisforge.intel.ratelimit import RateLimiter
from aegisforge.logs import analyze as logs_analyze_mod
from aegisforge.logs import detect as logs_detect_mod
from aegisforge.logs import redact as logs_redact_mod
from aegisforge.logs.analyze import AnalyzeOptions
from aegisforge.logs.filters import LogFilter
from aegisforge.logs.models import PARSER_UNKNOWN
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
from aegisforge.pcap import analyze as pcap_analyze_mod
from aegisforge.pcap.analyze import AnalyzeOptions as PcapAnalyzeOptions
from aegisforge.pcap.reader import PcapError

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
# v0.3: domain investigation commands
# ---------------------------------------------------------------------------


def _record_detail(record: dict[str, Any]) -> str:
    """One-line human summary of a DNS record's data."""
    data = record.get("data", {})
    rtype = record.get("rtype", "")
    if rtype == "A" or rtype == "AAAA":
        return str(data.get("address", ""))
    if rtype == "MX":
        return f"{data.get('preference')} {data.get('exchange')}"
    if rtype == "NS":
        return str(data.get("nameserver", ""))
    if rtype == "CNAME":
        return str(data.get("target", ""))
    if rtype == "TXT":
        text = str(data.get("text", ""))
        return text[:80] + ("…" if len(text) > 80 else "")
    if rtype == "SOA":
        return f"mname={data.get('mname')} serial={data.get('serial')}"
    if rtype == "DNSKEY":
        return (
            f"flags={data.get('flags')} alg={data.get('algorithm')} "
            f"key_tag={data.get('key_tag')}"
        )
    if rtype == "DS":
        digest = str(data.get("digest", ""))[:24]
        return f"key_tag={data.get('key_tag')} digest={digest}…"
    return json.dumps(data, sort_keys=True)[:80]


def cmd_domain_dns(args: argparse.Namespace, cfg: AppConfig) -> Result:
    result = Result(command="domain dns", target=args.name)
    qtype = args.type.upper()
    resolver = args.resolver or cfg.get("domain_resolver") or None
    timeout = args.timeout if args.timeout is not None else cfg["domain_dns_timeout"]
    try:
        response = domain_dns_client.query(
            args.name, qtype, resolver=resolver, timeout=timeout
        )
    except (domain_dns_client.DNSError, ValidationError) as exc:
        result.fail(str(exc))
        return result
    records = [answer.to_dict() for answer in response.answers]
    for record in records:
        record["detail"] = _record_detail(record)
    result.data = {
        "name": args.name,
        "qtype": qtype,
        "resolver": resolver or "(system)",
        "rcode": response.rcode_name,
        "records": records,
        "warnings": response.warnings,
    }
    result.summary = (
        f"{args.name}/{qtype}: {len(records)} record(s) ({response.rcode_name})"
    )
    result.add_event(
        Event(
            event_type="domain.dns.queried",
            source="aegisforge",
            host=args.name,
            evidence={
                "qtype": qtype,
                "rcode": response.rcode_name,
                "answer_count": len(records),
            },
        )
    )
    return result


def cmd_domain_investigate(args: argparse.Namespace, cfg: AppConfig) -> Result:
    result = Result(command="domain investigate", target=args.domain)
    resolver = args.resolver or cfg.get("domain_resolver") or None
    timeout = args.timeout if args.timeout is not None else cfg["domain_dns_timeout"]
    try:
        options = investigate_mod.DomainOptions(
            resolver=resolver,
            timeout=timeout,
            rdap=not args.no_rdap,
            whois=not args.no_whois,
            web=not args.no_web,
            tls=not args.no_tls,
        )
        report = investigate_mod.investigate_domain(args.domain, options)
    except ValidationError as exc:
        result.fail(str(exc))
        return result
    result.data = report.to_dict()
    findings = investigate_mod.analyze_findings(report)
    for finding in findings:
        result.add_finding(finding)
    error_count = len(report.errors)
    result.summary = (
        f"domain investigation of {report.domain}: "
        f"{len(findings)} finding(s), {error_count} error(s)"
    )
    result.add_event(
        Event(
            event_type="domain.investigation.completed",
            source="aegisforge",
            host=report.domain,
            evidence={
                "record_types": sorted(report.dns.get("records", {}).keys()),
                "nameservers": len(report.nameservers.get("nameservers", [])),
                "findings": len(findings),
                "errors": report.errors,
            },
        )
    )
    return result


# ---------------------------------------------------------------------------
# v0.4: log analysis commands
# ---------------------------------------------------------------------------


def cmd_logs_detect(args: argparse.Namespace, cfg: AppConfig) -> Result:
    result = Result(command="logs detect", target=args.file)
    try:
        detection = logs_detect_mod.detect_file(args.file)
    except OSError as exc:
        result.fail(f"cannot read {args.file}: {exc}")
        return result
    result.data = {"file": args.file, **detection.to_dict()}
    if detection.parser == PARSER_UNKNOWN:
        result.summary = (
            f"{args.file}: log format unknown "
            f"(best score {detection.confidence:.2f}); pass --format explicitly"
        )
    else:
        result.summary = (
            f"{args.file}: detected {detection.parser} format "
            f"(confidence {detection.confidence:.2f})"
        )
    result.add_event(
        Event(
            event_type="logs.format.detected",
            source="aegisforge",
            evidence={
                "file": args.file,
                "parser": detection.parser,
                "confidence": round(detection.confidence, 3),
            },
        )
    )
    return result


def cmd_logs_analyze(args: argparse.Namespace, cfg: AppConfig) -> Result:
    result = Result(command="logs analyze", target=args.file)
    try:
        filt = LogFilter(
            since=args.since,
            until=args.until,
            levels=tuple(args.level or ()),
            contains=tuple(args.contains or ()),
            not_contains=tuple(args.not_contains or ()),
            host=args.host,
            limit=args.limit,
        )
        options = AnalyzeOptions(
            parser_name=args.format,
            burst_window=(
                args.burst_window
                if args.burst_window is not None
                else cfg["logs_burst_window"]
            ),
            burst_threshold=(
                args.burst_threshold
                if args.burst_threshold is not None
                else cfg["logs_burst_threshold"]
            ),
            context_lines=(
                args.context if args.context is not None else cfg["logs_context_lines"]
            ),
        )
        analysis = logs_analyze_mod.analyze_file(args.file, filt, options)
    except (ValidationError, ValueError, OSError) as exc:
        result.fail(str(exc))
        return result
    data = analysis.to_dict()
    # Rename for the CSV renderer (primary table = the matched events).
    data["log_events"] = data.pop("events")
    data["filters"] = filt.describe()
    data["redacted"] = bool(args.redact)
    result.data = data
    for finding in analysis.findings:
        result.add_finding(finding)
    result.summary = (
        f"{args.file}: {analysis.events_matched} event(s) matched "
        f"({analysis.parser}), {len(analysis.findings)} finding(s), "
        f"{analysis.warning_count} warning(s)"
    )
    result.add_event(
        Event(
            event_type="logs.analysis.completed",
            source="aegisforge",
            evidence={
                "file": args.file,
                "parser": analysis.parser,
                "events_matched": analysis.events_matched,
                "warnings": analysis.warning_count,
                "findings": len(analysis.findings),
            },
        )
    )
    return result


def _forensics_algorithms(args: argparse.Namespace) -> tuple[str, ...]:
    chosen = tuple(args.algorithms) if args.algorithms else ("sha256",)
    unknown = [a for a in chosen if a not in forensics_hashing_mod.SUPPORTED_ALGORITHMS]
    if unknown:
        raise ValidationError(f"unsupported hash algorithm(s): {', '.join(unknown)}")
    # Preserve order, drop duplicates.
    return tuple(dict.fromkeys(chosen))


def _check_root(path: str) -> str | None:
    """Return an error message when *path* cannot be scanned, else None."""
    if not os.path.exists(path):
        return f"path does not exist: {path}"
    if not os.access(path, os.R_OK):
        return f"path is not readable: {path}"
    return None


def cmd_forensics_inventory(args: argparse.Namespace, cfg: AppConfig) -> Result:
    result = Result(command="forensics inventory", target=args.path)
    problem = _check_root(args.path)
    if problem is not None:
        result.fail(problem)
        return result
    try:
        algos = _forensics_algorithms(args)
        inv = forensics_inventory_mod.run_inventory(
            args.path,
            include=tuple(args.include or ()),
            exclude=tuple(args.exclude or ()),
            hash_algorithms=algos,
        )
    except (ValidationError, ValueError, OSError) as exc:
        result.fail(str(exc))
        return result
    data = inv.to_dict()
    result.data = data
    stats = inv.stats
    result.summary = (
        f"{args.path}: {stats.files} file(s), {stats.total_bytes} byte(s), "
        f"{stats.warnings} warning(s)"
    )
    result.add_event(
        Event(
            event_type="forensics.inventory.completed",
            source="aegisforge",
            evidence={
                "root": args.path,
                "files": stats.files,
                "total_bytes": stats.total_bytes,
                "warnings": stats.warnings,
                "algorithms": list(algos),
            },
        )
    )
    return result


def cmd_forensics_manifest(args: argparse.Namespace, cfg: AppConfig) -> Result:
    result = Result(command="forensics manifest", target=args.path)
    problem = _check_root(args.path)
    if problem is not None:
        result.fail(problem)
        return result
    try:
        algos = _forensics_algorithms(args)
        inv = forensics_inventory_mod.run_inventory(
            args.path,
            include=tuple(args.include or ()),
            exclude=tuple(args.exclude or ()),
            hash_algorithms=algos,
        )
        manifest = forensics_manifest_mod.build_manifest(inv, operator_note=args.note)
        out_path = forensics_manifest_mod.write_manifest(manifest, args.output)
    except (ValidationError, ValueError, OSError) as exc:
        result.fail(str(exc))
        return result
    sha = manifest["manifest_sha256"]
    # Tamper-evidence seam: the manifest digest goes to the audit log.
    audit_log(
        {
            "command": "forensics manifest",
            "target": args.path,
            "manifest": out_path,
            "manifest_sha256": sha,
            "file_count": manifest["file_count"],
            "exit_code": EXIT_OK,
        }
    )
    result.data = {
        "manifest_path": out_path,
        "manifest_sha256": sha,
        "file_count": manifest["file_count"],
        "total_bytes": manifest["total_bytes"],
        "created": manifest["created"],
        "root": manifest["root"],
    }
    result.summary = (
        f"manifest written to {out_path}: {manifest['file_count']} file(s), "
        f"sha256 {sha[:16]}…"
    )
    result.add_event(
        Event(
            event_type="forensics.manifest.created",
            source="aegisforge",
            evidence={
                "root": args.path,
                "manifest": out_path,
                "manifest_sha256": sha,
                "file_count": manifest["file_count"],
            },
        )
    )
    return result


def cmd_forensics_verify(args: argparse.Namespace, cfg: AppConfig) -> Result:
    result = Result(command="forensics verify", target=args.manifest)
    try:
        manifest = forensics_manifest_mod.read_manifest(args.manifest)
    except ValueError as exc:
        result.fail(str(exc))
        return result
    try:
        vr = forensics_manifest_mod.verify_manifest(manifest, root=args.root)
    except (ValueError, OSError) as exc:
        result.fail(str(exc))
        return result
    for finding in forensics_manifest_mod.verify_findings(vr):
        result.add_finding(finding)
    result.data = vr.to_dict()
    result.summary = (
        f"{args.manifest}: {vr.verified} verified, {len(vr.changed)} changed, "
        f"{len(vr.missing)} missing, {len(vr.new)} new"
    )
    result.add_event(
        Event(
            event_type="forensics.verify.completed",
            source="aegisforge",
            evidence={
                "manifest": args.manifest,
                "root": vr.root,
                "verified": vr.verified,
                "changed": len(vr.changed),
                "missing": len(vr.missing),
                "new": len(vr.new),
                "ok": vr.ok,
            },
        )
    )
    return result


def cmd_forensics_duplicates(args: argparse.Namespace, cfg: AppConfig) -> Result:
    result = Result(command="forensics duplicates", target=args.path)
    problem = _check_root(args.path)
    if problem is not None:
        result.fail(problem)
        return result
    try:
        inv = forensics_inventory_mod.run_inventory(
            args.path,
            include=tuple(args.include or ()),
            exclude=tuple(args.exclude or ()),
            hash_algorithms=("sha256",),
        )
    except (ValidationError, ValueError, OSError) as exc:
        result.fail(str(exc))
        return result
    groups = forensics_duplicates_mod.find_duplicates(inv.files)
    dup_files = sum(g.count for g in groups)
    result.data = {
        "root": args.path,
        "groups": [g.to_dict() for g in groups],
        "group_count": len(groups),
        "duplicate_files": dup_files,
        "files_scanned": inv.stats.files,
    }
    result.summary = (
        f"{args.path}: {len(groups)} duplicate group(s), "
        f"{dup_files} file(s) sharing content"
    )
    result.add_event(
        Event(
            event_type="forensics.duplicates.completed",
            source="aegisforge",
            evidence={
                "root": args.path,
                "groups": len(groups),
                "duplicate_files": dup_files,
            },
        )
    )
    return result


def cmd_forensics_timeline(args: argparse.Namespace, cfg: AppConfig) -> Result:
    result = Result(command="forensics timeline", target=args.path)
    problem = _check_root(args.path)
    if problem is not None:
        result.fail(problem)
        return result
    try:
        inv = forensics_inventory_mod.run_inventory(
            args.path,
            include=tuple(args.include or ()),
            exclude=tuple(args.exclude or ()),
            hash_algorithms=(),  # timestamps only; no hashing needed
        )
    except (ValidationError, ValueError, OSError) as exc:
        result.fail(str(exc))
        return result
    entries = forensics_timeline_mod.build_timeline(inv.files)
    if args.limit is not None and args.limit >= 0:
        entries = entries[: args.limit]
    result.data = {
        "root": args.path,
        "timeline": [e.to_dict() for e in entries],
        "entries": len(entries),
        "note": "filesystem timestamps (mtime/atime/ctime) — filesystem "
        "metadata, not content claims",
    }
    result.summary = f"{args.path}: {len(entries)} filesystem timestamp(s)"
    result.add_event(
        Event(
            event_type="forensics.timeline.completed",
            source="aegisforge",
            evidence={"root": args.path, "entries": len(entries)},
        )
    )
    return result


# ---------------------------------------------------------------------------
# Case management (v0.6) — incident-response engine
# ---------------------------------------------------------------------------


def _case_or_fail(result: Result, case_id: str) -> Any | None:
    try:
        return cases_store_mod.load_case(case_id)
    except CaseError as exc:
        result.fail(str(exc))
        return None


def _case_event(event_type: str, case_id: str, evidence: dict[str, Any]) -> Event:
    return Event(
        event_type=event_type,
        source="aegisforge",
        evidence={"case_id": case_id, **evidence},
    )


def cmd_case_create(args: argparse.Namespace, cfg: AppConfig) -> Result:
    result = Result(command="case create")
    try:
        case = cases_store_mod.create_case(args.title, note=args.note)
    except CaseError as exc:
        result.fail(str(exc))
        return result
    result.target = case.case_id
    result.data = case.to_dict()
    result.summary = f"case {case.case_id} created: {case.title}"
    result.add_event(_case_event("case.created", case.case_id, {"title": case.title}))
    return result


def cmd_case_list(args: argparse.Namespace, cfg: AppConfig) -> Result:
    result = Result(command="case list")
    cases = cases_store_mod.list_cases()
    result.data = {
        "cases": [
            {
                "case_id": c.case_id,
                "title": c.title,
                "status": c.status,
                "created": c.created,
                "evidence": len(c.evidence),
                "findings": len(c.findings),
                "notes": len(c.notes),
            }
            for c in cases
        ],
        "count": len(cases),
    }
    result.summary = f"{len(cases)} case(s)"
    return result


def cmd_case_show(args: argparse.Namespace, cfg: AppConfig) -> Result:
    result = Result(command="case show", target=args.case_id)
    case = _case_or_fail(result, args.case_id)
    if case is None:
        return result
    result.data = case.to_dict()
    result.summary = (
        f"{case.case_id}: {case.title} [{case.status}] — "
        f"{len(case.evidence)} evidence, {len(case.findings)} findings, "
        f"{len(case.notes)} notes"
    )
    return result


def cmd_case_attach(args: argparse.Namespace, cfg: AppConfig) -> Result:
    result = Result(command="case attach", target=args.case_id)
    case = _case_or_fail(result, args.case_id)
    if case is None:
        return result
    try:
        record = cases_evidence_mod.attach_evidence(case, args.kind, args.source)
    except CaseError as exc:
        result.fail(str(exc))
        return result
    result.data = record.to_dict()
    result.summary = (
        f"attached {args.source} to {case.case_id} as "
        f"{record.evidence_id} (sha256 {record.sha256[:16]}…)"
    )
    result.add_event(
        _case_event(
            "case.evidence.attached",
            case.case_id,
            {
                "evidence_id": record.evidence_id,
                "kind": record.kind,
                "sha256": record.sha256,
            },
        )
    )
    return result


def cmd_case_timeline(args: argparse.Namespace, cfg: AppConfig) -> Result:
    result = Result(command="case timeline", target=args.case_id)
    case = _case_or_fail(result, args.case_id)
    if case is None:
        return result
    timed, untimed = cases_timeline_mod.build_case_timeline(case)
    if args.limit is not None and args.limit >= 0:
        timed = timed[: args.limit]
    result.data = {
        "case_id": case.case_id,
        "timeline_entries": [e.to_dict() for e in timed],
        "untimed": [e.to_dict() for e in untimed],
        "timed_count": len(timed),
        "untimed_count": len(untimed),
        "note": "Filesystem timestamps are filesystem metadata claims, not "
        "content claims. Untimed events are listed separately, never dropped.",
    }
    result.summary = (
        f"{case.case_id}: {len(timed)} timed event(s), {len(untimed)} untimed event(s)"
    )
    result.add_event(
        _case_event(
            "case.timeline.built",
            case.case_id,
            {"timed": len(timed), "untimed": len(untimed)},
        )
    )
    return result


def cmd_case_finding(args: argparse.Namespace, cfg: AppConfig) -> Result:
    result = Result(command="case finding", target=args.case_id)
    case = _case_or_fail(result, args.case_id)
    if case is None:
        return result
    try:
        finding = cases_findings_mod.add_case_finding(
            case,
            title=args.title,
            severity=args.severity,
            confidence=args.confidence,
            detail=args.detail or "",
        )
        cases_store_mod.save_case(case)
    except CaseError as exc:
        result.fail(str(exc))
        return result
    result.data = finding.to_dict()
    result.summary = (
        f"finding {finding.finding_id} recorded in {case.case_id}: "
        f"{finding.title} [{finding.severity}]"
    )
    result.add_finding(
        Finding(
            title=finding.title,
            severity=finding.severity,
            confidence=finding.confidence,
            reason=finding.detail,
            evidence=[f"case {case.case_id}", f"finding {finding.finding_id}"],
        )
    )
    result.add_event(
        _case_event(
            "case.finding.recorded",
            case.case_id,
            {"finding_id": finding.finding_id, "severity": finding.severity},
        )
    )
    return result


def cmd_case_findings(args: argparse.Namespace, cfg: AppConfig) -> Result:
    result = Result(command="case findings", target=args.case_id)
    case = _case_or_fail(result, args.case_id)
    if case is None:
        return result
    findings = case.findings
    if args.status:
        findings = [f for f in findings if f.status == args.status]
    result.data = {
        "case_id": case.case_id,
        "case_findings": [f.to_dict() for f in findings],
        "count": len(findings),
    }
    result.summary = f"{case.case_id}: {len(findings)} finding(s)"
    return result


def cmd_case_link(args: argparse.Namespace, cfg: AppConfig) -> Result:
    result = Result(command="case link", target=args.case_id)
    case = _case_or_fail(result, args.case_id)
    if case is None:
        return result
    try:
        link = cases_findings_mod.link_indicator(
            case, args.finding, args.indicator, type_override=args.type
        )
        cases_store_mod.save_case(case)
    except CaseError as exc:
        result.fail(str(exc))
        return result
    result.data = link.to_dict()
    origin = "analyst-specified" if link.type_source == "specified" else "guessed"
    result.summary = (
        f"linked {link.value!r} ({link.type}, type {origin}) "
        f"to {args.finding} in {case.case_id}"
    )
    result.add_event(
        _case_event(
            "case.indicator.linked",
            case.case_id,
            {
                "finding_id": args.finding,
                "indicator": link.value,
                "type": link.type,
                "type_source": link.type_source,
            },
        )
    )
    return result


def cmd_case_note(args: argparse.Namespace, cfg: AppConfig) -> Result:
    result = Result(command="case note", target=args.case_id)
    case = _case_or_fail(result, args.case_id)
    if case is None:
        return result
    try:
        note = cases_findings_mod.add_note(case, args.text)
        cases_store_mod.save_case(case)
    except CaseError as exc:
        result.fail(str(exc))
        return result
    result.data = note.to_dict()
    result.summary = f"note added to {case.case_id}"
    result.add_event(_case_event("case.note.added", case.case_id, {}))
    return result


def cmd_case_report(args: argparse.Namespace, cfg: AppConfig) -> Result:
    result = Result(command="case report", target=args.case_id)
    case = _case_or_fail(result, args.case_id)
    if case is None:
        return result
    try:
        summary = cases_report_mod.generate_report(case, args.output, force=args.force)
    except CaseError as exc:
        result.fail(str(exc))
        return result
    result.data = summary
    result.summary = (
        f"report for {case.case_id} written to {summary['output']}: "
        f"{summary['artifact_count']} artifact(s)"
    )
    result.add_event(
        _case_event(
            "case.report.generated",
            case.case_id,
            {"output": summary["output"], "artifacts": summary["artifact_count"]},
        )
    )
    return result


def cmd_case_status(args: argparse.Namespace, cfg: AppConfig) -> Result:
    result = Result(command="case status", target=args.case_id)
    case = _case_or_fail(result, args.case_id)
    if case is None:
        return result
    if args.status is None:
        result.data = {"case_id": case.case_id, "status": case.status}
        result.summary = f"{case.case_id} status: {case.status}"
        return result
    try:
        cases_findings_mod.set_case_status(case, args.status, note=args.note)
        cases_store_mod.save_case(case)
    except CaseError as exc:
        result.fail(str(exc))
        return result
    result.data = {"case_id": case.case_id, "status": case.status}
    result.summary = f"{case.case_id} status -> {case.status}"
    result.add_event(
        _case_event("case.status.changed", case.case_id, {"status": case.status})
    )
    return result


def _pcap_options(args: argparse.Namespace, cfg: AppConfig) -> PcapAnalyzeOptions:
    return PcapAnalyzeOptions(
        burst_window=int(cfg["pcap_burst_window"]),
        burst_threshold=int(cfg["pcap_burst_threshold"]),
        unusual_port_packets=int(cfg["pcap_unusual_port_packets"]),
        top=args.top if getattr(args, "top", None) else int(cfg["pcap_top_n"]),
    )


def _pcap_check(path: str) -> str | None:
    if not os.path.exists(path):
        return f"file does not exist: {path}"
    if not os.path.isfile(path):
        return f"not a file: {path}"
    if not os.access(path, os.R_OK):
        return f"file is not readable: {path}"
    return None


def cmd_pcap_summary(args: argparse.Namespace, cfg: AppConfig) -> Result:
    result = Result(command="pcap summary", target=args.file)
    problem = _pcap_check(args.file)
    if problem is not None:
        result.fail(problem)
        return result
    try:
        summary = pcap_analyze_mod.summarize(args.file, _pcap_options(args, cfg))
    except PcapError as exc:
        result.fail(str(exc))
        return result
    data = summary.to_dict()
    data["pcap_talkers"] = [
        {"ip": ip, "packets": count} for ip, count in data["top_talkers_packets"]
    ]
    result.data = data
    for finding in summary.findings:
        result.add_finding(finding)
    result.summary = (
        f"{args.file}: {summary.packet_count} packet(s), "
        f"{summary.total_bytes} bytes, {len(summary.findings)} finding(s), "
        f"{summary.warning_count} warning(s)"
    )
    result.add_event(
        Event(
            event_type="pcap.analysis.completed",
            source="aegisforge",
            evidence={
                "file": args.file,
                "packets": summary.packet_count,
                "bytes": summary.total_bytes,
                "warnings": summary.warning_count,
                "findings": len(summary.findings),
            },
        )
    )
    return result


def cmd_pcap_conversations(args: argparse.Namespace, cfg: AppConfig) -> Result:
    result = Result(command="pcap conversations", target=args.file)
    problem = _pcap_check(args.file)
    if problem is not None:
        result.fail(problem)
        return result
    try:
        conv = pcap_analyze_mod.conversations(args.file, _pcap_options(args, cfg))
    except PcapError as exc:
        result.fail(str(exc))
        return result
    data = conv.to_dict()
    data["pcap_flows"] = data.pop("flows")
    result.data = data
    result.summary = (
        f"{args.file}: {len(conv.flows)} conversation(s) shown, "
        f"{conv.warning_count} warning(s)"
    )
    result.add_event(
        Event(
            event_type="pcap.conversations.completed",
            source="aegisforge",
            evidence={"file": args.file, "flows_shown": len(conv.flows)},
        )
    )
    return result


def cmd_pcap_dns(args: argparse.Namespace, cfg: AppConfig) -> Result:
    result = Result(command="pcap dns", target=args.file)
    problem = _pcap_check(args.file)
    if problem is not None:
        result.fail(problem)
        return result
    try:
        dns = pcap_analyze_mod.dns_activity(args.file, _pcap_options(args, cfg))
    except PcapError as exc:
        result.fail(str(exc))
        return result
    data = dns.to_dict()
    data["pcap_dns"] = data.pop("queries")
    result.data = data
    result.summary = (
        f"{args.file}: {len(dns.queries)} queried name(s), "
        f"{dns.malformed_count} malformed, {dns.warning_count} warning(s)"
    )
    result.add_event(
        Event(
            event_type="pcap.dns.completed",
            source="aegisforge",
            evidence={
                "file": args.file,
                "names": len(dns.queries),
                "malformed": dns.malformed_count,
            },
        )
    )
    return result


def cmd_pcap_http(args: argparse.Namespace, cfg: AppConfig) -> Result:
    result = Result(command="pcap http", target=args.file)
    problem = _pcap_check(args.file)
    if problem is not None:
        result.fail(problem)
        return result
    try:
        http = pcap_analyze_mod.http_metadata(args.file, _pcap_options(args, cfg))
    except PcapError as exc:
        result.fail(str(exc))
        return result
    data = http.to_dict()
    data["pcap_http"] = data.pop("records")
    result.data = data
    result.summary = (
        f"{args.file}: {len(http.records)} HTTP record(s), "
        f"{http.warning_count} warning(s)"
    )
    result.add_event(
        Event(
            event_type="pcap.http.completed",
            source="aegisforge",
            evidence={"file": args.file, "records": len(http.records)},
        )
    )
    return result


def cmd_pcap_tls(args: argparse.Namespace, cfg: AppConfig) -> Result:
    result = Result(command="pcap tls", target=args.file)
    problem = _pcap_check(args.file)
    if problem is not None:
        result.fail(problem)
        return result
    try:
        tls = pcap_analyze_mod.tls_metadata(args.file, _pcap_options(args, cfg))
    except PcapError as exc:
        result.fail(str(exc))
        return result
    data = tls.to_dict()
    data["pcap_tls"] = data.pop("records")
    result.data = data
    result.summary = (
        f"{args.file}: {len(tls.records)} TLS ClientHello(s), "
        f"{tls.failed_count} unparsable, {tls.warning_count} warning(s)"
    )
    result.add_event(
        Event(
            event_type="pcap.tls.completed",
            source="aegisforge",
            evidence={"file": args.file, "records": len(tls.records)},
        )
    )
    return result


def cmd_pcap_indicators(args: argparse.Namespace, cfg: AppConfig) -> Result:
    result = Result(command="pcap indicators", target=args.file)
    problem = _pcap_check(args.file)
    if problem is not None:
        result.fail(problem)
        return result
    try:
        ind = pcap_analyze_mod.extract_indicators(args.file, _pcap_options(args, cfg))
    except PcapError as exc:
        result.fail(str(exc))
        return result
    data = ind.to_dict()
    data["pcap_indicators"] = data.pop("indicators")
    result.data = data
    result.summary = (
        f"{args.file}: {len(ind.indicators)} observed indicator(s), "
        f"{ind.warning_count} warning(s)"
    )
    result.add_event(
        Event(
            event_type="pcap.indicators.completed",
            source="aegisforge",
            evidence={"file": args.file, "indicators": len(ind.indicators)},
        )
    )
    return result


def cmd_pcap_timeline(args: argparse.Namespace, cfg: AppConfig) -> Result:
    result = Result(command="pcap timeline", target=args.file)
    problem = _pcap_check(args.file)
    if problem is not None:
        result.fail(problem)
        return result
    try:
        tl = pcap_analyze_mod.timeline(args.file, _pcap_options(args, cfg))
    except PcapError as exc:
        result.fail(str(exc))
        return result
    data = tl.to_dict()
    data["pcap_timeline"] = data.pop("events")
    result.data = data
    for entry in tl.events:
        result.add_event(
            Event(
                event_type=f"pcap.{entry.kind.replace('-', '.')}",
                source="pcap",
                severity=entry.severity,
                timestamp=entry.timestamp,
                evidence={"summary": entry.summary, "file": args.file},
            )
        )
    result.summary = (
        f"{args.file}: {len(tl.events)} timeline event(s), "
        f"{tl.warning_count} warning(s)"
    )
    return result


# ---------------------------------------------------------------------------
# Threat intelligence (v0.8)
# ---------------------------------------------------------------------------


def _intel_parts(cfg: AppConfig) -> tuple[IntelCache, RateLimiter]:
    cache = IntelCache(ttl_seconds=int(cfg.get("intel_cache_ttl")))
    limiter = RateLimiter(rate_per_second=float(cfg.get("intel_rate_limit")))
    return cache, limiter


def cmd_intel_lookup(args: argparse.Namespace, cfg: AppConfig) -> Result:
    result = Result(command="intel lookup", target=args.indicator)
    indicator = normalize_indicator(args.indicator)
    if indicator.rejected:
        result.fail(f"invalid indicator: {indicator.reject_reason}")
        return result
    selected = (
        [args.provider]
        if args.provider
        else intel_engine_mod.default_provider_selection(cfg)
    )
    cache, limiter = _intel_parts(cfg)
    try:
        providers, notices = intel_engine_mod.resolve_providers(
            selected, cfg, enrich=args.enrich, explicit=bool(args.provider)
        )
        enrichment = intel_engine_mod.enrich_indicators(
            [indicator], providers, cache, limiter
        )
    finally:
        cache.close()
    enrichment.notices.extend(notices)
    edata = enrichment.to_dict()
    edata["intel_records"] = edata.pop("records")
    result.data = {
        "indicator": indicator.to_dict(),
        **edata,
    }
    for finding in intel_engine_mod.findings_for_records(enrichment.records):
        result.add_finding(finding)
    verdicts = [r.verdict_label() for r in enrichment.records if not r.skipped]
    result.summary = (
        f"{indicator.value} ({indicator.type}): "
        f"{len(enrichment.records)} record(s); verdicts: "
        f"{', '.join(verdicts) if verdicts else 'none'}"
    )
    if enrichment.network_contacted:
        result.data["network_notice"] = (
            "NOTICE: the indicator was sent to network provider(s): "
            + ", ".join(enrichment.network_contacted)
            + " — indicators sent to providers leave this machine."
        )
    result.add_event(
        Event(
            event_type="intel.lookup.completed",
            source="aegisforge",
            evidence={
                "indicator": indicator.value,
                "type": indicator.type,
                "enrich": args.enrich,
                "providers": [p.name for p in providers],
                "network_contacted": enrichment.network_contacted,
            },
        )
    )
    return result


def _intel_case_indicators(case: Any) -> list[tuple[str, str]]:
    """(indicator value, evidence ref) pairs from a case's finding links."""
    pairs: list[tuple[str, str]] = []
    for finding in case.findings:
        for link in finding.indicators:
            pairs.append((link.value, f"case:{finding.finding_id}"))
    return pairs


def cmd_intel_correlate(args: argparse.Namespace, cfg: AppConfig) -> Result:
    result = Result(command="intel correlate", target=args.case_id)
    case = _case_or_fail(result, args.case_id)
    if case is None:
        return result
    evidence: list[tuple[Any, list[str]]] = []
    for value, ref in _intel_case_indicators(case):
        ind = normalize_indicator(value)
        evidence.append((ind, [ref]))
    if args.pcap:
        problem = _pcap_check(args.pcap)
        if problem is not None:
            result.fail(problem)
            return result
        try:
            ind_result = pcap_analyze_mod.extract_indicators(
                args.pcap, _pcap_options(args, cfg)
            )
        except PcapError as exc:
            result.fail(str(exc))
            return result
        for item in ind_result.indicators:
            ind = normalize_indicator(item.value)
            evidence.append((ind, [f"pcap:{args.pcap}"]))
    if not evidence:
        result.fail(
            f"{args.case_id} has no linked indicators"
            + (" and no pcap indicators were found" if args.pcap else "")
            + "; link indicators with 'case link' first"
        )
        return result
    selected = intel_engine_mod.default_provider_selection(cfg)
    cache, limiter = _intel_parts(cfg)
    try:
        providers, notices = intel_engine_mod.resolve_providers(
            selected, cfg, enrich=args.enrich
        )
        correlation = intel_engine_mod.correlate(evidence, providers, cache, limiter)
    finally:
        cache.close()
    correlation.notices.extend(notices)
    cdata = correlation.to_dict()
    cdata["intel_rows"] = cdata.pop("rows")
    cdata["intel_records"] = cdata.pop("records")
    result.data = cdata
    for finding in intel_engine_mod.findings_for_records(correlation.records):
        result.add_finding(finding)
    malicious = sum(1 for r in correlation.rows if r.combined_verdict == "malicious")
    conflicting = sum(
        1 for r in correlation.rows if r.combined_verdict == "conflicting"
    )
    result.summary = (
        f"{args.case_id}: {len(correlation.rows)} indicator(s) correlated, "
        f"{malicious} malicious, {conflicting} conflicting"
    )
    if correlation.network_contacted:
        result.data["network_notice"] = (
            "NOTICE: indicators were sent to network provider(s): "
            + ", ".join(correlation.network_contacted)
            + " — indicators sent to providers leave this machine."
        )
    result.add_event(
        Event(
            event_type="intel.correlate.completed",
            source="aegisforge",
            evidence={
                "case_id": args.case_id,
                "indicators": len(correlation.rows),
                "enrich": args.enrich,
                "network_contacted": correlation.network_contacted,
            },
        )
    )
    return result


def cmd_intel_providers(args: argparse.Namespace, cfg: AppConfig) -> Result:
    from aegisforge.intel.providers import get_provider, provider_names

    result = Result(command="intel providers")
    rows = []
    for name in provider_names():
        cls = get_provider(name)
        instance = cls()
        intel_engine_mod._configure_provider(instance, cfg)
        rows.append(
            {
                "name": name,
                "network": cls.network,
                "supported_types": list(cls.supported_types),
                "configured": instance.is_configured(),
                "default_confidence": cls.default_confidence,
            }
        )
    result.data = {"providers": rows}
    result.summary = f"{len(rows)} registered provider(s)"
    return result


def cmd_intel_cache_clear(args: argparse.Namespace, cfg: AppConfig) -> Result:
    result = Result(command="intel cache-clear")
    cache = IntelCache(ttl_seconds=int(cfg.get("intel_cache_ttl")))
    try:
        removed = cache.clear()
    finally:
        cache.close()
    result.data = {"removed_entries": removed}
    result.summary = f"intel cache cleared: {removed} entr(ies) removed"
    result.add_event(
        Event(
            event_type="intel.cache.cleared",
            source="aegisforge",
            evidence={"removed_entries": removed},
        )
    )
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


def _hist_lines(title: str, pairs: list[list[Any]]) -> list[str]:
    lines = [f"{title}:"]
    if not pairs:
        lines.append("  (none)")
        return lines
    width = max(len(str(p[0])) for p in pairs)
    for key, count in pairs:
        lines.append(f"  {str(key):<{width}}  {count}")
    return lines


def render_logs_analyze(result: Result) -> str:
    """Human-readable rendering of a `logs analyze` result envelope."""
    data = result.data
    lines = [result.summary] if result.summary else []
    detection = data.get("detection", {})
    lines.append("")
    lines.append(
        f"Format: {data.get('parser')} (confidence {detection.get('confidence', '?')})"
    )
    lines.append(
        f"Lines: {data.get('total_lines')} parsed, "
        f"{data.get('events_matched')} matched, "
        f"{data.get('warning_count')} warnings"
    )
    if data.get("time_first"):
        lines.append(f"Time range: {data['time_first']} .. {data['time_last']}")
    if data.get("filters"):
        lines.append(
            "Filters: " + ", ".join(f"{k}={v}" for k, v in data["filters"].items())
        )
    if data.get("warnings"):
        lines.append("")
        lines.append(f"Parse warnings (showing {len(data['warnings'])}):")
        for w in data["warnings"][:10]:
            lines.append(f"  line {w.get('line_number')}: {w.get('reason')}")
    lines.append("")
    lines.extend(
        _hist_lines(
            "Severity",
            [[k, v] for k, v in data.get("severity_histogram", {}).items()],
        )
    )
    if data.get("status_histogram"):
        lines.append("")
        lines.extend(
            _hist_lines(
                "HTTP status",
                [[k, v] for k, v in data.get("status_histogram", {}).items()],
            )
        )
    lines.append("")
    lines.extend(_hist_lines("Top IPs", data.get("top_ips", [])))
    lines.append("")
    lines.extend(_hist_lines("Top hosts", data.get("top_hosts", [])))
    if data.get("bursts"):
        lines.append("")
        lines.append("Bursts:")
        for b in data["bursts"]:
            key = f" [{b['key']}]" if b.get("key") else ""
            window = f"{b['window_start']} (+{b.get('window_end') or ''}){key}"
            lines.append(f"  {window}: {b['count']} events")
    if data.get("errors"):
        lines.append("")
        lines.append(f"Errors ({len(data['errors'])} shown):")
        for entry in data["errors"][:10]:
            event = entry["event"]
            lines.append(
                f"  line {event.get('line_number')} [{event.get('severity')}] "
                f"{(event.get('message') or '')[:100]}"
            )
            for ctx in entry.get("context_before", []):
                lines.append(f"    | {ctx[:100]}")
            for ctx in entry.get("context_after", []):
                lines.append(f"    | {ctx[:100]}")
    if data.get("hourly"):
        lines.append("")
        lines.extend(_hist_lines("Events per hour", data["hourly"][:12]))
        if len(data["hourly"]) > 12:
            lines.append(f"  ... and {len(data['hourly']) - 12} more buckets")
    if result.findings:
        lines.append("")
        lines.append("Findings:")
        for f in result.findings:
            lines.append(f"  [{f.severity}] {f.title} (confidence {f.confidence})")
            if f.reason:
                lines.append(f"    {f.reason}")
    return "\n".join(lines)


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


def _short_sha(digest: str | None) -> str:
    return (digest or "")[:12]


def render_forensics_inventory(result: Result) -> str:
    """Human-readable rendering of a `forensics inventory` result."""
    data = result.data
    lines = [result.summary] if result.summary else []
    stats = data.get("stats", {})
    lines.append("")
    lines.append(
        f"Files: {stats.get('files', 0)}  Directories: {stats.get('directories', 0)}  "
        f"Total bytes: {stats.get('total_bytes', 0)}"
    )
    files = data.get("files", [])
    if files:
        lines.append("")
        lines.append(f"{'PATH':<44}{'SIZE':>10}  {'MTIME':<20}  {'SHA256':<12}  TYPE")
        for f in files[:50]:
            lines.append(
                f"{f.get('path', '')[:44]:<44}{f.get('size', 0):>10}  "
                f"{(f.get('mtime') or '-')[:19]:<20}  "
                f"{_short_sha(f.get('hashes', {}).get('sha256')):<12}  "
                f"{f.get('file_type', '')}"
                + ("  [extension mismatch]" if f.get("extension_mismatch") else "")
            )
        if len(files) > 50:
            lines.append(f"  ... and {len(files) - 50} more (see --json)")
    for w in data.get("warnings", [])[:10]:
        lines.append(f"warning: {w.get('path')}: {w.get('reason')}")
    return "\n".join(lines)


def render_forensics_manifest(result: Result) -> str:
    """Human-readable rendering of a `forensics manifest` result."""
    data = result.data
    lines = [result.summary] if result.summary else []
    lines.append("")
    lines.append(f"Manifest: {data.get('manifest_path')}")
    lines.append(f"SHA-256:  {data.get('manifest_sha256')}")
    lines.append(
        f"Files:    {data.get('file_count')} "
        f"({data.get('total_bytes')} bytes, sealed {data.get('created')})"
    )
    lines.append(
        "The manifest digest was recorded in the audit log "
        "(tamper-evidence seam, not a legal claim)."
    )
    return "\n".join(lines)


def render_forensics_verify(result: Result) -> str:
    """Human-readable rendering of a `forensics verify` result."""
    data = result.data
    lines = [result.summary] if result.summary else []
    if data.get("ok"):
        lines.append("")
        lines.append(f"OK: all {data.get('verified')} file(s) match the manifest.")
        return "\n".join(lines)
    for label, key in (
        ("Changed", "changed"),
        ("Missing", "missing"),
        ("New", "new"),
    ):
        items = data.get(key, [])
        if items:
            lines.append("")
            lines.append(f"{label} ({len(items)}):")
            for item in items[:20]:
                lines.append(f"  {item.get('path')}: {item.get('detail')}")
            if len(items) > 20:
                lines.append(f"  ... and {len(items) - 20} more (see --json)")
    if result.findings:
        lines.append("")
        lines.append("Findings:")
        for f in result.findings:
            lines.append(f"  [{f.severity}] {f.title} (confidence {f.confidence})")
            if f.reason:
                lines.append(f"    {f.reason}")
    return "\n".join(lines)


def render_forensics_duplicates(result: Result) -> str:
    """Human-readable rendering of a `forensics duplicates` result."""
    data = result.data
    lines = [result.summary] if result.summary else []
    for group in data.get("groups", [])[:20]:
        lines.append("")
        lines.append(
            f"sha256 {_short_sha(group.get('sha256'))}… ({group.get('count')} files):"
        )
        for path in group.get("paths", []):
            lines.append(f"  {path}")
    if len(data.get("groups", [])) > 20:
        lines.append(f"... and {len(data['groups']) - 20} more groups (see --json)")
    if not data.get("groups"):
        lines.append("")
        lines.append("No duplicate files found.")
    return "\n".join(lines)


def render_forensics_timeline(result: Result) -> str:
    """Human-readable rendering of a `forensics timeline` result."""
    data = result.data
    lines = [result.summary] if result.summary else []
    lines.append("")
    lines.append(
        "Filesystem timestamps (mtime/atime/ctime) — filesystem metadata, "
        "not content claims."
    )
    entries = data.get("timeline", [])
    if entries:
        lines.append("")
        lines.append(f"{'TIMESTAMP (UTC)':<28}{'KIND':<7}PATH")
        for e in entries[:100]:
            lines.append(
                f"{e.get('timestamp', ''):<28}{e.get('kind', ''):<7}{e.get('path', '')}"
            )
        if len(entries) > 100:
            lines.append(f"... and {len(entries) - 100} more (see --json)")
    return "\n".join(lines)


def render_case_create(result: Result) -> str:
    data = result.data
    lines = [result.summary] if result.summary else []
    lines.append("")
    lines.append(f"  case id:  {data.get('case_id')}")
    lines.append(f"  title:    {data.get('title')}")
    lines.append(f"  status:   {data.get('status')}")
    lines.append(f"  created:  {data.get('created')}")
    return "\n".join(lines)


def render_case_list(result: Result) -> str:
    data = result.data
    lines = [result.summary] if result.summary else []
    cases = data.get("cases", [])
    if cases:
        lines.append("")
        lines.append(f"{'CASE ID':<16}{'STATUS':<12}{'EVID':>5}{'FIND':>5}  TITLE")
        for c in cases:
            lines.append(
                f"{c['case_id']:<16}{c['status']:<12}{c['evidence']:>5}"
                f"{c['findings']:>5}  {c['title']}"
            )
    return "\n".join(lines)


def render_case_show(result: Result) -> str:
    data = result.data
    lines = [result.summary] if result.summary else []
    lines.append("")
    lines.append(f"  title:    {data.get('title')}")
    lines.append(f"  status:   {data.get('status')}")
    lines.append(f"  created:  {data.get('created')}")
    evidence = data.get("evidence", [])
    if evidence:
        lines.append("")
        lines.append("Evidence:")
        for e in evidence:
            lines.append(
                f"  {e['evidence_id']} [{e['kind']}] {e['stored_path']} "
                f"(sha256 {e['sha256'][:12]}…)"
            )
    findings = data.get("findings", [])
    if findings:
        lines.append("")
        lines.append("Findings:")
        for f in findings:
            lines.append(
                f"  {f['finding_id']} [{f['severity']}/{f['status']}] {f['title']}"
            )
    notes = data.get("notes", [])
    if notes:
        lines.append("")
        lines.append(f"Notes: {len(notes)} (see --json for full text)")
    return "\n".join(lines)


def render_case_attach(result: Result) -> str:
    data = result.data
    lines = [result.summary] if result.summary else []
    lines.append("")
    lines.append(f"  evidence id:  {data.get('evidence_id')}")
    lines.append(f"  kind:         {data.get('kind')}")
    lines.append(f"  stored as:    {data.get('stored_path')}")
    lines.append(f"  sha256:       {data.get('sha256')}")
    lines.append(f"  attached at:  {data.get('attached_at')} (UTC)")
    return "\n".join(lines)


def render_case_timeline(result: Result) -> str:
    data = result.data
    lines = [result.summary] if result.summary else []
    entries = data.get("timeline_entries", [])
    if entries:
        lines.append("")
        lines.append(f"{'TIMESTAMP (UTC)':<30}{'SOURCE':<22}{'KIND':<16}SUMMARY")
        for e in entries[:80]:
            lines.append(
                f"{(e.get('timestamp') or ''):<30}{e.get('source', ''):<22}"
                f"{e.get('kind', ''):<16}{e.get('summary', '')[:60]}"
            )
        if len(entries) > 80:
            lines.append(f"... and {len(entries) - 80} more (see --json)")
    untimed = data.get("untimed", [])
    if untimed:
        lines.append("")
        lines.append(
            f"Untimed ({len(untimed)} — no parseable timestamp, listed "
            "separately, never dropped):"
        )
        for e in untimed[:20]:
            lines.append(f"  [{e.get('source')}] {e.get('summary', '')[:70]}")
        if len(untimed) > 20:
            lines.append(f"  ... and {len(untimed) - 20} more (see --json)")
    lines.append("")
    lines.append(data.get("note", ""))
    return "\n".join(lines)


def render_case_finding(result: Result) -> str:
    data = result.data
    lines = [result.summary] if result.summary else []
    lines.append("")
    lines.append(f"  severity:   {data.get('severity')}")
    lines.append(f"  confidence: {data.get('confidence')}")
    lines.append(f"  status:     {data.get('status')}")
    if data.get("detail"):
        lines.append(f"  detail:     {data.get('detail')}")
    return "\n".join(lines)


def render_case_findings(result: Result) -> str:
    data = result.data
    lines = [result.summary] if result.summary else []
    findings = data.get("case_findings", [])
    if findings:
        lines.append("")
        lines.append(f"{'FINDING ID':<22}{'SEVERITY':<10}{'STATUS':<14}TITLE")
        for f in findings:
            indicators = ", ".join(
                f"{i['value']} ({i['type']})" for i in f.get("indicators", [])
            )
            lines.append(
                f"{f['finding_id']:<22}{f['severity']:<10}{f['status']:<14}{f['title']}"
            )
            if indicators:
                lines.append(f"  indicators: {indicators}")
    return "\n".join(lines)


def render_case_link(result: Result) -> str:
    data = result.data
    lines = [result.summary] if result.summary else []
    lines.append("")
    origin = (
        "analyst-specified"
        if data.get("type_source") == "specified"
        else "guessed from value shape (not a verified classification)"
    )
    lines.append(f"  value: {data.get('value')}")
    lines.append(f"  type:  {data.get('type')} ({origin})")
    return "\n".join(lines)


def render_case_note(result: Result) -> str:
    data = result.data
    lines = [result.summary] if result.summary else []
    lines.append("")
    lines.append(f"  [{data.get('created')}] {data.get('author')}: {data.get('text')}")
    return "\n".join(lines)


def render_case_report(result: Result) -> str:
    data = result.data
    lines = [result.summary] if result.summary else []
    lines.append("")
    lines.append(f"  output:   {data.get('output')}")
    lines.append(f"  evidence: {data.get('evidence_count')} file(s)")
    lines.append(f"  findings: {data.get('finding_count')}")
    lines.append(f"  timeline: {data.get('timeline_entries')} entr(ies)")
    manifest = (data.get("manifest") or {}).get("artifacts", {})
    if manifest:
        lines.append("")
        lines.append("  report manifest (SHA-256 per artifact):")
        for name, digest in manifest.items():
            lines.append(f"    {name}: {digest[:16]}…")
    return "\n".join(lines)


def render_case_status(result: Result) -> str:
    lines = [result.summary] if result.summary else []
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
    elif "records" in data:  # domain dns
        rows = data["records"]
        headers = ["name", "rtype", "ttl", "detail"]
    elif "log_events" in data:  # logs analyze
        rows = data["log_events"]
        headers = ["line_number", "timestamp", "parser", "host", "severity", "message"]
    elif "files" in data:  # forensics inventory
        rows = [
            {
                "path": f.get("path"),
                "size": f.get("size"),
                "mtime": f.get("mtime"),
                "sha256": (f.get("hashes") or {}).get("sha256"),
                "md5": (f.get("hashes") or {}).get("md5"),
                "sha1": (f.get("hashes") or {}).get("sha1"),
                "file_type": f.get("file_type"),
                "type_source": f.get("type_source"),
            }
            for f in data["files"]
        ]
        headers = [
            "path",
            "size",
            "mtime",
            "sha256",
            "md5",
            "sha1",
            "file_type",
            "type_source",
        ]
    elif "timeline" in data:  # forensics timeline
        rows = data["timeline"]
        headers = ["timestamp", "kind", "path"]
    elif "groups" in data:  # forensics duplicates
        rows = [
            {"sha256": g.get("sha256"), "path": p}
            for g in data["groups"]
            for p in g.get("paths", [])
        ]
        headers = ["sha256", "path"]
    elif "changed" in data:  # forensics verify
        rows = [
            {"status": status, "path": c.get("path"), "detail": c.get("detail")}
            for status, key in (
                ("changed", "changed"),
                ("missing", "missing"),
                ("new", "new"),
            )
            for c in data.get(key, [])
        ]
        headers = ["status", "path", "detail"]
    elif "timeline_entries" in data:  # case timeline
        rows = data["timeline_entries"]
        headers = ["timestamp", "source", "kind", "summary", "detail"]
    elif "pcap_talkers" in data:  # pcap summary
        rows = data["pcap_talkers"]
        headers = ["ip", "packets"]
    elif "pcap_flows" in data:  # pcap conversations
        rows = data["pcap_flows"]
        headers = [
            "src_ip",
            "dst_ip",
            "protocol",
            "src_port",
            "dst_port",
            "packets",
            "bytes",
            "duration_s",
            "tcp_flags",
        ]
    elif "pcap_dns" in data:  # pcap dns
        rows = data["pcap_dns"]
        headers = ["name", "qtype", "queries", "responses", "nxdomain"]
    elif "pcap_http" in data:  # pcap http
        rows = data["pcap_http"]
        headers = ["timestamp", "src", "dst", "method", "host", "path", "status"]
    elif "pcap_tls" in data:  # pcap tls
        rows = data["pcap_tls"]
        headers = ["timestamp", "src", "dst", "sni", "offered_version"]
    elif "pcap_indicators" in data:  # pcap indicators
        rows = data["pcap_indicators"]
        headers = ["itype", "value", "first_seen", "last_seen", "observation"]
    elif "pcap_timeline" in data:  # pcap timeline
        rows = data["pcap_timeline"]
        headers = ["timestamp", "source", "kind", "summary"]
    elif "intel_rows" in data:  # intel correlate
        rows = [
            {
                "indicator": r.get("indicator"),
                "type": r.get("indicator_type"),
                "combined_verdict": r.get("combined_verdict"),
                "providers": ";".join(r.get("providers_hit", [])),
                "local_evidence": ";".join(r.get("local_evidence", [])),
            }
            for r in data["intel_rows"]
        ]
        headers = [
            "indicator",
            "type",
            "combined_verdict",
            "providers",
            "local_evidence",
        ]
    elif "intel_records" in data:  # intel lookup
        rows = [
            {
                "indicator": r.get("indicator"),
                "type": r.get("indicator_type"),
                "provider": r.get("provider"),
                "verdict": r.get("verdict_label", r.get("verdict")),
                "confidence": r.get("confidence"),
                "skipped": r.get("skipped"),
                "detail": r.get("detail"),
            }
            for r in data["intel_records"]
        ]
        headers = [
            "indicator",
            "type",
            "provider",
            "verdict",
            "confidence",
            "skipped",
            "detail",
        ]
    elif "case_findings" in data:  # case findings
        rows = [
            {
                "finding_id": f.get("finding_id"),
                "title": f.get("title"),
                "severity": f.get("severity"),
                "confidence": f.get("confidence"),
                "status": f.get("status"),
                "indicators": ";".join(
                    f"{i.get('value')}({i.get('type')})"
                    for i in f.get("indicators", [])
                ),
            }
            for f in data["case_findings"]
        ]
        headers = [
            "finding_id",
            "title",
            "severity",
            "confidence",
            "status",
            "indicators",
        ]
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


def _redacted_result(result: Result) -> Result:
    """Copy of *result* with IPs/emails masked (output only, never source)."""
    redacted = Result(
        command=result.command,
        target=(logs_redact_mod.redact_text(result.target) if result.target else None),
        status=result.status,
        summary=logs_redact_mod.redact_text(result.summary),
        data=logs_redact_mod.redact_value(result.data),
        tool=result.tool,
        version=result.version,
        timestamp=result.timestamp,
    )
    for finding in result.findings:
        redacted.findings.append(
            Finding(**logs_redact_mod.redact_value(finding.to_dict()))
        )
    for event in result.events:
        redacted.events.append(Event(**logs_redact_mod.redact_value(event.to_dict())))
    return redacted


def render_pcap_summary(result: Result) -> str:
    """Human-readable rendering of a `pcap summary` result."""
    data = result.data
    lines = [result.summary] if result.summary else []
    lines.append("")
    lines.append(
        f"Packets: {data.get('packet_count')}  "
        f"Bytes: {data.get('total_bytes')}  "
        f"Range: {data.get('time_first')} .. {data.get('time_last')}"
    )
    lines.append("")
    lines.extend(_hist_lines("Protocols", data.get("protocol_histogram", [])))
    lines.append("")
    lines.extend(
        _hist_lines("Top talkers (packets)", data.get("top_talkers_packets", []))
    )
    lines.append("")
    lines.extend(_hist_lines("Top talkers (bytes)", data.get("top_talkers_bytes", [])))
    lines.append("")
    lines.extend(_hist_lines("Top ports", data.get("top_ports", [])))
    unusual = data.get("unusual_ports", [])
    if unusual:
        lines.append("")
        lines.append("Unusual ports (observed — not a verdict):")
        for entry in unusual:
            lines.append(
                f"  {entry.get('protocol')}/{entry.get('port')}: "
                f"{entry.get('packets')} packets"
            )
    if data.get("warnings"):
        lines.append("")
        lines.append(f"Warnings ({data.get('warning_count')}):")
        for w in data["warnings"][:5]:
            lines.append(f"  {w.get('reason')}")
    if result.findings:
        lines.append("")
        lines.append("Findings:")
        for f in result.findings:
            lines.append(f"  [{f.severity}] {f.title} (confidence {f.confidence})")
            if f.reason:
                lines.append(f"    {f.reason}")
    return "\n".join(lines)


def render_pcap_conversations(result: Result) -> str:
    """Human-readable rendering of a `pcap conversations` result."""
    data = result.data
    flows = data.get("pcap_flows", [])
    lines = [result.summary] if result.summary else []
    lines.append("")
    lines.append(
        f"{'SOURCE':<22}{'DEST':<22}{'PROTO':<6}{'SPORT':<7}{'DPORT':<7}"
        f"{'PKTS':<7}{'BYTES':<9}DURATION"
    )
    for f in flows:
        lines.append(
            f"{str(f.get('src_ip')):<22}{str(f.get('dst_ip')):<22}"
            f"{str(f.get('protocol')):<6}{str(f.get('src_port')):<7}"
            f"{str(f.get('dst_port')):<7}{f.get('packets'):<7}"
            f"{f.get('bytes'):<9}{f.get('duration_s')}s"
        )
    if result.findings:
        lines.append("")
        lines.append("Findings:")
        for f in result.findings:
            lines.append(f"  [{f.severity}] {f.title} (confidence {f.confidence})")
    return "\n".join(lines)


def render_pcap_dns(result: Result) -> str:
    """Human-readable rendering of a `pcap dns` result."""
    data = result.data
    queries = data.get("pcap_dns", [])
    lines = [result.summary] if result.summary else []
    lines.append("")
    lines.append(f"{'NAME':<40}{'QTYPE':<8}{'Q':<6}{'RESP':<6}NXDOMAIN")
    for q in queries:
        lines.append(
            f"{str(q.get('name'))[:39]:<40}{str(q.get('qtype')):<8}"
            f"{q.get('queries'):<6}{q.get('responses'):<6}{q.get('nxdomain')}"
        )
    return "\n".join(lines)


def render_pcap_http(result: Result) -> str:
    """Human-readable rendering of a `pcap http` result."""
    data = result.data
    records = data.get("pcap_http", [])
    lines = [result.summary] if result.summary else []
    lines.append("")
    for r in records:
        if r.get("method"):
            lines.append(
                f"  {r.get('timestamp')} {r.get('src')} -> {r.get('dst')}: "
                f"{r.get('method')} {r.get('host')}{r.get('path')}"
            )
        else:
            lines.append(
                f"  {r.get('timestamp')} {r.get('src')} -> {r.get('dst')}: "
                f"HTTP {r.get('status')}"
            )
    return "\n".join(lines)


def render_pcap_tls(result: Result) -> str:
    """Human-readable rendering of a `pcap tls` result."""
    data = result.data
    records = data.get("pcap_tls", [])
    lines = [result.summary] if result.summary else []
    lines.append("")
    lines.append(f"{'TIMESTAMP':<28}{'SOURCE':<18}{'SNI':<36}VERSION")
    for r in records:
        lines.append(
            f"{str(r.get('timestamp')):<28}{str(r.get('src')):<18}"
            f"{str(r.get('sni') or '(none)')[:35]:<36}{r.get('offered_version')}"
        )
    return "\n".join(lines)


def render_pcap_indicators(result: Result) -> str:
    """Human-readable rendering of a `pcap indicators` result."""
    data = result.data
    indicators = data.get("pcap_indicators", [])
    lines = [result.summary] if result.summary else []
    lines.append("")
    lines.append("Observed in capture (not a verdict):")
    lines.append(f"{'TYPE':<8}{'VALUE':<44}FIRST SEEN")
    for i in indicators:
        lines.append(
            f"{str(i.get('itype')):<8}{str(i.get('value'))[:43]:<44}"
            f"{i.get('first_seen')}"
        )
    return "\n".join(lines)


def render_pcap_timeline(result: Result) -> str:
    """Human-readable rendering of a `pcap timeline` result."""
    data = result.data
    events = data.get("pcap_timeline", [])
    lines = [result.summary] if result.summary else []
    lines.append("")
    lines.append(f"{'TIMESTAMP (UTC)':<28}{'KIND':<12}SUMMARY")
    for e in events[:50]:
        lines.append(
            f"{str(e.get('timestamp')):<28}{str(e.get('kind')):<12}"
            f"{str(e.get('summary'))[:80]}"
        )
    if len(events) > 50:
        lines.append(f"  ... and {len(events) - 50} more events")
    return "\n".join(lines)


def render_intel_lookup(result: Result) -> str:
    """Human-readable rendering of an `intel lookup` result."""
    data = result.data
    indicator = data.get("indicator", {})
    lines = [result.summary] if result.summary else []
    lines.append("")
    lines.append(f"Indicator: {indicator.get('value')} ({indicator.get('type')})")
    if indicator.get("defanged"):
        lines.append("  (input was defanged; refanged before lookup)")
    if data.get("network_notice"):
        lines.append("")
        lines.append(data["network_notice"])
    lines.append("")
    lines.append(f"{'PROVIDER':<22}{'VERDICT':<14}{'CONF':<6}DETAIL")
    for rec in data.get("intel_records", []):
        if rec.get("skipped"):
            lines.append(
                f"{rec.get('provider', ''):<22}{'skipped':<14}{'-':<6}"
                f"{rec.get('skip_reason', '')}"
            )
            continue
        lines.append(
            f"{rec.get('provider', ''):<22}"
            f"{rec.get('verdict_label', rec.get('verdict', '')):<14}"
            f"{rec.get('confidence', ''):<6}"
            f"{str(rec.get('detail', ''))[:70]}"
        )
    for notice in data.get("notices", []):
        lines.append(f"  note [{notice.get('provider')}]: {notice.get('notice')}")
    return "\n".join(lines)


def render_intel_correlate(result: Result) -> str:
    """Human-readable rendering of an `intel correlate` result."""
    data = result.data
    lines = [result.summary] if result.summary else []
    if data.get("network_notice"):
        lines.append("")
        lines.append(data["network_notice"])
    lines.append("")
    lines.append(f"{'INDICATOR':<40}{'TYPE':<8}{'VERDICT':<12}PROVIDERS / EVIDENCE")
    for row in data.get("intel_rows", []):
        lines.append(
            f"{str(row.get('indicator'))[:39]:<40}"
            f"{row.get('indicator_type', ''):<8}"
            f"{row.get('combined_verdict', ''):<12}"
            f"{', '.join(row.get('providers_hit', []))}"
        )
        for ref in row.get("local_evidence", []):
            lines.append(f"{'':<60}<- {ref}")
    for notice in data.get("notices", []):
        lines.append(f"  note [{notice.get('provider')}]: {notice.get('notice')}")
    return "\n".join(lines)


def render_intel_providers(result: Result) -> str:
    """Human-readable rendering of an `intel providers` result."""
    lines = [result.summary] if result.summary else []
    lines.append("")
    lines.append(f"{'NAME':<22}{'NETWORK':<9}{'CONFIGURED':<11}TYPES")
    for p in result.data.get("providers", []):
        lines.append(
            f"{p.get('name', ''):<22}"
            f"{'yes' if p.get('network') else 'no':<9}"
            f"{'yes' if p.get('configured') else 'no':<11}"
            f"{', '.join(p.get('supported_types', []))}"
        )
    lines.append("")
    lines.append(
        "Network providers run only with --enrich; without it, lookups "
        "stay local (blocklist + cache)."
    )
    return "\n".join(lines)


def render_intel_cache_clear(result: Result) -> str:
    """Human-readable rendering of an `intel cache-clear` result."""
    lines = [result.summary] if result.summary else []
    return "\n".join(lines)


def render(result: Result, args: argparse.Namespace) -> str:
    if getattr(args, "redact", False) and result.command.startswith("logs "):
        result = _redacted_result(result)
    if result.command == "logs analyze" and not args.json and not args.csv:
        return render_logs_analyze(result)
    if result.command.startswith("forensics ") and not args.json and not args.csv:
        renderer = {
            "forensics inventory": render_forensics_inventory,
            "forensics manifest": render_forensics_manifest,
            "forensics verify": render_forensics_verify,
            "forensics duplicates": render_forensics_duplicates,
            "forensics timeline": render_forensics_timeline,
        }.get(result.command)
        if renderer is not None:
            return renderer(result)
    if result.command.startswith("case ") and not args.json and not args.csv:
        renderer = {
            "case create": render_case_create,
            "case list": render_case_list,
            "case show": render_case_show,
            "case attach": render_case_attach,
            "case timeline": render_case_timeline,
            "case finding": render_case_finding,
            "case findings": render_case_findings,
            "case link": render_case_link,
            "case note": render_case_note,
            "case report": render_case_report,
            "case status": render_case_status,
        }.get(result.command)
        if renderer is not None:
            return renderer(result)
    if result.command.startswith("pcap ") and not args.json and not args.csv:
        renderer = {
            "pcap summary": render_pcap_summary,
            "pcap conversations": render_pcap_conversations,
            "pcap dns": render_pcap_dns,
            "pcap http": render_pcap_http,
            "pcap tls": render_pcap_tls,
            "pcap indicators": render_pcap_indicators,
            "pcap timeline": render_pcap_timeline,
        }.get(result.command)
        if renderer is not None:
            return renderer(result)
    if result.command.startswith("intel ") and not args.json and not args.csv:
        renderer = {
            "intel lookup": render_intel_lookup,
            "intel correlate": render_intel_correlate,
            "intel providers": render_intel_providers,
            "intel cache-clear": render_intel_cache_clear,
        }.get(result.command)
        if renderer is not None:
            return renderer(result)
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
        "(v0.8: core + network discovery + port/service analysis + domain "
        "investigation + log analysis + digital forensics + incident-response "
        "engine + offline PCAP analysis + threat-intel enrichment). Commercial "
        "software: 1-week free trial, see LICENSE.",
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

    # domain group (v0.3)
    dom_p = sub.add_parser("domain", help="domain investigation")
    dom_sub = dom_p.add_subparsers(dest="command", required=True)

    p_ddns = dom_sub.add_parser(
        "dns",
        help="query DNS records (A/AAAA/MX/NS/TXT/SOA/CNAME/DNSKEY/DS)",
        parents=parents,
    )
    p_ddns.add_argument("name", help="domain name to query")
    p_ddns.add_argument(
        "--type",
        default="A",
        help="record type: A, AAAA, MX, NS, TXT, SOA, CNAME, DNSKEY, DS",
    )
    p_ddns.add_argument(
        "--resolver",
        default=None,
        help="DNS resolver IP (default: system resolvers)",
    )
    _add_timeout_flags(p_ddns)
    p_ddns.set_defaults(func=cmd_domain_dns)

    p_inv = dom_sub.add_parser(
        "investigate",
        help="consolidated domain investigation report",
        parents=parents,
    )
    p_inv.add_argument("domain", help="domain name to investigate")
    p_inv.add_argument(
        "--resolver",
        default=None,
        help="DNS resolver IP (default: system resolvers)",
    )
    p_inv.add_argument(
        "--no-rdap", action="store_true", help="skip RDAP registration lookup"
    )
    p_inv.add_argument(
        "--no-whois", action="store_true", help="skip WHOIS fallback lookup"
    )
    p_inv.add_argument(
        "--no-web", action="store_true", help="skip HTTP/HTTPS header collection"
    )
    p_inv.add_argument(
        "--no-tls", action="store_true", help="skip TLS certificate inspection"
    )
    _add_timeout_flags(p_inv)
    p_inv.set_defaults(func=cmd_domain_investigate)

    # logs group (v0.4)
    logs_p = sub.add_parser("logs", help="log analysis")
    logs_sub = logs_p.add_subparsers(dest="command", required=True)

    p_detect = logs_sub.add_parser(
        "detect", help="auto-detect the format of a log file", parents=parents
    )
    p_detect.add_argument("file", help="path to the log file")
    p_detect.set_defaults(func=cmd_logs_detect)

    p_analyze = logs_sub.add_parser(
        "analyze", help="analyze a log file (streaming)", parents=parents
    )
    p_analyze.add_argument("file", help="path to the log file")
    p_analyze.add_argument(
        "--format",
        default="auto",
        choices=["auto", "syslog", "apache", "json", "winevent", "keyvalue"],
        help="log format (default: auto-detect)",
    )
    p_analyze.add_argument(
        "--since", default=None, help="only events at/after an ISO-8601 time"
    )
    p_analyze.add_argument(
        "--until", default=None, help="only events at/before an ISO-8601 time"
    )
    p_analyze.add_argument(
        "--level",
        action="append",
        default=None,
        choices=["info", "low", "medium", "high", "critical"],
        help="only events at this severity (repeatable)",
    )
    p_analyze.add_argument(
        "--contains",
        action="append",
        default=None,
        help="only events containing this text (repeatable)",
    )
    p_analyze.add_argument(
        "--not-contains",
        action="append",
        default=None,
        help="exclude events containing this text (repeatable)",
    )
    p_analyze.add_argument("--host", default=None, help="only events from this host")
    p_analyze.add_argument(
        "--limit", type=int, default=None, help="max events kept for display"
    )
    p_analyze.add_argument(
        "--burst-window",
        type=int,
        default=None,
        help="burst detection window in seconds (default 60)",
    )
    p_analyze.add_argument(
        "--burst-threshold",
        type=int,
        default=None,
        help="events per window to flag a burst (default 50)",
    )
    p_analyze.add_argument(
        "--context",
        type=int,
        default=None,
        help="context lines kept around error events (default 3)",
    )
    p_analyze.add_argument(
        "--redact",
        action="store_true",
        help="mask IP addresses and emails in output (source files untouched)",
    )
    p_analyze.set_defaults(func=cmd_logs_analyze)

    # forensics group (v0.4) — read-only: never modifies scanned files
    for_p = sub.add_parser("forensics", help="digital forensics")
    for_sub = for_p.add_subparsers(dest="command", required=True)

    def _add_forensics_path_flags(p: argparse.ArgumentParser) -> None:
        p.add_argument(
            "--include",
            action="append",
            default=None,
            help="only include paths matching this glob (repeatable)",
        )
        p.add_argument(
            "--exclude",
            action="append",
            default=None,
            help="exclude paths matching this glob (repeatable)",
        )

    def _add_hash_flags(p: argparse.ArgumentParser) -> None:
        p.add_argument(
            "--algorithms",
            action="append",
            default=None,
            choices=["sha256", "md5", "sha1"],
            help="hash algorithm (repeatable, default: sha256)",
        )

    p_finv = for_sub.add_parser(
        "inventory",
        help="recursive read-only file inventory with hashing",
        parents=parents,
    )
    p_finv.add_argument("path", help="file or directory to inventory")
    _add_forensics_path_flags(p_finv)
    _add_hash_flags(p_finv)
    p_finv.set_defaults(func=cmd_forensics_inventory)

    p_fman = for_sub.add_parser(
        "manifest",
        help="inventory a tree and write a sealed evidence manifest",
        parents=parents,
    )
    p_fman.add_argument("path", help="file or directory to inventory")
    p_fman.add_argument(
        "--output", required=True, help="where to write the manifest JSON"
    )
    p_fman.add_argument(
        "--note", default=None, help="operator note recorded in the manifest"
    )
    _add_forensics_path_flags(p_fman)
    _add_hash_flags(p_fman)
    p_fman.set_defaults(func=cmd_forensics_manifest)

    p_fver = for_sub.add_parser(
        "verify",
        help="verify a live tree against a manifest (changed/missing/new)",
        parents=parents,
    )
    p_fver.add_argument(
        "--manifest", required=True, help="manifest JSON to verify against"
    )
    p_fver.add_argument(
        "--root",
        default=None,
        help="tree to verify (default: root recorded in the manifest)",
    )
    p_fver.set_defaults(func=cmd_forensics_verify)

    p_fdup = for_sub.add_parser(
        "duplicates",
        help="group files with identical SHA-256 content",
        parents=parents,
    )
    p_fdup.add_argument("path", help="file or directory to scan")
    _add_forensics_path_flags(p_fdup)
    p_fdup.set_defaults(func=cmd_forensics_duplicates)

    p_ftime = for_sub.add_parser(
        "timeline",
        help="chronological filesystem timestamps (mtime/atime/ctime)",
        parents=parents,
    )
    p_ftime.add_argument("path", help="file or directory to scan")
    _add_forensics_path_flags(p_ftime)
    p_ftime.add_argument(
        "--limit", type=int, default=None, help="max timeline entries shown"
    )
    p_ftime.set_defaults(func=cmd_forensics_timeline)

    # case group (v0.6) — incident-response engine: timeline + case management
    case_p = sub.add_parser("case", help="incident case management")
    case_sub = case_p.add_subparsers(dest="command", required=True)

    p_ccreate = case_sub.add_parser(
        "create", help="create a new incident case", parents=parents
    )
    p_ccreate.add_argument("--title", required=True, help="case title")
    p_ccreate.add_argument("--note", default=None, help="opening analyst note")
    p_ccreate.set_defaults(func=cmd_case_create)

    p_clist = case_sub.add_parser("list", help="list all cases", parents=parents)
    p_clist.set_defaults(func=cmd_case_list)

    p_cshow = case_sub.add_parser(
        "show", help="show case metadata, evidence and findings", parents=parents
    )
    p_cshow.add_argument("case_id", help="case ID, e.g. CASE-2026-001")
    p_cshow.set_defaults(func=cmd_case_show)

    p_cattach = case_sub.add_parser(
        "attach",
        help="copy a file into the case evidence folder (sources untouched)",
        parents=parents,
    )
    p_cattach.add_argument("case_id", help="case ID, e.g. CASE-2026-001")
    p_cattach.add_argument(
        "--kind",
        required=True,
        choices=["network", "logs", "files"],
        help="evidence kind",
    )
    p_cattach.add_argument("--source", required=True, help="file to copy into the case")
    p_cattach.set_defaults(func=cmd_case_attach)

    p_ctime = case_sub.add_parser(
        "timeline",
        help="unified chronological timeline across all case evidence",
        parents=parents,
    )
    p_ctime.add_argument("case_id", help="case ID, e.g. CASE-2026-001")
    p_ctime.add_argument(
        "--limit", type=int, default=None, help="max timed entries shown"
    )
    p_ctime.set_defaults(func=cmd_case_timeline)

    p_cfinding = case_sub.add_parser(
        "finding", help="record a finding in the case", parents=parents
    )
    p_cfinding.add_argument("case_id", help="case ID, e.g. CASE-2026-001")
    p_cfinding.add_argument("--title", required=True, help="finding title")
    p_cfinding.add_argument(
        "--severity",
        required=True,
        choices=["info", "low", "medium", "high", "critical"],
        help="finding severity",
    )
    p_cfinding.add_argument(
        "--confidence",
        required=True,
        type=int,
        help="confidence 0-100",
    )
    p_cfinding.add_argument("--detail", default="", help="finding detail")
    p_cfinding.set_defaults(func=cmd_case_finding)

    p_cfindings = case_sub.add_parser(
        "findings", help="list findings tracked in the case", parents=parents
    )
    p_cfindings.add_argument("case_id", help="case ID, e.g. CASE-2026-001")
    p_cfindings.add_argument(
        "--status",
        default=None,
        choices=["open", "investigating", "resolved", "false-positive"],
        help="only findings in this lifecycle state",
    )
    p_cfindings.set_defaults(func=cmd_case_findings)

    p_clink = case_sub.add_parser(
        "link", help="link an indicator to a finding", parents=parents
    )
    p_clink.add_argument("case_id", help="case ID, e.g. CASE-2026-001")
    p_clink.add_argument("--finding", required=True, help="finding ID")
    p_clink.add_argument("--indicator", required=True, help="indicator value")
    p_clink.add_argument(
        "--type",
        default=None,
        choices=["ip", "domain", "hash", "url", "email"],
        help="indicator type (default: guessed from the value's shape)",
    )
    p_clink.set_defaults(func=cmd_case_link)

    p_cnote = case_sub.add_parser(
        "note", help="append an analyst note to the case", parents=parents
    )
    p_cnote.add_argument("case_id", help="case ID, e.g. CASE-2026-001")
    p_cnote.add_argument("text", help="note text")
    p_cnote.set_defaults(func=cmd_case_note)

    p_creport = case_sub.add_parser(
        "report",
        help="generate a reproducible report bundle",
        parents=parents,
    )
    p_creport.add_argument("case_id", help="case ID, e.g. CASE-2026-001")
    p_creport.add_argument(
        "--output", required=True, help="directory for the report bundle"
    )
    p_creport.add_argument(
        "--force",
        action="store_true",
        help="overwrite a non-empty output directory",
    )
    p_creport.set_defaults(func=cmd_case_report)

    p_cstatus = case_sub.add_parser(
        "status",
        help="show or change the case status (closing needs --note)",
        parents=parents,
    )
    p_cstatus.add_argument("case_id", help="case ID, e.g. CASE-2026-001")
    p_cstatus.add_argument(
        "status",
        nargs="?",
        default=None,
        choices=["open", "in-progress", "closed"],
        help="new status (omit to show the current status)",
    )
    p_cstatus.add_argument("--note", default=None, help="note for the transition")
    p_cstatus.set_defaults(func=cmd_case_status)

    # pcap group (v0.7) — offline capture analysis, read-only
    pcap_p = sub.add_parser("pcap", help="offline PCAP analysis")
    pcap_sub = pcap_p.add_subparsers(dest="command", required=True)

    p_psum = pcap_sub.add_parser(
        "summary", help="protocol stats, talkers, ports, findings", parents=parents
    )
    p_psum.add_argument("file", help="path to a classic pcap file")
    p_psum.set_defaults(func=cmd_pcap_summary)

    p_pconv = pcap_sub.add_parser(
        "conversations", help="5-tuple flow summaries", parents=parents
    )
    p_pconv.add_argument("file", help="path to a classic pcap file")
    p_pconv.add_argument(
        "--top", type=int, default=None, help="flows shown (default from config)"
    )
    p_pconv.set_defaults(func=cmd_pcap_conversations)

    p_pdns = pcap_sub.add_parser(
        "dns", help="DNS queries/responses observed on UDP/53", parents=parents
    )
    p_pdns.add_argument("file", help="path to a classic pcap file")
    p_pdns.add_argument(
        "--top", type=int, default=None, help="names shown (default from config)"
    )
    p_pdns.set_defaults(func=cmd_pcap_dns)

    p_phttp = pcap_sub.add_parser(
        "http", help="HTTP request/response metadata on TCP/80", parents=parents
    )
    p_phttp.add_argument("file", help="path to a classic pcap file")
    p_phttp.add_argument(
        "--top", type=int, default=None, help="records shown (default from config)"
    )
    p_phttp.set_defaults(func=cmd_pcap_http)

    p_ptls = pcap_sub.add_parser(
        "tls", help="TLS ClientHello SNI/version on TCP/443", parents=parents
    )
    p_ptls.add_argument("file", help="path to a classic pcap file")
    p_ptls.add_argument(
        "--top", type=int, default=None, help="records shown (default from config)"
    )
    p_ptls.set_defaults(func=cmd_pcap_tls)

    p_pind = pcap_sub.add_parser(
        "indicators",
        help="deduped observed indicators (IPs, domains, URLs)",
        parents=parents,
    )
    p_pind.add_argument("file", help="path to a classic pcap file")
    p_pind.set_defaults(func=cmd_pcap_indicators)

    p_ptime = pcap_sub.add_parser(
        "timeline",
        help="timestamped flow-start and DNS-query events",
        parents=parents,
    )
    p_ptime.add_argument("file", help="path to a classic pcap file")
    p_ptime.set_defaults(func=cmd_pcap_timeline)

    intel_p = sub.add_parser("intel", help="threat-intel enrichment")
    intel_sub = intel_p.add_subparsers(dest="command", required=True)

    p_ilook = intel_sub.add_parser(
        "lookup",
        help="look up one indicator across configured providers",
        parents=parents,
    )
    p_ilook.add_argument("indicator", help="IP, domain, URL or hash")
    p_ilook.add_argument(
        "--provider",
        default=None,
        help="use only this provider (default: configured providers)",
    )
    p_ilook.add_argument(
        "--enrich",
        action="store_true",
        help="allow network providers (indicators leave this machine)",
    )
    p_ilook.set_defaults(func=cmd_intel_lookup)

    p_icorr = intel_sub.add_parser(
        "correlate",
        help="enrich case + pcap indicators and combine verdicts",
        parents=parents,
    )
    p_icorr.add_argument("--case", dest="case_id", required=True, help="case ID")
    p_icorr.add_argument("--pcap", default=None, help="also enrich pcap indicators")
    p_icorr.add_argument(
        "--enrich",
        action="store_true",
        help="allow network providers (indicators leave this machine)",
    )
    p_icorr.set_defaults(func=cmd_intel_correlate)

    p_iprov = intel_sub.add_parser(
        "providers", help="list registered providers", parents=parents
    )
    p_iprov.set_defaults(func=cmd_intel_providers)

    p_icache = intel_sub.add_parser(
        "cache-clear", help="clear the local intel cache", parents=parents
    )
    p_icache.set_defaults(func=cmd_intel_cache_clear)

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
