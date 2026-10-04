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

v1.0 adds professional reporting (``report case``, ``report pcap``,
``report logs``, ``report forensics``, ``report domain``): a unified
report data model with auto-generated executive summaries (labelled as
generated, analyst review required), evidence inventories with hashes,
a methodology section honest about methods and limits, findings with
explicit OBSERVED/INFERRED splits, timelines, deduped indicators with
offline verdicts, and supporting-evidence hash appendices — rendered as
self-contained HTML, stdlib-only PDF, JSON and per-section CSVs. Also
adds ``aegisforge version`` and the v1.x CLI stability contract (see
README): commands and flags are not renamed without deprecation.
"""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from typing import Any

from aegisforge import __version__
from aegisforge.cli.commands.case import (
    cmd_case_attach,
    cmd_case_create,
    cmd_case_finding,
    cmd_case_findings,
    cmd_case_link,
    cmd_case_list,
    cmd_case_note,
    cmd_case_report,
    cmd_case_show,
    cmd_case_status,
    cmd_case_timeline,
)
from aegisforge.cli.commands.config import cmd_config_show
from aegisforge.cli.commands.correlate import (
    cmd_correlate_entities,
    cmd_correlate_run,
    cmd_correlate_timeline,
)
from aegisforge.cli.commands.domain import cmd_domain_dns, cmd_domain_investigate
from aegisforge.cli.commands.forensics import (
    cmd_forensics_duplicates,
    cmd_forensics_inventory,
    cmd_forensics_manifest,
    cmd_forensics_timeline,
    cmd_forensics_verify,
)
from aegisforge.cli.commands.intel import (
    cmd_intel_cache_clear,
    cmd_intel_correlate,
    cmd_intel_lookup,
    cmd_intel_providers,
)
from aegisforge.cli.commands.logs import cmd_logs_analyze, cmd_logs_detect
from aegisforge.cli.commands.network import (
    cmd_baseline,
    cmd_dns,
    cmd_interfaces,
    cmd_inventory,
    cmd_ping,
    cmd_scan,
    cmd_subnet,
    cmd_trace,
    dns_mod,
    interfaces_mod,
    inventory_mod,
    ping_mod,
    trace_mod,
)
from aegisforge.cli.commands.pcap import (
    cmd_pcap_conversations,
    cmd_pcap_dns,
    cmd_pcap_http,
    cmd_pcap_indicators,
    cmd_pcap_summary,
    cmd_pcap_timeline,
    cmd_pcap_tls,
)
from aegisforge.cli.commands.render import render
from aegisforge.cli.commands.report import (
    cmd_report_case,
    cmd_report_domain,
    cmd_report_forensics,
    cmd_report_logs,
    cmd_report_pcap,
)
from aegisforge.core import config as config_mod
from aegisforge.core.config import AppConfig, ConfigError
from aegisforge.core.logging import audit_log, configure_logging, get_logger
from aegisforge.core.plugins import get_registry
from aegisforge.core.results import EXIT_ERROR, Result, exit_code_for
from aegisforge.network.validation import ValidationError

# Re-exported so existing tests can keep monkeypatching
# ``aegisforge.cli.main.<module>`` exactly as before the CLI split.
__all__ = [
    "build_parser",
    "cmd_version",
    "dns_mod",
    "interfaces_mod",
    "inventory_mod",
    "main",
    "ping_mod",
    "render",
    "trace_mod",
]

log = get_logger()


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
        "(v1.0: core + network discovery + port/service analysis + domain "
        "investigation + log analysis + digital forensics + incident-response "
        "engine + offline PCAP analysis + threat-intel enrichment + "
        "correlation engine + professional reporting). Open source "
        "software (MIT), see LICENSE.",
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

    corr_p = sub.add_parser("correlate", help="correlation engine")
    corr_sub = corr_p.add_subparsers(dest="command", required=True)

    def _add_corr_common(p: argparse.ArgumentParser) -> None:
        p.add_argument("--case", dest="case_id", required=True, help="case ID")
        p.add_argument(
            "--window",
            default=None,
            help="temporal window like '30s', '5m', '2h', '1d' "
            "(default: correlate_window_seconds)",
        )
        p.add_argument(
            "--min-sources",
            type=int,
            default=None,
            help="minimum distinct source types for a pivot "
            "(default: correlate_min_sources)",
        )
        p.add_argument(
            "--enrich",
            action="store_true",
            help="allow network intel providers (indicators leave this machine)",
        )

    p_crun = corr_sub.add_parser(
        "run",
        help="correlate a case's evidence into pivots",
        parents=parents,
    )
    _add_corr_common(p_crun)
    p_crun.add_argument(
        "--explain",
        action="store_true",
        help="show the per-pivot score breakdown",
    )
    p_crun.set_defaults(func=cmd_correlate_run)

    p_cent = corr_sub.add_parser(
        "entities",
        help="list normalized entities in a case",
        parents=parents,
    )
    p_cent.add_argument("--case", dest="case_id", required=True, help="case ID")
    p_cent.set_defaults(func=cmd_correlate_entities)

    p_ctime = corr_sub.add_parser(
        "timeline",
        help="incident timeline: case events merged with pivots",
        parents=parents,
    )
    _add_corr_common(p_ctime)
    p_ctime.set_defaults(func=cmd_correlate_timeline)

    ver_p = sub.add_parser(
        "version",
        help="show version and registered module versions",
        parents=parents,
    )
    ver_p.set_defaults(func=cmd_version)

    rep_p = sub.add_parser("report", help="professional reports (HTML/PDF/JSON/CSV)")
    rep_sub = rep_p.add_subparsers(dest="command", required=True)

    def _add_report_common(
        p: argparse.ArgumentParser,
    ) -> None:
        p.add_argument("--output", required=True, help="report output directory")
        p.add_argument(
            "--format",
            default="all",
            choices=("html", "pdf", "json", "csv", "all"),
            help="report format (default: all)",
        )
        p.add_argument(
            "--force",
            action="store_true",
            help="overwrite a non-empty output directory",
        )

    p_rcase = rep_sub.add_parser("case", help="full case report", parents=parents)
    p_rcase.add_argument("case_id", help="case ID")
    _add_report_common(p_rcase)
    p_rcase.set_defaults(func=cmd_report_case)

    p_rpcap = rep_sub.add_parser(
        "pcap", help="report on a single PCAP file", parents=parents
    )
    p_rpcap.add_argument("--file", required=True, help="PCAP file to analyze")
    _add_report_common(p_rpcap)
    p_rpcap.set_defaults(func=cmd_report_pcap)

    p_rlogs = rep_sub.add_parser(
        "logs", help="report on a single log file", parents=parents
    )
    p_rlogs.add_argument("--file", required=True, help="log file to analyze")
    p_rlogs.add_argument(
        "--log-format",
        default=None,
        help="parser hint (default: auto-detect)",
    )
    _add_report_common(p_rlogs)
    p_rlogs.set_defaults(func=cmd_report_logs)

    p_rfor = rep_sub.add_parser(
        "forensics", help="report on a directory tree", parents=parents
    )
    p_rfor.add_argument("--path", required=True, help="root path to inventory")
    _add_report_common(p_rfor)
    p_rfor.set_defaults(func=cmd_report_forensics)

    p_rdom = rep_sub.add_parser(
        "domain", help="report on a domain investigation", parents=parents
    )
    p_rdom.add_argument("--target", required=True, help="domain to investigate")
    p_rdom.add_argument("--resolver", default=None, help="DNS resolver to use")
    p_rdom.add_argument(
        "--timeout", type=float, default=None, help="per-operation timeout"
    )
    p_rdom.add_argument("--no-rdap", action="store_true", help="skip RDAP")
    p_rdom.add_argument("--no-whois", action="store_true", help="skip WHOIS")
    p_rdom.add_argument("--no-web", action="store_true", help="skip HTTP fetch")
    p_rdom.add_argument("--no-tls", action="store_true", help="skip TLS probe")
    _add_report_common(p_rdom)
    p_rdom.set_defaults(func=cmd_report_domain)

    return parser


def cmd_version(args: argparse.Namespace, cfg: AppConfig) -> Result:
    result = Result(command="version")
    registry = get_registry()
    modules = {name: registry.get(name).version for name in registry.names()}
    result.data = {"version": __version__, "modules": modules}
    result.summary = f"aegisforge {__version__}"
    return result


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    configure_logging(args.verbose)

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
