"""Domain investigation command implementations."""

from __future__ import annotations

import argparse
import json
from typing import Any

from aegisforge.core.config import AppConfig
from aegisforge.core.events import Event
from aegisforge.core.results import Result
from aegisforge.domain import dns_client as domain_dns_client
from aegisforge.domain import investigate as investigate_mod
from aegisforge.network.validation import ValidationError


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
