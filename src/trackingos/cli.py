"""Operator CLI. There is no flag that marks an action authorised."""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import secrets
import sys

from trackingos import __version__
from trackingos.build_host import assess_build_host
from trackingos.evidence import CASE_RE, CaseStore, StorageError, UnsafePathError
from trackingos.executor import execute
from trackingos.loaders import load_grant, load_scope
from trackingos.models import ActionRequest, ActionResult
from trackingos.osint import (
    decide_target,
    dns_lookup,
    load_programs,
    make_program,
    save_program,
    select_program,
    system_resolver,
)
from trackingos.registry import ToolRegistry


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="trackingos")
    parser.add_argument("--version", action="version", version=f"trackingos {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    case = sub.add_parser("case", help="create an investigation")
    case_sub = case.add_subparsers(dest="case_command", required=True)
    create = case_sub.add_parser("create")
    create.add_argument("--store", required=True)
    create.add_argument("--title", required=True)
    create.add_argument("--investigator", required=True)
    create.add_argument("--description", default="")
    create.add_argument("--id", default=None)
    create.set_defaults(func=_case_create)

    evidence = sub.add_parser("evidence", help="store or check evidence")
    evidence_sub = evidence.add_subparsers(dest="evidence_command", required=True)
    add = evidence_sub.add_parser("add")
    add.add_argument("--store", required=True)
    add.add_argument("--case", required=True)
    add.add_argument("--file", required=True)
    add.add_argument("--source", required=True)
    add.set_defaults(func=_evidence_add)
    verify = evidence_sub.add_parser("verify")
    verify.add_argument("--store", required=True)
    verify.add_argument("--case", required=True)
    verify.add_argument("--evidence", required=True)
    verify.set_defaults(func=_evidence_verify)

    action = sub.add_parser("action", help="run an allowlisted tool")
    action_sub = action.add_subparsers(dest="action_command", required=True)
    run = action_sub.add_parser("run")
    run.add_argument("--store", required=True)
    run.add_argument("--case", required=True)
    run.add_argument("--registry", required=True)
    run.add_argument("--scope", required=True)
    run.add_argument("--grant", required=True)
    run.add_argument("--tool", required=True)
    run.add_argument("--target", required=True)
    run.add_argument("--timeout", type=float, default=60)
    run.add_argument("arguments", nargs=argparse.REMAINDER)
    run.set_defaults(func=_action_run)

    doctor = sub.add_parser("doctor", help="check the tool allowlist without executing it")
    doctor.add_argument("--registry", required=True)
    doctor.set_defaults(func=_doctor)

    host = sub.add_parser("build-host", help="check image-build prerequisites")
    host.set_defaults(func=_build_host)

    osint = sub.add_parser("osint", help="bug-bounty scope and passive DNS")
    osint_sub = osint.add_subparsers(dest="osint_command", required=True)
    program_add = osint_sub.add_parser("program", help="record an authorised bounty program")
    program_add.add_argument("--store", required=True)
    program_add.add_argument("--case", required=True)
    program_add.add_argument("--name", required=True)
    program_add.add_argument("--platform", required=True)
    program_add.add_argument("--domain", action="append", default=[])
    program_add.add_argument("--cidr", action="append", default=[])
    program_add.add_argument("--out-domain", action="append", default=[])
    program_add.add_argument("--out-cidr", action="append", default=[])
    program_add.add_argument("--no-dns", action="store_true")
    program_add.set_defaults(func=_osint_program)
    check = osint_sub.add_parser("check", help="test a target against the program, no network")
    check.add_argument("--store", required=True)
    check.add_argument("--case", required=True)
    check.add_argument("--program", default=None)
    check.add_argument("--target", required=True)
    check.set_defaults(func=_osint_check)
    dns = osint_sub.add_parser("dns", help="resolve one in-scope name and store the result")
    dns.add_argument("--store", required=True)
    dns.add_argument("--case", required=True)
    dns.add_argument("--program", default=None)
    dns.add_argument("--grant", required=True)
    dns.add_argument("--target", required=True)
    dns.set_defaults(func=_osint_dns)
    brief = osint_sub.add_parser("brief", help="show the program boundary")
    brief.add_argument("--store", required=True)
    brief.add_argument("--case", required=True)
    brief.add_argument("--program", default=None)
    brief.set_defaults(func=_osint_brief)

    args = parser.parse_args(argv)
    try:
        return int(args.func(args))
    except (ValueError, StorageError, UnsafePathError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


def _case_create(args: argparse.Namespace) -> int:
    with CaseStore(args.store) as store:
        case_id = store.create_case(args.title, args.investigator, args.description, args.id)
    print(case_id)
    return 0


def _evidence_add(args: argparse.Namespace) -> int:
    with CaseStore(args.store) as store:
        evidence_id = store.add_evidence_file(args.case, args.file, args.source)
    print(evidence_id)
    return 0


def _evidence_verify(args: argparse.Namespace) -> int:
    with CaseStore(args.store) as store:
        report = store.verify_evidence(args.case, args.evidence)
    if report.ok:
        print("ok")
        return 0
    for problem in report.problems:
        print(problem)
    return 1


def _action_run(args: argparse.Namespace) -> int:
    arguments = tuple(args.arguments)
    if arguments and arguments[0] == "--":
        arguments = arguments[1:]
    scope = load_scope(os.path.abspath(args.scope))
    grant = load_grant(os.path.abspath(args.grant))
    registry = ToolRegistry.load(os.path.abspath(args.registry))
    request = ActionRequest(
        tool=args.tool,
        target=args.target,
        scope=scope,
        arguments=arguments,
        timeout_s=args.timeout,
    )
    result = execute(request, registry, grant)
    if not CASE_RE.match(args.case):
        raise ValueError("invalid case id")
    with CaseStore(args.store) as store:
        store.record_action(args.case, _record(result), result.stdout, result.stderr)
    _print_result(result)
    if not result.executed:
        if result.reason == "cancelled":
            return 4
        return 3
    if result.timed_out or result.cancelled:
        return 4
    if result.exit_code != 0:
        return 1
    return 0


def _doctor(args: argparse.Namespace) -> int:
    registry = ToolRegistry.load(os.path.abspath(args.registry))
    missing = False
    for name, present, detail in registry.doctor():
        state = "present" if present else "missing"
        print(f"{name} {state} {detail}")
        missing = missing or not present
    return 1 if missing else 0


def _build_host(_args: argparse.Namespace) -> int:
    report = assess_build_host()
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["iso_build_ready"] else 2


def _osint_program(args: argparse.Namespace) -> int:
    created_at = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    program = make_program(
        program_id="PROG-" + secrets.token_hex(8).upper(),
        case_id=args.case,
        name=args.name,
        platform=args.platform,
        in_scope_domains=args.domain,
        out_of_scope_domains=args.out_domain,
        in_scope_cidrs=args.cidr,
        out_of_scope_cidrs=args.out_cidr,
        allow_dns=not args.no_dns,
        created_at=created_at,
    )
    with CaseStore(args.store) as store:
        save_program(store, program)
    print(program.program_id)
    print("allow_active: no")
    print("allow_dns: " + ("yes" if program.allow_dns else "no"))
    return 0


def _osint_check(args: argparse.Namespace) -> int:
    with CaseStore(args.store) as store:
        program = select_program(load_programs(store, args.case), args.program)
    decision = decide_target(program, args.target)
    print(f"program_id: {program.program_id}")
    print(f"target: {decision.kind}:{decision.value}")
    print(f"allowed: {'yes' if decision.allowed else 'no'}")
    print(f"reason: {decision.reason}")
    print("active: no")
    return 0 if decision.allowed else 3


def _osint_dns(args: argparse.Namespace) -> int:
    grant = load_grant(os.path.abspath(args.grant))
    now = dt.datetime.now(dt.timezone.utc)
    with CaseStore(args.store) as store:
        program = select_program(load_programs(store, args.case), args.program)
        try:
            result = dns_lookup(program, args.target, grant, now=now, resolver=system_resolver)
        except OSError as exc:
            result = {
                "executed": False,
                "reason": "dns_failed",
                "host": args.target,
                "addresses": [],
                "outside_cidr": [],
                "error": exc.strerror or str(exc),
            }
        payload = (json.dumps(result, indent=2, sort_keys=True) + "\n").encode("utf-8")
        host = str(result.get("host") or "lookup")
        evidence_id = store.add_evidence_bytes(
            program.case_id,
            payload,
            "osint-dns",
            _dns_filename(host),
            media_type="application/json",
        )
        outside = result.get("outside_cidr") or []
        detail = (
            f"host={result.get('host')} executed={result.get('executed')} "
            f"reason={result.get('reason')} evidence={evidence_id} "
            f"addresses={','.join(result.get('addresses') or []) or '-'} "
            f"do_not_scan={','.join(outside) or '-'}"
        )
        store.add_finding(
            program.case_id,
            "DNS lookup",
            detail[:100_000],
            grant.subject,
        )
    print(f"program_id: {program.program_id}")
    print(f"executed: {'yes' if result.get('executed') else 'no'}")
    print(f"reason: {result.get('reason')}")
    print(f"evidence_id: {evidence_id}")
    for address in result.get("addresses") or []:
        print(f"address: {address}")
    for address in result.get("outside_cidr") or []:
        print(f"do_not_scan: {address}")
    if result.get("error"):
        print(f"error: {result['error']}")
    return 0 if result.get("executed") else 3


def _osint_brief(args: argparse.Namespace) -> int:
    with CaseStore(args.store) as store:
        program = select_program(load_programs(store, args.case), args.program)
    print(f"program_id: {program.program_id}")
    print(f"name: {program.name}")
    print(f"platform: {program.platform}")
    print("allow_active: no")
    print("allow_dns: " + ("yes" if program.allow_dns else "no"))
    print("in_scope_domains: " + (",".join(program.in_scope_domains) or "-"))
    print("out_of_scope_domains: " + (",".join(program.out_of_scope_domains) or "-"))
    print("in_scope_cidrs: " + (",".join(program.in_scope_cidrs) or "-"))
    print("out_of_scope_cidrs: " + (",".join(program.out_of_scope_cidrs) or "-"))
    print("note: resolved addresses outside these cidrs are not targets")
    return 0


def _dns_filename(host: str) -> str:
    cleaned = host.replace(":", "_")
    if not cleaned or len(cleaned) > 200:
        return "dns.json"
    return cleaned + ".dns.json"


def _record(result: ActionResult) -> dict:
    return {
        "schema": 1,
        "action_id": result.action_id,
        "tool": result.tool,
        "target": result.target,
        "scope_id": result.scope_id,
        "subject": result.subject,
        "client_reference": result.client_reference,
        "started_at": result.started_at,
        "ended_at": result.ended_at,
        "executed": result.executed,
        "reason": result.reason,
        "exit_code": result.exit_code,
        "timed_out": result.timed_out,
        "cancelled": result.cancelled,
        "stdout_truncated": result.stdout_truncated,
        "stderr_truncated": result.stderr_truncated,
        "stdout_sha256": result.stdout_sha256,
        "stderr_sha256": result.stderr_sha256,
        "stdout_bytes": len(result.stdout),
        "stderr_bytes": len(result.stderr),
        "network_isolated": result.network_isolated,
        "argument_count": result.argument_count,
        "argument_sha256": result.argument_sha256,
    }


def _print_result(result: ActionResult) -> None:
    print(f"action_id: {result.action_id}")
    print(f"executed: {'yes' if result.executed else 'no'}")
    print(f"reason: {result.reason or ''}")
    print(f"exit_code: {'' if result.exit_code is None else result.exit_code}")
    print(f"timed_out: {'yes' if result.timed_out else 'no'}")
    print(f"cancelled: {'yes' if result.cancelled else 'no'}")
    print(f"network_isolated: {'yes' if result.network_isolated else 'no'}")
    if result.stdout_sha256:
        print(f"stdout_sha256: {result.stdout_sha256}")
    if result.executed and result.stdout:
        sys.stdout.buffer.write(b"--- stdout ---\n")
        sys.stdout.buffer.write(result.stdout)
        if not result.stdout.endswith(b"\n"):
            sys.stdout.buffer.write(b"\n")
