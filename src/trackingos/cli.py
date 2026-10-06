"""Operator CLI. There is no flag that marks an action authorised."""

from __future__ import annotations

import argparse
import json
import os
import sys

from trackingos import __version__
from trackingos.build_host import assess_build_host
from trackingos.evidence import CASE_RE, CaseStore, StorageError, UnsafePathError
from trackingos.executor import execute
from trackingos.loaders import load_grant, load_scope
from trackingos.models import ActionRequest, ActionResult
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
