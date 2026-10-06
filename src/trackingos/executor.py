"""Run an allowlisted tool without a shell.

The process is started with ``shell=False`` and an argument vector. User
strings are never interpolated into a command line. When the tool is not
authorised for network access, the child calls ``unshare(CLONE_NEWNET)``
before ``exec``. If that isolation call fails, the tool is not started.

This is not a full sandbox: the tool runs as the same user as TrackingOS,
output limits are byte caps, and an authorised network is not filtered by
destination. See docs/security-model.md.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import logging
import os
import secrets
import signal
import subprocess
import tempfile
import threading
import time
from pathlib import Path

from trackingos.fsutil import UnsafePathError
from trackingos.models import HARD_OUTPUT_CAP, ActionRequest, ActionResult, AuthorizationGrant
from trackingos.policy import evaluate
from trackingos.registry import ToolRegistry

log = logging.getLogger("trackingos.executor")

_ENTRY = str(Path(__file__).resolve().parent / "isolate_entry.py")
_SAFE_PATH = "/usr/bin:/bin"


def execute(
    request: ActionRequest,
    registry: ToolRegistry,
    grant: AuthorizationGrant | None,
    *,
    cancel: threading.Event | None = None,
    now: dt.datetime | None = None,
    term_grace_s: float = 1.0,
) -> ActionResult:
    moment = now or dt.datetime.now(dt.timezone.utc)
    spec = registry.get(request.tool) if isinstance(request.tool, str) else None
    # Shape checks live in policy. A bad tool name yields tool_name_invalid
    # before a registry lookup is trusted.
    if not isinstance(request.tool, str):
        spec = None
    decision = evaluate(request, spec if _tool_name_ok(request) else None, grant, moment)
    action_id = "ACT-" + secrets.token_hex(16).upper()
    started = _stamp(moment)
    arg_hash = _argument_sha256(request.arguments if isinstance(request.arguments, tuple) else ())
    subject = grant.subject if grant is not None else ""
    base = dict(
        action_id=action_id,
        tool=request.tool if isinstance(request.tool, str) else "",
        target=request.target if isinstance(request.target, str) else "",
        scope_id=request.scope.scope_id,
        subject=subject,
        client_reference=request.client_reference,
        started_at=started,
        argument_count=len(request.arguments) if isinstance(request.arguments, tuple) else 0,
        argument_sha256=arg_hash,
    )
    if not decision.allowed:
        log.info("action %s tool=%s denied reason=%s", action_id, base["tool"], decision.reason)
        return _finish(base, executed=False, reason=decision.reason, network_isolated=False)
    if cancel is not None and cancel.is_set():
        return _finish(base, executed=False, reason="cancelled", cancelled=True, network_isolated=False)
    assert spec is not None
    try:
        exec_fd = registry.open_executable(spec)
    except UnsafePathError as exc:
        log.info("action %s tool=%s unavailable", action_id, spec.name)
        return _finish(base, executed=False, reason="tool_unavailable", network_isolated=False, detail=str(exc))
    work = tempfile.TemporaryDirectory(prefix="trackingos-")
    status_r, status_w = os.pipe()
    os.set_inheritable(status_w, True)
    mode = "netoff" if decision.isolate_network else "open"
    env = {
        "PATH": _SAFE_PATH,
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "HOME": work.name,
        "TMPDIR": work.name,
        "TRACKINGOS_ACTION_ID": action_id,
    }
    argv = [
        _python(),
        _ENTRY,
        mode,
        str(status_w),
        str(exec_fd),
        spec.name,
        *request.arguments,
    ]
    log.info(
        "action %s tool=%s target=%s isolate_network=%s",
        action_id,
        spec.name,
        request.target,
        decision.isolate_network,
    )
    try:
        proc = subprocess.Popen(
            argv,
            shell=False,
            cwd=work.name,
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            pass_fds=(exec_fd, status_w),
            start_new_session=True,
            close_fds=True,
        )
    except OSError as exc:
        os.close(exec_fd)
        os.close(status_r)
        os.close(status_w)
        work.cleanup()
        return _finish(base, executed=False, reason="launcher_failed", network_isolated=False, detail=str(exc))
    os.close(exec_fd)
    os.close(status_w)
    assert proc.stdout is not None and proc.stderr is not None
    limit = min(request.max_output_bytes, HARD_OUTPUT_CAP)
    stdout_box: dict[str, bytes | bool] = {"data": b"", "truncated": False}
    stderr_box: dict[str, bytes | bool] = {"data": b"", "truncated": False}
    threads = [
        threading.Thread(target=_drain, args=(proc.stdout, limit, stdout_box), daemon=True),
        threading.Thread(target=_drain, args=(proc.stderr, limit, stderr_box), daemon=True),
    ]
    for thread in threads:
        thread.start()
    deadline = time.monotonic() + float(request.timeout_s)
    timed_out = False
    cancelled = False
    truncated = False
    while proc.poll() is None:
        if stdout_box["truncated"] or stderr_box["truncated"]:
            truncated = True
            _terminate(proc, term_grace_s)
            break
        if cancel is not None and cancel.is_set():
            cancelled = True
            _terminate(proc, term_grace_s)
            break
        if time.monotonic() >= deadline:
            timed_out = True
            _terminate(proc, term_grace_s)
            break
        time.sleep(0.02)
    try:
        proc.wait(timeout=max(term_grace_s, 0.2) + 2)
    except subprocess.TimeoutExpired:
        _terminate(proc, term_grace_s)
        proc.wait(timeout=5)
    for thread in threads:
        thread.join(timeout=2)
    marker = os.read(status_r, 1)
    os.close(status_r)
    stdout = stdout_box["data"] if isinstance(stdout_box["data"], bytes) else b""
    stderr = stderr_box["data"] if isinstance(stderr_box["data"], bytes) else b""
    stdout_truncated = bool(stdout_box["truncated"]) or (truncated and bool(stdout_box["truncated"]))
    stderr_truncated = bool(stderr_box["truncated"])
    work.cleanup()
    if marker == b"I":
        return _finish(
            base,
            executed=False,
            reason="network_isolation_unavailable",
            network_isolated=False,
            exit_code=proc.returncode,
            stderr=stderr,
        )
    if marker != b"R":
        return _finish(
            base,
            executed=False,
            reason="launcher_failed",
            network_isolated=decision.isolate_network,
            exit_code=proc.returncode,
            stderr=stderr,
        )
    reason = None
    if timed_out:
        reason = "timeout"
    elif cancelled:
        reason = "cancelled"
    elif stdout_truncated or stderr_truncated:
        reason = "output_limited"
    return _finish(
        base,
        executed=True,
        reason=reason,
        exit_code=proc.returncode,
        timed_out=timed_out,
        cancelled=cancelled,
        stdout=stdout,
        stderr=stderr,
        stdout_truncated=stdout_truncated,
        stderr_truncated=stderr_truncated,
        network_isolated=decision.isolate_network,
    )


def _tool_name_ok(request: ActionRequest) -> bool:
    return isinstance(request.tool, str)


def _python() -> str:
    import sys

    return sys.executable


def _drain(pipe, limit: int, box: dict[str, bytes | bool]) -> None:
    chunks: list[bytes] = []
    total = 0
    try:
        while True:
            chunk = os.read(pipe.fileno(), 65536)
            if not chunk:
                break
            room = limit - total
            if room <= 0:
                box["truncated"] = True
                break
            if len(chunk) > room:
                chunks.append(chunk[:room])
                total += room
                box["truncated"] = True
                break
            chunks.append(chunk)
            total += len(chunk)
    finally:
        box["data"] = b"".join(chunks)
        try:
            pipe.close()
        except OSError:
            pass


def _terminate(proc: subprocess.Popen[bytes], grace: float) -> None:
    try:
        os.killpg(proc.pid, signal.SIGTERM)
    except (ProcessLookupError, PermissionError):
        return
    try:
        proc.wait(timeout=grace)
        return
    except subprocess.TimeoutExpired:
        pass
    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        return
    try:
        proc.wait(timeout=grace)
    except subprocess.TimeoutExpired:
        pass


def _argument_sha256(arguments: tuple[str, ...]) -> str:
    payload = json.dumps(list(arguments), separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _stamp(moment: dt.datetime) -> str:
    return moment.astimezone(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _finish(
    base: dict,
    *,
    executed: bool,
    reason: str | None,
    network_isolated: bool,
    exit_code: int | None = None,
    timed_out: bool = False,
    cancelled: bool = False,
    stdout: bytes = b"",
    stderr: bytes = b"",
    stdout_truncated: bool = False,
    stderr_truncated: bool = False,
    detail: str | None = None,
) -> ActionResult:
    ended = _stamp(dt.datetime.now(dt.timezone.utc))
    if detail and not executed:
        log.info("action %s not executed reason=%s detail=%s", base["action_id"], reason, detail)
    return ActionResult(
        action_id=base["action_id"],
        tool=base["tool"],
        target=base["target"],
        scope_id=base["scope_id"],
        subject=base["subject"],
        client_reference=base["client_reference"],
        started_at=base["started_at"],
        ended_at=ended,
        executed=executed,
        reason=reason,
        exit_code=exit_code,
        timed_out=timed_out,
        cancelled=cancelled,
        stdout_truncated=stdout_truncated,
        stderr_truncated=stderr_truncated,
        stdout=stdout if executed else b"",
        stderr=stderr if executed or reason == "network_isolation_unavailable" else b"",
        stdout_sha256=hashlib.sha256(stdout).hexdigest() if executed else None,
        stderr_sha256=hashlib.sha256(stderr).hexdigest() if executed else None,
        network_isolated=network_isolated,
        argument_count=base["argument_count"],
        argument_sha256=base["argument_sha256"],
    )
