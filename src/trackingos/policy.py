"""Authorisation policy. Independent of any user interface.

A request has no ``authorised`` field. The grant is a separate object the
caller loads from operator-controlled storage. Grants can only narrow a
scope: ``allow_active`` on a grant does nothing if the scope forbids active
work.

Hostnames are matched literally. This module does not resolve DNS.
"""

from __future__ import annotations

import datetime as dt
import ipaddress
import os
import re
import stat

from trackingos.models import (
    CLIENT_REF_RE,
    HARD_OUTPUT_CAP,
    MAX_ARGUMENT_BYTES,
    MAX_ARGUMENTS,
    MAX_TIMEOUT_S,
    TOOL_NAME_RE,
    ActionRequest,
    AuthorizationGrant,
    Decision,
    ToolSpec,
)

_HOST_RE = re.compile(
    r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*$"
)
_LAB_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,63}$")


def evaluate(
    request: ActionRequest,
    spec: ToolSpec | None,
    grant: AuthorizationGrant | None,
    now: dt.datetime,
) -> Decision:
    structural = _validate_shape(request)
    if structural is not None:
        return Decision(False, structural, False)
    if spec is None or spec.name != request.tool:
        return Decision(False, "tool_unknown", False)
    if grant is None:
        return Decision(False, "missing_grant", False)
    if now.tzinfo is None:
        return Decision(False, "clock_naive", False)
    moment = now.astimezone(dt.timezone.utc)
    if grant.scope_id != request.scope.scope_id:
        return Decision(False, "scope_mismatch", False)
    if moment < grant.not_before:
        return Decision(False, "grant_not_yet_valid", False)
    if moment >= grant.not_after:
        return Decision(False, "grant_expired", False)
    target_reason = _target_allowed(request)
    if target_reason is not None:
        return Decision(False, target_reason, False)
    if spec.path_policy == "absolute-only":
        path_reason = _paths_allowed(request)
        if path_reason is not None:
            return Decision(False, path_reason, False)
    if spec.operation == "active" and not (request.scope.allow_active and grant.allow_active):
        return Decision(False, "active_not_authorised", False)
    if spec.network == "required" and not grant.allow_network:
        return Decision(False, "network_not_authorised", False)
    isolate = spec.network == "none" or not grant.allow_network
    return Decision(True, "authorised", isolate)


def _validate_shape(request: ActionRequest) -> str | None:
    if not isinstance(request.tool, str) or not TOOL_NAME_RE.match(request.tool):
        return "tool_name_invalid"
    if not isinstance(request.arguments, tuple):
        return "arguments_invalid"
    if len(request.arguments) > MAX_ARGUMENTS:
        return "arguments_invalid"
    for arg in request.arguments:
        if not isinstance(arg, str) or "\x00" in arg or len(arg.encode("utf-8")) > MAX_ARGUMENT_BYTES:
            return "arguments_invalid"
    if not isinstance(request.timeout_s, (int, float)) or isinstance(request.timeout_s, bool):
        return "timeout_invalid"
    if not (0 < float(request.timeout_s) <= MAX_TIMEOUT_S):
        return "timeout_invalid"
    if not isinstance(request.max_output_bytes, int) or isinstance(request.max_output_bytes, bool):
        return "arguments_invalid"
    if not (1 <= request.max_output_bytes <= HARD_OUTPUT_CAP):
        return "arguments_invalid"
    if not CLIENT_REF_RE.match(request.client_reference or ""):
        return "arguments_invalid"
    return _target_grammar(request.target)


def _target_grammar(target: object) -> str | None:
    if not isinstance(target, str) or not target or "\x00" in target:
        return "target_invalid"
    kind, sep, rest = target.partition(":")
    if sep != ":" or not rest or kind not in ("ip", "host", "path", "lab"):
        return "target_invalid"
    if kind == "ip":
        try:
            address = ipaddress.ip_address(rest)
        except ValueError:
            return "target_invalid"
        if address.is_unspecified or address.is_multicast:
            return "target_invalid"
        return None
    if kind == "host":
        host = rest.lower()
        if not _HOST_RE.match(host) or len(host) > 253:
            return "target_invalid"
        return None
    if kind == "lab":
        if not _LAB_RE.match(rest):
            return "target_invalid"
        return None
    if not rest.startswith("/") or len(rest) > 4096:
        return "target_invalid"
    return None


def _target_allowed(request: ActionRequest) -> str | None:
    target = request.target
    kind, sep, rest = target.partition(":")
    if sep != ":" or not rest or kind not in ("ip", "host", "path", "lab"):
        return "target_invalid"
    scope = request.scope
    if kind == "ip":
        return _ip_allowed(rest, scope.network_cidrs)
    if kind == "host":
        host = rest.lower()
        if not _HOST_RE.match(host) or len(host) > 253:
            return "target_invalid"
        if host not in scope.hostnames:
            return "target_out_of_scope"
        return None
    if kind == "lab":
        if not _LAB_RE.match(rest):
            return "target_invalid"
        if rest not in scope.labs:
            return "target_out_of_scope"
        return None
    return _path_in_roots(rest, scope.local_roots)


def _ip_allowed(text: str, cidrs: tuple[str, ...]) -> str | None:
    try:
        address = ipaddress.ip_address(text)
    except ValueError:
        return "target_invalid"
    if address.is_unspecified or address.is_multicast:
        return "target_invalid"
    for cidr in cidrs:
        network = ipaddress.ip_network(cidr, strict=True)
        if address in network and address.version == network.version:
            return None
    return "target_out_of_scope"


def _paths_allowed(request: ActionRequest) -> str | None:
    if not request.arguments:
        return "path_out_of_scope"
    for arg in request.arguments:
        reason = _path_in_roots(arg, request.scope.local_roots)
        if reason is not None:
            return reason
    return None


def _path_in_roots(path: str, roots: tuple[str, ...]) -> str | None:
    if not path.startswith("/") or "\x00" in path or len(path) > 4096:
        return "path_out_of_scope"
    parts = path.split("/")
    if any(part in ("", ".", "..") for part in parts[1:]):
        return "path_out_of_scope"
    current = "/"
    last = None
    try:
        for part in parts[1:]:
            current = os.path.join(current, part)
            last = os.lstat(current)
            if stat.S_ISLNK(last.st_mode):
                return "path_out_of_scope"
            if not stat.S_ISDIR(last.st_mode) and current != path:
                return "path_out_of_scope"
    except OSError:
        return "path_out_of_scope"
    if last is None or not stat.S_ISREG(last.st_mode):
        return "path_out_of_scope"
    real = os.path.realpath(current)
    for root in roots:
        root_real = os.path.realpath(root)
        if root_real == "/":
            return "path_out_of_scope"
        try:
            if os.path.commonpath([real, root_real]) == root_real:
                return None
        except ValueError:
            continue
    return "path_out_of_scope"
