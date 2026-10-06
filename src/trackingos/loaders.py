"""Load operator policy files. These are not action requests."""

from __future__ import annotations

import datetime as dt
import ipaddress
import json
import os
import re
import stat

from trackingos.fsutil import UnsafePathError
from trackingos.models import SCOPE_ID_RE, SUBJECT_RE, AuthorizationGrant, Scope
from trackingos.policy import _HOST_RE, _LAB_RE
from trackingos.registry import _read_policy_file

_GRANT_RE = re.compile(r"^GRT-[0-9A-F]{16}$")


def load_scope(path: str) -> Scope:
    payload = _read_policy_file(path)
    if not isinstance(payload, dict):
        raise ValueError("scope file must be a json object")
    scope_id = payload.get("scope_id")
    if not isinstance(scope_id, str) or not SCOPE_ID_RE.match(scope_id):
        raise ValueError("invalid scope id")
    cidrs = _string_tuple(payload.get("network_cidrs"), "network_cidrs")
    for cidr in cidrs:
        ipaddress.ip_network(cidr, strict=True)
    hostnames = tuple(item.lower() for item in _string_tuple(payload.get("hostnames"), "hostnames"))
    for host in hostnames:
        if not _HOST_RE.match(host) or len(host) > 253:
            raise ValueError(f"invalid hostname in scope: {host}")
    labs = _string_tuple(payload.get("labs"), "labs")
    for lab in labs:
        if not _LAB_RE.match(lab):
            raise ValueError(f"invalid lab id: {lab}")
    roots_in = _string_tuple(payload.get("local_roots"), "local_roots")
    roots: list[str] = []
    for root in roots_in:
        roots.append(_directory_root(root))
    allow_active = payload.get("allow_active")
    if type(allow_active) is not bool:
        raise ValueError("allow_active must be a json boolean")
    return Scope(
        scope_id=scope_id,
        network_cidrs=cidrs,
        hostnames=hostnames,
        local_roots=tuple(roots),
        labs=labs,
        allow_active=allow_active,
    )


def load_grant(path: str) -> AuthorizationGrant:
    _require_private_file(path)
    payload = _read_policy_file(path)
    if not isinstance(payload, dict):
        raise ValueError("grant file must be a json object")
    grant_id = payload.get("grant_id")
    scope_id = payload.get("scope_id")
    subject = payload.get("subject")
    if not isinstance(grant_id, str) or not _GRANT_RE.match(grant_id):
        raise ValueError("invalid grant id")
    if not isinstance(scope_id, str) or not SCOPE_ID_RE.match(scope_id):
        raise ValueError("invalid scope id")
    if not isinstance(subject, str) or not SUBJECT_RE.match(subject):
        raise ValueError("invalid subject")
    allow_active = payload.get("allow_active")
    allow_network = payload.get("allow_network")
    if type(allow_active) is not bool or type(allow_network) is not bool:
        raise ValueError("grant flags must be json booleans")
    not_before = _parse_time(payload.get("not_before"), "not_before")
    not_after = _parse_time(payload.get("not_after"), "not_after")
    if not_after <= not_before:
        raise ValueError("grant window is empty")
    return AuthorizationGrant(
        grant_id=grant_id,
        scope_id=scope_id,
        subject=subject,
        allow_active=allow_active,
        allow_network=allow_network,
        not_before=not_before,
        not_after=not_after,
    )


def _string_tuple(value: object, field: str) -> tuple[str, ...]:
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise ValueError(f"{field} must be a list of strings")
    return tuple(value)


def _directory_root(root: str) -> str:
    if not root.startswith("/") or root == "/":
        raise ValueError("refusing filesystem root as a local scope")
    try:
        st = os.lstat(root)
    except OSError as exc:
        raise ValueError(f"local root unavailable: {root}") from exc
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode):
        raise ValueError("local root must be a real directory")
    real = os.path.realpath(root)
    if real == "/":
        raise ValueError("refusing filesystem root as a local scope")
    return real


def _require_private_file(path: str) -> None:
    if not os.path.isabs(path):
        raise UnsafePathError("grant path must be absolute")
    try:
        st = os.lstat(path)
    except OSError as exc:
        raise UnsafePathError(f"cannot read grant: {exc.strerror}") from exc
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode):
        raise UnsafePathError("grant must be a regular non-symlink file")
    if st.st_mode & 0o077:
        raise UnsafePathError("grant file must be readable only by its owner")


def _parse_time(value: object, field: str) -> dt.datetime:
    if not isinstance(value, str):
        raise ValueError(f"invalid {field}")
    text = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        parsed = dt.datetime.fromisoformat(text)
    except ValueError as exc:
        raise ValueError(f"invalid {field}") from exc
    if parsed.tzinfo is None:
        raise ValueError(f"{field} must include a timezone")
    return parsed.astimezone(dt.timezone.utc)


def dumps_private(path: str, payload: dict) -> None:
    """Write a 0600 JSON file without following a symlink."""
    data = (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode("utf-8")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
    fd = os.open(path, flags, 0o600)
    try:
        os.write(fd, data)
        os.fchmod(fd, 0o600)
        os.fsync(fd)
    finally:
        os.close(fd)
