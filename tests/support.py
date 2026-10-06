"""Shared builders for security tests. Not production policy."""

from __future__ import annotations

import datetime as dt
import os
import shutil
import sys
import tempfile
from pathlib import Path

from trackingos.models import AuthorizationGrant, Scope, ToolSpec
from trackingos.registry import ToolRegistry

ROOT = Path(__file__).resolve().parents[1]
RECORDER_SRC = Path(__file__).resolve().parent / "fixtures" / "recorder.py"


def install_recorder(directory: Path, name: str = "recorder.py") -> Path:
    body = RECORDER_SRC.read_text(encoding="utf-8")
    dest = directory / name
    dest.write_text(f"#!{sys.executable}\n" + body, encoding="utf-8")
    os.chmod(dest, 0o755)
    return dest


def private_dir() -> str:
    path = tempfile.mkdtemp(prefix="tos-")
    os.chmod(path, 0o700)
    return path


def scope_for(
    data: str,
    *,
    scope_id: str = "lab-a",
    cidrs: tuple[str, ...] = ("203.0.113.0/24",),
    hostnames: tuple[str, ...] = ("lab.example",),
    labs: tuple[str, ...] = ("lab-a",),
    allow_active: bool = False,
) -> Scope:
    return Scope(
        scope_id=scope_id,
        network_cidrs=cidrs,
        hostnames=hostnames,
        local_roots=(os.path.realpath(data),),
        labs=labs,
        allow_active=allow_active,
    )


def grant_for(
    scope: Scope,
    *,
    allow_active: bool = False,
    allow_network: bool = False,
    not_before: dt.datetime | None = None,
    not_after: dt.datetime | None = None,
) -> AuthorizationGrant:
    return AuthorizationGrant(
        grant_id="GRT-0123456789ABCDEF",
        scope_id=scope.scope_id,
        subject="investigator",
        allow_active=allow_active,
        allow_network=allow_network,
        not_before=not_before or dt.datetime(2020, 1, 1, tzinfo=dt.timezone.utc),
        not_after=not_after or dt.datetime(2099, 1, 1, tzinfo=dt.timezone.utc),
    )


def registry_for(executable: Path, **overrides: object) -> ToolRegistry:
    spec = ToolSpec(
        name="recorder",
        executable=str(executable.resolve()),
        operation=overrides.get("operation", "passive"),  # type: ignore[arg-type]
        network=overrides.get("network", "none"),  # type: ignore[arg-type]
        path_policy=overrides.get("path_policy", "none"),  # type: ignore[arg-type]
        summary="test fixture",
    )
    return ToolRegistry((spec,), (str(executable.resolve().parent),))


def write_private(path: Path, text: str, mode: int = 0o600) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    try:
        os.write(fd, text.encode("utf-8"))
        os.fchmod(fd, mode)
    finally:
        os.close(fd)


def which_sha() -> str | None:
    return shutil.which("sha256sum")
