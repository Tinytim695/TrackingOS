"""Request and result types. Requests cannot carry an allow/deny flag."""

from __future__ import annotations

import datetime as dt
import re
from dataclasses import dataclass
from typing import Literal

TOOL_NAME_RE = re.compile(r"^[a-z][a-z0-9._-]{0,63}$")
SCOPE_ID_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,63}$")
GRANT_ID_RE = re.compile(r"^GRT-[0-9A-F]{16}$")
SUBJECT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 ._'@-]{0,127}$")
CLIENT_REF_RE = re.compile(r"^[A-Za-z0-9._:-]{0,64}$")

Operation = Literal["passive", "active"]
NetworkNeed = Literal["none", "optional", "required"]
PathPolicy = Literal["none", "absolute-only"]

HARD_OUTPUT_CAP = 8 * 1024 * 1024
MAX_ARGUMENTS = 64
MAX_ARGUMENT_BYTES = 4096
MAX_TIMEOUT_S = 24 * 60 * 60


@dataclass(frozen=True)
class ToolSpec:
    name: str
    executable: str
    operation: Operation
    network: NetworkNeed
    path_policy: PathPolicy
    summary: str

    def __post_init__(self) -> None:
        if not TOOL_NAME_RE.match(self.name):
            raise ValueError(f"invalid tool name: {self.name}")
        if self.operation not in ("passive", "active"):
            raise ValueError("invalid operation")
        if self.network not in ("none", "optional", "required"):
            raise ValueError("invalid network mode")
        if self.path_policy not in ("none", "absolute-only"):
            raise ValueError("invalid path policy")
        if self.operation == "passive" and self.network == "required":
            raise ValueError("a passive tool cannot require network")
        if not self.executable.startswith("/"):
            raise ValueError("executable must be an absolute path")


@dataclass(frozen=True)
class Scope:
    scope_id: str
    network_cidrs: tuple[str, ...]
    hostnames: tuple[str, ...]
    local_roots: tuple[str, ...]
    labs: tuple[str, ...]
    allow_active: bool


@dataclass(frozen=True)
class AuthorizationGrant:
    grant_id: str
    scope_id: str
    subject: str
    allow_active: bool
    allow_network: bool
    not_before: dt.datetime
    not_after: dt.datetime


@dataclass(frozen=True)
class ActionRequest:
    tool: str
    target: str
    scope: Scope
    arguments: tuple[str, ...]
    timeout_s: float
    client_reference: str = ""
    max_output_bytes: int = 1024 * 1024


@dataclass(frozen=True)
class Decision:
    allowed: bool
    reason: str
    isolate_network: bool


@dataclass(frozen=True)
class ActionResult:
    action_id: str
    tool: str
    target: str
    scope_id: str
    subject: str
    client_reference: str
    started_at: str
    ended_at: str
    executed: bool
    reason: str | None
    exit_code: int | None
    timed_out: bool
    cancelled: bool
    stdout_truncated: bool
    stderr_truncated: bool
    stdout: bytes
    stderr: bytes
    stdout_sha256: str | None
    stderr_sha256: str | None
    network_isolated: bool
    argument_count: int
    argument_sha256: str
