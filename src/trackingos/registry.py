"""Trusted tool allowlist. The action request selects a name, never a path."""

from __future__ import annotations

import json
import os
import stat

from trackingos.fsutil import UnsafePathError
from trackingos.models import ToolSpec

_POLICY_LIMIT = 1_048_576


class ToolRegistry:
    def __init__(self, tools: tuple[ToolSpec, ...], allowed_roots: tuple[str, ...]) -> None:
        if not allowed_roots:
            raise ValueError("executable roots are required")
        cleaned: list[str] = []
        for root in allowed_roots:
            if not isinstance(root, str) or not root.startswith("/") or root == "/":
                raise ValueError("refusing executable root")
            try:
                st = os.lstat(root)
            except OSError as exc:
                raise ValueError(f"executable root unavailable: {root}") from exc
            if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode):
                raise ValueError("executable root must be a real directory")
            real = os.path.realpath(root)
            if real == "/":
                raise ValueError("refusing filesystem root")
            cleaned.append(real)
        names = [tool.name for tool in tools]
        if len(names) != len(set(names)):
            raise ValueError("duplicate tool name")
        for tool in tools:
            _configured_under_roots(tool.executable, tuple(cleaned))
        self._tools = {tool.name: tool for tool in tools}
        self.allowed_roots = tuple(cleaned)

    def get(self, name: str) -> ToolSpec | None:
        return self._tools.get(name)

    def names(self) -> tuple[str, ...]:
        return tuple(sorted(self._tools))

    def doctor(self) -> tuple[tuple[str, bool, str], ...]:
        """Return ``(name, present, detail)`` without executing anything."""
        rows = []
        for name in self.names():
            spec = self._tools[name]
            try:
                self.open_executable(spec)
            except UnsafePathError as exc:
                rows.append((name, False, str(exc)))
            else:
                rows.append((name, True, spec.executable))
        return tuple(rows)

    def open_executable(self, spec: ToolSpec) -> int:
        """Open the tool inode and pin it. Caller closes the fd.

        Re-checks the path at execution time. A registry entry that has been
        replaced by a symlink to somewhere outside the allowed roots is refused.
        """
        _configured_under_roots(spec.executable, self.allowed_roots)
        try:
            fd = os.open(spec.executable, os.O_RDONLY)
        except OSError as exc:
            raise UnsafePathError(f"tool unavailable: {spec.name}") from exc
        try:
            st = os.fstat(fd)
            if not stat.S_ISREG(st.st_mode):
                raise UnsafePathError(f"tool is not a regular file: {spec.name}")
            if st.st_mode & 0o002:
                raise UnsafePathError(f"tool is world-writable: {spec.name}")
            if not (st.st_mode & 0o111):
                raise UnsafePathError(f"tool is not executable: {spec.name}")
            located = os.readlink(f"/proc/self/fd/{fd}")
            if located.endswith(" (deleted)"):
                raise UnsafePathError(f"tool was deleted: {spec.name}")
            if not _realpath_under_roots(located, self.allowed_roots):
                raise UnsafePathError(f"tool escapes executable roots: {spec.name}")
            os.set_inheritable(fd, True)
            return fd
        except Exception:
            os.close(fd)
            raise

    @staticmethod
    def load(path: str, strict: bool = False) -> ToolRegistry:
        payload = _read_policy_file(path)
        if not isinstance(payload, dict) or payload.get("schema") != 1:
            raise ValueError("registry schema must be 1")
        roots = payload.get("allowed_executable_roots")
        tools_raw = payload.get("tools")
        if not isinstance(roots, list) or not isinstance(tools_raw, list):
            raise ValueError("invalid registry")
        tools: list[ToolSpec] = []
        for item in tools_raw:
            if not isinstance(item, dict):
                raise ValueError("invalid tool entry")
            spec = ToolSpec(
                name=item["name"],
                executable=item["executable"],
                operation=item["operation"],
                network=item["network"],
                path_policy=item["path_policy"],
                summary=str(item.get("summary", "")),
            )
            if strict and not os.path.exists(spec.executable):
                raise ValueError(f"missing tool: {spec.name}")
            tools.append(spec)
        return ToolRegistry(tuple(tools), tuple(roots))


def _configured_under_roots(executable: str, roots: tuple[str, ...]) -> None:
    if not executable.startswith("/") or "\x00" in executable:
        raise ValueError("executable must be an absolute path")
    parts = executable.split("/")
    if any(part in ("", ".", "..") for part in parts[1:]):
        raise ValueError("executable must be an absolute path")
    parent = os.path.realpath(os.path.dirname(executable))
    candidate = os.path.join(parent, os.path.basename(executable))
    if not any(_is_under(candidate, root) for root in roots):
        raise ValueError(f"executable is outside allowed roots: {executable}")


def _realpath_under_roots(path: str, roots: tuple[str, ...]) -> bool:
    real = os.path.realpath(path)
    return any(_is_under(real, root) for root in roots)


def _is_under(path: str, root: str) -> bool:
    root_real = os.path.realpath(root)
    if root_real == "/":
        return False
    try:
        return os.path.commonpath([os.path.realpath(path), root_real]) == root_real
    except ValueError:
        return False


def _read_policy_file(path: str) -> object:
    if not os.path.isabs(path):
        raise UnsafePathError("policy path must be absolute")
    try:
        st = os.lstat(path)
    except OSError as exc:
        raise UnsafePathError(f"cannot read policy file: {exc.strerror}") from exc
    if stat.S_ISLNK(st.st_mode):
        raise UnsafePathError("refusing symlink policy file")
    if not stat.S_ISREG(st.st_mode):
        raise UnsafePathError("policy file must be a regular file")
    if st.st_mode & 0o022:
        raise UnsafePathError("refusing group or world-writable policy file")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        data = os.read(fd, _POLICY_LIMIT + 1)
    finally:
        os.close(fd)
    if len(data) > _POLICY_LIMIT:
        raise ValueError("policy file too large")
    try:
        return json.loads(data.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError("policy file is not json") from exc
