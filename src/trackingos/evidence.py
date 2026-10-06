"""Append-only investigation store.

Security assumptions:
- The store root is a real directory the operator controls, never a symlink.
- Object ids are the file names. They cannot contain path separators.
- Creates use O_EXCL / link(2) that fails if the destination exists. Rename is
  not used, because rename replaces. A crash may leave a ``.tmp-*`` file; it
  is not a canonical evidence object.
- Payload bytes are hashed while they are written. ``verify`` re-reads the
  same inode through O_NOFOLLOW.
- Evidence files are never executed.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
import re
import secrets
import stat
from dataclasses import dataclass
from typing import Any, Callable

from trackingos.fsutil import (
    CollisionError,
    StorageError,
    UnsafePathError,
    copy_fd_exclusive,
    mkdir_exclusive,
    open_child_dir,
    open_file_nofollow,
    open_root,
    read_file_limited,
    write_bytes_exclusive,
)

CASE_RE = re.compile(r"^TOS-[0-9]{8}-[0-9A-F]{8}$")
EVIDENCE_RE = re.compile(r"^EV-[0-9A-F]{16}$")
ACTION_RE = re.compile(r"^ACT-[0-9A-F]{32}$")
NOTE_RE = re.compile(r"^NOTE-[0-9A-F]{16}$")
FINDING_RE = re.compile(r"^FIND-[0-9A-F]{16}$")

_META_LIMIT = 1_048_576
_LAYOUT = ("evidence", "notes", "actions", "findings", "osint")


def _utcnow() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def _stamp(moment: dt.datetime) -> str:
    if moment.tzinfo is None:
        raise ValueError("timestamps must be timezone-aware")
    return moment.astimezone(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def new_case_id(moment: dt.datetime | None = None) -> str:
    now = moment or _utcnow()
    return f"TOS-{now.strftime('%Y%m%d')}-{secrets.token_hex(4).upper()}"


def _new_id(prefix: str, nbytes: int) -> str:
    return f"{prefix}-{secrets.token_hex(nbytes).upper()}"


def _require_text(value: str, field: str, limit: int) -> str:
    if not isinstance(value, str) or not value or len(value) > limit or "\x00" in value:
        raise ValueError(f"invalid {field}")
    if any(ord(ch) < 32 for ch in value):
        raise ValueError(f"invalid {field}")
    return value


def _basename(name: str) -> str:
    base = name.rsplit("/", 1)[-1].rsplit("\\", 1)[-1]
    if base in ("", ".", "..") or "/" in base or "\\" in base or "\x00" in base:
        raise ValueError("invalid original name")
    if len(base) > 255:
        raise ValueError("invalid original name")
    return base


@dataclass(frozen=True)
class VerifyReport:
    ok: bool
    problems: tuple[str, ...]


class CaseStore:
    def __init__(self, root: str | os.PathLike[str], clock: Callable[[], dt.datetime] | None = None) -> None:
        self.root = os.path.abspath(os.fspath(root))
        self._fd = open_root(self.root)
        self._clock = clock or _utcnow

    def close(self) -> None:
        if self._fd is not None:
            os.close(self._fd)
            self._fd = None

    def __enter__(self) -> CaseStore:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def _root_fd(self) -> int:
        if self._fd is None:
            raise StorageError("store is closed")
        return self._fd

    def create_case(
        self,
        title: str,
        investigator: str,
        description: str = "",
        case_id: str | None = None,
    ) -> str:
        title = _require_text(title, "title", 200)
        investigator = _require_text(investigator, "investigator", 200)
        if description:
            description = _require_text(description, "description", 4000)
        case_id = case_id or new_case_id(self._clock())
        if not CASE_RE.match(case_id):
            raise ValueError("invalid case id")
        old = os.umask(0o077)
        try:
            case_fd = mkdir_exclusive(self._root_fd(), case_id)
            try:
                for name in _LAYOUT:
                    child = mkdir_exclusive(case_fd, name)
                    os.close(child)
                document = {
                    "schema": 1,
                    "case_id": case_id,
                    "title": title,
                    "investigator": investigator,
                    "description": description,
                    "created_at": _stamp(self._clock()),
                }
                write_bytes_exclusive(case_fd, "case.json", _dumps(document))
            finally:
                os.close(case_fd)
        finally:
            os.umask(old)
        return case_id

    def add_evidence_bytes(
        self,
        case_id: str,
        data: bytes,
        source_label: str,
        original_name: str,
        evidence_id: str | None = None,
        media_type: str = "application/octet-stream",
    ) -> str:
        if not isinstance(data, bytes):
            raise ValueError("evidence bytes required")
        return self._add_evidence(
            case_id,
            source_label,
            original_name,
            evidence_id,
            media_type,
            lambda dir_fd, name: _write_and_hash(dir_fd, name, data),
        )

    def add_evidence_file(
        self,
        case_id: str,
        source: str | os.PathLike[str],
        source_label: str,
        original_name: str | None = None,
        evidence_id: str | None = None,
        media_type: str = "application/octet-stream",
    ) -> str:
        source_path = os.fspath(source)
        try:
            st = os.lstat(source_path)
        except OSError as exc:
            raise UnsafePathError(f"cannot read source: {exc.strerror}") from exc
        if stat.S_ISLNK(st.st_mode):
            raise UnsafePathError("refusing to ingest a symlink")
        if not stat.S_ISREG(st.st_mode):
            raise UnsafePathError("evidence source must be a regular file")
        fd = os.open(source_path, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            st_fd = os.fstat(fd)
            if not stat.S_ISREG(st_fd.st_mode) or stat.S_ISLNK(st.st_mode):
                raise UnsafePathError("evidence source must be a regular file")
            name = original_name or os.path.basename(source_path)

            def writer(dir_fd: int, dest: str) -> tuple[str, int]:
                os.lseek(fd, 0, os.SEEK_SET)
                return copy_fd_exclusive(dir_fd, dest, fd)

            return self._add_evidence(case_id, source_label, name, evidence_id, media_type, writer)
        finally:
            os.close(fd)

    def _add_evidence(
        self,
        case_id: str,
        source_label: str,
        original_name: str,
        evidence_id: str | None,
        media_type: str,
        writer: Callable[[int, str], tuple[str, int]],
    ) -> str:
        source_label = _require_text(source_label, "source label", 200)
        original_name = _basename(original_name)
        media_type = _require_text(media_type, "media type", 100)
        evidence_id = evidence_id or _new_id("EV", 8)
        if not EVIDENCE_RE.match(evidence_id):
            raise ValueError("invalid evidence id")
        old = os.umask(0o077)
        try:
            case_fd = self._open_case(case_id)
            try:
                evidence_root = open_child_dir(case_fd, "evidence")
                try:
                    item_fd = mkdir_exclusive(evidence_root, evidence_id)
                    try:
                        sha256, size = writer(item_fd, "payload")
                        meta = {
                            "schema": 1,
                            "evidence_id": evidence_id,
                            "sha256": sha256,
                            "size": size,
                            "source_label": source_label,
                            "original_name": original_name,
                            "media_type": media_type,
                            "acquired_at": _stamp(self._clock()),
                        }
                        write_bytes_exclusive(item_fd, "meta.json", _dumps(meta))
                    finally:
                        os.close(item_fd)
                finally:
                    os.close(evidence_root)
            finally:
                os.close(case_fd)
        finally:
            os.umask(old)
        return evidence_id

    def add_note(self, case_id: str, body: str, author: str, note_id: str | None = None) -> str:
        body = _require_text(body, "note", 100_000)
        author = _require_text(author, "author", 200)
        note_id = note_id or _new_id("NOTE", 8)
        if not NOTE_RE.match(note_id):
            raise ValueError("invalid note id")
        document = {
            "schema": 1,
            "note_id": note_id,
            "author": author,
            "body": body,
            "created_at": _stamp(self._clock()),
        }
        self._write_record(case_id, "notes", f"{note_id}.json", document)
        return note_id

    def add_finding(
        self,
        case_id: str,
        title: str,
        detail: str,
        author: str,
        finding_id: str | None = None,
    ) -> str:
        title = _require_text(title, "title", 200)
        detail = _require_text(detail, "detail", 100_000)
        author = _require_text(author, "author", 200)
        finding_id = finding_id or _new_id("FIND", 8)
        if not FINDING_RE.match(finding_id):
            raise ValueError("invalid finding id")
        document = {
            "schema": 1,
            "finding_id": finding_id,
            "title": title,
            "detail": detail,
            "author": author,
            "created_at": _stamp(self._clock()),
        }
        self._write_record(case_id, "findings", f"{finding_id}.json", document)
        return finding_id

    def record_action(self, case_id: str, record: dict[str, Any], stdout: bytes, stderr: bytes) -> None:
        action_id = record.get("action_id")
        if not isinstance(action_id, str) or not ACTION_RE.match(action_id):
            raise ValueError("invalid action id")
        if not isinstance(stdout, bytes) or not isinstance(stderr, bytes):
            raise ValueError("action output must be bytes")
        encoded = _dumps(record)
        if record.get("stdout_sha256") is not None:
            _expect_hash(stdout, record["stdout_sha256"])
        if record.get("stderr_sha256") is not None:
            _expect_hash(stderr, record["stderr_sha256"])
        old = os.umask(0o077)
        try:
            case_fd = self._open_case(case_id)
            try:
                actions = open_child_dir(case_fd, "actions")
                try:
                    write_bytes_exclusive(actions, f"{action_id}.json", encoded)
                    if stdout:
                        write_bytes_exclusive(actions, f"{action_id}.stdout", stdout)
                    if stderr:
                        write_bytes_exclusive(actions, f"{action_id}.stderr", stderr)
                finally:
                    os.close(actions)
            finally:
                os.close(case_fd)
        finally:
            os.umask(old)

    def verify_evidence(self, case_id: str, evidence_id: str) -> VerifyReport:
        if not EVIDENCE_RE.match(evidence_id):
            raise ValueError("invalid evidence id")
        problems: list[str] = []
        case_fd = self._open_case(case_id)
        try:
            evidence_root = open_child_dir(case_fd, "evidence")
            try:
                item = open_child_dir(evidence_root, evidence_id)
                try:
                    meta_bytes = read_file_limited(item, "meta.json", _META_LIMIT)
                    try:
                        meta = json.loads(meta_bytes.decode("utf-8"))
                    except (UnicodeError, json.JSONDecodeError):
                        return VerifyReport(False, ("meta.json is not valid json",))
                    if not isinstance(meta, dict):
                        return VerifyReport(False, ("meta.json is not an object",))
                    payload_fd = open_file_nofollow(item, "payload")
                    try:
                        st = os.fstat(payload_fd)
                        if not stat.S_ISREG(st.st_mode):
                            problems.append("payload is not a regular file")
                        if st.st_mode & 0o077:
                            problems.append("payload is group or world accessible")
                        digest = hashlib.sha256()
                        size = 0
                        while True:
                            chunk = os.read(payload_fd, 1024 * 1024)
                            if not chunk:
                                break
                            size += len(chunk)
                            digest.update(chunk)
                        actual = digest.hexdigest()
                    finally:
                        os.close(payload_fd)
                    if meta.get("sha256") != actual:
                        problems.append("sha256 mismatch")
                    if meta.get("size") != size:
                        problems.append("size mismatch")
                    if meta.get("evidence_id") != evidence_id:
                        problems.append("evidence id mismatch")
                finally:
                    os.close(item)
            finally:
                os.close(evidence_root)
        finally:
            os.close(case_fd)
        return VerifyReport(not problems, tuple(problems))

    def list_evidence(self, case_id: str) -> list[dict[str, Any]]:
        return self._list_json_dirs(case_id, "evidence", "meta.json")

    def timeline(self, case_id: str) -> list[dict[str, Any]]:
        events: list[dict[str, Any]] = []
        case_fd = self._open_case(case_id)
        try:
            raw = read_file_limited(case_fd, "case.json", _META_LIMIT)
        finally:
            os.close(case_fd)
        case_doc = json.loads(raw.decode("utf-8"))
        events.append({"kind": "case", "at": case_doc["created_at"], "id": case_doc["case_id"]})
        for meta in self.list_evidence(case_id):
            events.append({"kind": "evidence", "at": meta["acquired_at"], "id": meta["evidence_id"]})
        for note in self._list_named(case_id, "notes"):
            events.append({"kind": "note", "at": note["created_at"], "id": note["note_id"]})
        for finding in self._list_named(case_id, "findings"):
            events.append({"kind": "finding", "at": finding["created_at"], "id": finding["finding_id"]})
        for action in self._list_named(case_id, "actions"):
            if "action_id" not in action:
                continue
            events.append(
                {
                    "kind": "action",
                    "at": action.get("started_at") or action.get("ended_at"),
                    "id": action["action_id"],
                    "executed": action.get("executed"),
                    "tool": action.get("tool"),
                }
            )
        for program in self.list_records(case_id, "osint"):
            if "program_id" not in program:
                continue
            events.append(
                {
                    "kind": "osint-program",
                    "at": program.get("created_at"),
                    "id": program["program_id"],
                }
            )
        events.sort(key=lambda item: (item["at"] or "", item["id"]))
        return events

    def write_record(self, case_id: str, folder: str, name: str, document: dict[str, Any]) -> None:
        if folder not in _LAYOUT:
            raise UnsafePathError("refusing record outside the case layout")
        if not isinstance(name, str) or not name.endswith(".json") or "/" in name or "\\" in name:
            raise ValueError("invalid record name")
        self._write_record(case_id, folder, name, document)

    def list_records(self, case_id: str, folder: str) -> list[dict[str, Any]]:
        if folder not in _LAYOUT:
            raise UnsafePathError("refusing record outside the case layout")
        return self._list_named(case_id, folder)

    def _write_record(self, case_id: str, folder: str, name: str, document: dict[str, Any]) -> None:
        old = os.umask(0o077)
        try:
            case_fd = self._open_case(case_id)
            try:
                folder_fd = open_child_dir(case_fd, folder)
                try:
                    write_bytes_exclusive(folder_fd, name, _dumps(document))
                finally:
                    os.close(folder_fd)
            finally:
                os.close(case_fd)
        finally:
            os.umask(old)

    def _open_case(self, case_id: str) -> int:
        if not CASE_RE.match(case_id):
            raise ValueError("invalid case id")
        return open_child_dir(self._root_fd(), case_id)

    def _list_named(self, case_id: str, folder: str) -> list[dict[str, Any]]:
        case_fd = self._open_case(case_id)
        try:
            folder_fd = open_child_dir(case_fd, folder)
            try:
                names = sorted(os.listdir(folder_fd))
                documents = []
                for name in names:
                    if not name.endswith(".json"):
                        continue
                    raw = read_file_limited(folder_fd, name, _META_LIMIT)
                    documents.append(json.loads(raw.decode("utf-8")))
                return documents
            finally:
                os.close(folder_fd)
        finally:
            os.close(case_fd)

    def _list_json_dirs(self, case_id: str, folder: str, filename: str) -> list[dict[str, Any]]:
        case_fd = self._open_case(case_id)
        try:
            folder_fd = open_child_dir(case_fd, folder)
            try:
                documents = []
                for name in sorted(os.listdir(folder_fd)):
                    if not EVIDENCE_RE.match(name):
                        continue
                    item = open_child_dir(folder_fd, name)
                    try:
                        raw = read_file_limited(item, filename, _META_LIMIT)
                    finally:
                        os.close(item)
                    documents.append(json.loads(raw.decode("utf-8")))
                return documents
            finally:
                os.close(folder_fd)
        finally:
            os.close(case_fd)


def _dumps(document: dict[str, Any]) -> bytes:
    return (json.dumps(document, indent=2, sort_keys=True) + "\n").encode("utf-8")


def _write_and_hash(dir_fd: int, name: str, data: bytes) -> tuple[str, int]:
    write_bytes_exclusive(dir_fd, name, data)
    return hashlib.sha256(data).hexdigest(), len(data)


def _expect_hash(data: bytes, expected: object) -> None:
    if not isinstance(expected, str):
        raise ValueError("invalid output hash")
    actual = hashlib.sha256(data).hexdigest()
    if actual != expected:
        raise ValueError("action output hash does not match the record")
