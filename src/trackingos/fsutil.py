"""Directory operations that refuse symlinks and silent overwrites."""

from __future__ import annotations

import errno
import os
import stat
from collections.abc import Callable


class StorageError(Exception):
    """Base error for case storage."""


class CollisionError(StorageError):
    """A case object with this id already exists. Nothing was overwritten."""


class UnsafePathError(StorageError):
    """The path is a symlink, escapes the store, or has unsafe permissions."""


_COMPONENT = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._-")


def safe_component(name: str) -> bool:
    if not name or name in (".", "..") or len(name) > 80:
        return False
    return all(ch in _COMPONENT for ch in name)


def open_root(path: str) -> int:
    if not os.path.isabs(path):
        raise UnsafePathError("store root must be absolute")
    try:
        st = os.lstat(path)
    except OSError as exc:
        raise UnsafePathError(f"store root unavailable: {exc.strerror}") from exc
    if stat.S_ISLNK(st.st_mode):
        raise UnsafePathError("store root must not be a symlink")
    if not stat.S_ISDIR(st.st_mode):
        raise UnsafePathError("store root must be a directory")
    if st.st_mode & 0o002:
        raise UnsafePathError("store root must not be world-writable")
    try:
        return os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    except OSError as exc:
        raise UnsafePathError(f"cannot open store root: {exc.strerror}") from exc


def open_child_dir(parent_fd: int, name: str) -> int:
    if not safe_component(name):
        raise UnsafePathError("refusing unsafe directory name")
    try:
        fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent_fd)
    except OSError as exc:
        if exc.errno in (errno.ELOOP, errno.ENOTDIR):
            raise UnsafePathError("refusing symlink or non-directory in case layout") from exc
        raise UnsafePathError(f"case layout damaged: {name}") from exc
    os.fchmod(fd, 0o700)
    return fd


def mkdir_exclusive(parent_fd: int, name: str) -> int:
    if not safe_component(name):
        raise UnsafePathError("refusing unsafe directory name")
    try:
        os.mkdir(name, 0o700, dir_fd=parent_fd)
    except FileExistsError as exc:
        raise CollisionError(name) from exc
    fd = open_child_dir(parent_fd, name)
    return fd


def _fsync_dir(dir_fd: int) -> None:
    os.fsync(dir_fd)


def write_bytes_exclusive(dir_fd: int, name: str, data: bytes, mode: int = 0o600) -> None:
    """Create ``name`` exactly once. Never replaces an existing inode."""
    if not safe_component(name) and not _tmp_ok(name):
        raise UnsafePathError("refusing unsafe file name")
    tmp = f".tmp-{os.getpid()}-{os.urandom(8).hex()}"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
    fd = os.open(tmp, flags, mode, dir_fd=dir_fd)
    try:
        view = memoryview(data)
        while view:
            written = os.write(fd, view)
            if written <= 0:
                raise StorageError("short write")
            view = view[written:]
        os.fchmod(fd, mode)
        os.fsync(fd)
    except Exception:
        os.close(fd)
        _unlink_quiet(dir_fd, tmp)
        raise
    os.close(fd)
    try:
        os.link(tmp, name, src_dir_fd=dir_fd, dst_dir_fd=dir_fd, follow_symlinks=False)
    except FileExistsError as exc:
        _unlink_quiet(dir_fd, tmp)
        raise CollisionError(name) from exc
    except OSError as exc:
        _unlink_quiet(dir_fd, tmp)
        if exc.errno in (errno.EEXIST, errno.ELOOP):
            raise CollisionError(name) from exc
        raise
    _unlink_quiet(dir_fd, tmp)
    _fsync_dir(dir_fd)


def copy_fd_exclusive(dir_fd: int, name: str, src_fd: int, mode: int = 0o600) -> tuple[str, int]:
    """Stream ``src_fd`` into a new file. Returns ``(sha256, size)``."""
    import hashlib

    if not safe_component(name):
        raise UnsafePathError("refusing unsafe file name")
    tmp = f".tmp-{os.getpid()}-{os.urandom(8).hex()}"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
    fd = os.open(tmp, flags, mode, dir_fd=dir_fd)
    digest = hashlib.sha256()
    size = 0
    try:
        while True:
            chunk = os.read(src_fd, 1024 * 1024)
            if not chunk:
                break
            size += len(chunk)
            digest.update(chunk)
            view = memoryview(chunk)
            while view:
                written = os.write(fd, view)
                if written <= 0:
                    raise StorageError("short write")
                view = view[written:]
        os.fchmod(fd, mode)
        os.fsync(fd)
    except Exception:
        os.close(fd)
        _unlink_quiet(dir_fd, tmp)
        raise
    os.close(fd)
    try:
        os.link(tmp, name, src_dir_fd=dir_fd, dst_dir_fd=dir_fd, follow_symlinks=False)
    except FileExistsError as exc:
        _unlink_quiet(dir_fd, tmp)
        raise CollisionError(name) from exc
    except OSError as exc:
        _unlink_quiet(dir_fd, tmp)
        if exc.errno in (errno.EEXIST, errno.ELOOP):
            raise CollisionError(name) from exc
        raise
    _unlink_quiet(dir_fd, tmp)
    _fsync_dir(dir_fd)
    return digest.hexdigest(), size


def open_file_nofollow(dir_fd: int, name: str) -> int:
    if not safe_component(name):
        raise UnsafePathError("refusing unsafe file name")
    try:
        return os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=dir_fd)
    except OSError as exc:
        if exc.errno in (errno.ELOOP, errno.ENOTDIR):
            raise UnsafePathError("refusing symlink evidence file") from exc
        raise


def read_file_limited(dir_fd: int, name: str, limit: int) -> bytes:
    fd = open_file_nofollow(dir_fd, name)
    try:
        data = os.read(fd, limit + 1)
    finally:
        os.close(fd)
    if len(data) > limit:
        raise StorageError("metadata file exceeds size limit")
    return data


def with_umask(mask: int, fn: Callable[[], None]) -> None:
    old = os.umask(mask)
    try:
        fn()
    finally:
        os.umask(old)


def _tmp_ok(name: str) -> bool:
    return name.startswith(".tmp-") and safe_component(name[1:]) is False and "/" not in name


def _unlink_quiet(dir_fd: int, name: str) -> None:
    try:
        os.unlink(name, dir_fd=dir_fd)
    except FileNotFoundError:
        pass
