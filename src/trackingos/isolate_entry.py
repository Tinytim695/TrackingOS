"""Child entry used by the executor. Not a user-facing tool.

The parent invokes this file with an absolute path and a scrubbed environment.
It must not import the rest of the package: the child PATH cannot see a
source checkout, and inheriting PYTHONPATH would copy the parent environment.
"""

from __future__ import annotations

import os
import sys

# Duplicated on purpose so this process has no package import.
_CLONE_NEWNET = 0x40000000


def _unshare_network() -> None:
    import ctypes
    import ctypes.util

    libc_path = ctypes.util.find_library("c")
    if not libc_path:
        raise OSError("libc not found")
    libc = ctypes.CDLL(libc_path, use_errno=True)
    libc.unshare.argtypes = [ctypes.c_int]
    libc.unshare.restype = ctypes.c_int
    if libc.unshare(_CLONE_NEWNET) != 0:
        err = ctypes.get_errno()
        raise OSError(err, os.strerror(err))


def main() -> None:
    if len(sys.argv) < 5:
        os._exit(2)
    mode, status_s, exec_s, toolname = sys.argv[1:5]
    tool_args = sys.argv[5:]
    try:
        status_fd = int(status_s)
        exec_fd = int(exec_s)
    except ValueError:
        os._exit(2)
    if mode == "netoff":
        try:
            _unshare_network()
        except OSError:
            os.write(status_fd, b"I")
            os._exit(111)
    elif mode != "open":
        os.write(status_fd, b"I")
        os._exit(2)
    os.write(status_fd, b"R")
    # Do not let the tool inherit the status pipe.
    os.set_inheritable(status_fd, False)
    try:
        os.execv(f"/proc/self/fd/{exec_fd}", [toolname, *tool_args])
    except OSError:
        os._exit(127)


if __name__ == "__main__":
    main()
