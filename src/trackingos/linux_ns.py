"""Linux network-namespace helper. Fail closed if isolation is unavailable."""

from __future__ import annotations

import ctypes
import ctypes.util
import os

CLONE_NEWNET = 0x40000000


def unshare_network() -> None:
    """Place the calling process in a new network namespace with no interfaces.

    The new namespace has no routable network. Loopback is down. This is a
    kernel control, not a policy flag. Caller must already be in the child
    that will exec the tool.
    """
    libc_path = ctypes.util.find_library("c")
    if not libc_path:
        raise OSError("libc not found; refusing to run without network isolation")
    libc = ctypes.CDLL(libc_path, use_errno=True)
    libc.unshare.argtypes = [ctypes.c_int]
    libc.unshare.restype = ctypes.c_int
    if libc.unshare(CLONE_NEWNET) != 0:
        err = ctypes.get_errno()
        raise OSError(err, os.strerror(err), "unshare(CLONE_NEWNET)")
