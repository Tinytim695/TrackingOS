"""Report whether this machine can build a TrackingOS image.

Finding the helper binaries is not an ISO build. Callers must not treat a
ready report as evidence that an image was produced or that it boots.
"""

from __future__ import annotations

import shutil
from typing import Callable

REQUIRED_COMMANDS = ("debootstrap", "mksquashfs", "xorriso", "qemu-system-x86_64")


def assess_build_host(which: Callable[[str], str | None] | None = None) -> dict[str, object]:
    finder = which or shutil.which
    commands = {name: finder(name) for name in REQUIRED_COMMANDS}
    ready = all(commands.values())
    return {
        "commands": commands,
        "iso_build_ready": ready,
        "iso_built": False,
        "note": "iso_build_ready only means helper binaries were found. No image was built.",
    }
