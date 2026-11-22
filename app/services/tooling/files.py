"""Safe, bounded reads of files listed in a validated repository inventory.

Shared by every tool that opens repository files. A read never follows a
symbolic link, never leaves the repository root, accepts only regular files, and
never returns more than ``max_bytes``. Failures are reported as reason codes, not
exceptions, so tools can account for every file they did not read.
"""

from __future__ import annotations

import os
import stat
from pathlib import Path, PurePosixPath


def read_bounded(root: Path, relative_path: str, max_bytes: int) -> tuple[bytes | None, str]:
    """Read a regular file inside ``root`` without following symlinks."""
    relative = PurePosixPath(relative_path)
    if relative.is_absolute() or ".." in relative.parts:
        return None, "outside_root"
    candidate = root.joinpath(*relative.parts)
    try:
        info = candidate.lstat()
    except FileNotFoundError:
        return None, "disappeared"
    except OSError:
        return None, "unreadable"
    if stat.S_ISLNK(info.st_mode):
        return None, "symlink"
    if not stat.S_ISREG(info.st_mode):
        return None, "not_regular"
    if info.st_size > max_bytes:
        return None, "oversize"
    try:
        if not candidate.resolve(strict=True).is_relative_to(root):
            return None, "outside_root"
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
        descriptor = os.open(candidate, flags)
    except FileNotFoundError:
        return None, "disappeared"
    except OSError:
        return None, "unreadable"
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode):
            return None, "not_regular"
        with os.fdopen(descriptor, "rb", closefd=True) as handle:
            descriptor = -1
            data = handle.read(max_bytes + 1)
    except OSError:
        return None, "unreadable"
    finally:
        if descriptor != -1:
            os.close(descriptor)
    if len(data) > max_bytes:
        return None, "oversize"
    return data, "ok"


__all__ = ["read_bounded"]
