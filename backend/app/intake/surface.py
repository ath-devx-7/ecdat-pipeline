"""Surface scan — enumerate every file, parse nothing (SPEC.md §4 step 3).

This is what the user is shown before granting permission, so it must stay
cheap and content-blind: path and size only, taken from the directory entry.
Not one byte of any file is read here.

The file cap from §2 is enforced during the walk rather than after it, so a
mistakenly pointed-at home directory is rejected in milliseconds instead of
after enumerating a million entries.
"""

from __future__ import annotations

import os
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

__all__ = ["FileCapExceeded", "SurfaceFile", "walk_surface"]


class FileCapExceeded(RuntimeError):
    """The tree holds more files than the synchronous-scan cap allows (§2)."""


@dataclass(frozen=True, slots=True)
class SurfaceFile:
    """One row-to-be in ``scan_files``."""

    #: POSIX-style, relative to the work directory — the key the user approves
    #: and every later collector resolves against.
    path: str
    size_bytes: int | None


def walk_surface(
    work_dir: Path,
    *,
    max_files: int,
    exclude_dirs: Iterable[str] = (),
) -> list[SurfaceFile]:
    """List every regular file under ``work_dir``.

    Symlinks are neither recorded as files nor descended into: following one
    would take the scan outside the tree the user approved, and a link target
    that is inside the tree gets enumerated on its own anyway.

    Raises :class:`FileCapExceeded` as soon as the count passes ``max_files``.
    """
    root = Path(work_dir).resolve()
    if not root.is_dir():
        raise NotADirectoryError(f"Work directory does not exist: {root}")

    pruned = set(exclude_dirs)
    found: list[SurfaceFile] = []

    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        # Sorted in place so both the walk order and the resulting tree are
        # deterministic; the frontend renders these without re-sorting.
        dirnames[:] = sorted(
            name
            for name in dirnames
            if name not in pruned and not os.path.islink(os.path.join(dirpath, name))
        )
        here = Path(dirpath)
        for name in sorted(filenames):
            absolute = here / name
            if absolute.is_symlink():
                continue
            try:
                size = absolute.stat().st_size
            except OSError:
                # Unreadable entry: still offer it for approval, size unknown.
                size = None
            found.append(
                SurfaceFile(path=absolute.relative_to(root).as_posix(), size_bytes=size)
            )
            if len(found) > max_files:
                raise FileCapExceeded(
                    f"Source exceeds the file cap of {max_files} files. Scans run "
                    "synchronously in this prototype, so the cap is a hard guard. "
                    "Point the scan at a narrower directory, or raise "
                    "ECDAT_MAX_FILES_PER_SCAN if this host can afford the run."
                )

    return found
