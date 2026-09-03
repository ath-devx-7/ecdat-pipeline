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
from collections import Counter
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

__all__ = ["ATTRIBUTION_CEILING", "FileCapExceeded", "SurfaceFile", "walk_surface"]

#: When the cap is hit, the walk continues counting — not recording — up to this
#: many files so the error can say *where* they are. A committed `node_modules`
#: is the usual answer, and "exceeds 5000" without the directory name sends the
#: user hunting for it.
ATTRIBUTION_CEILING = 250_000


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
    #: files per directory prefix (top level, and one level below it), kept for
    #: the error message and nothing else
    per_prefix: Counter[str] = Counter()
    total = 0

    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        # Sorted in place so both the walk order and the resulting tree are
        # deterministic; the frontend renders these without re-sorting.
        dirnames[:] = sorted(
            name
            for name in dirnames
            if name not in pruned and not os.path.islink(os.path.join(dirpath, name))
        )
        here = Path(dirpath)
        relative_dir = here.relative_to(root).as_posix()
        for name in sorted(filenames):
            absolute = here / name
            if absolute.is_symlink():
                continue
            total += 1
            for prefix in _prefixes(relative_dir):
                per_prefix[prefix] += 1
            if total > max_files:
                # Past the cap: stop recording, keep counting so the message can
                # name the directory responsible, and stop counting at a ceiling
                # so a mistakenly pointed-at drive still fails quickly.
                if total >= ATTRIBUTION_CEILING:
                    break
                continue
            try:
                size = absolute.stat().st_size
            except OSError:
                # Unreadable entry: still offer it for approval, size unknown.
                size = None
            found.append(
                SurfaceFile(path=absolute.relative_to(root).as_posix(), size_bytes=size)
            )
        if total >= ATTRIBUTION_CEILING:
            break

    if total > max_files:
        raise FileCapExceeded(_cap_message(max_files, total, per_prefix, pruned))
    return found


def _prefixes(relative_dir: str) -> tuple[str, ...]:
    """``"a/b/c"`` → ``("a", "a/b")``; a file at the root → ``("(root)",)``."""
    if not relative_dir or relative_dir == ".":
        return ("(root)",)
    parts = relative_dir.split("/")
    return (parts[0], "/".join(parts[:2])) if len(parts) > 1 else (parts[0],)


def _cap_message(max_files: int, total: int, per_prefix: Counter[str], pruned: set[str]) -> str:
    """Name the cap, the count, and the directories carrying it."""
    # Only prefixes that carry a real share of the count: a six-file `src`
    # beside a forty-thousand-file `node_modules` is not part of the answer.
    heaviest = [
        f"{prefix} ({count} files)"
        for prefix, count in per_prefix.most_common(6)
        if count >= total * 0.05
    ][:3]
    reached = "at least " if total >= ATTRIBUTION_CEILING else ""
    where = f" The largest directories: {', '.join(heaviest)}." if heaviest else ""
    excluded = ", ".join(sorted(pruned)) or "none"
    return (
        f"Source exceeds the file cap of {max_files} files ({reached}{total} found).{where} "
        "Scans run synchronously in this prototype, so the cap is a hard guard. Point the "
        "scan at a narrower directory, exclude directories with ECDAT_SURFACE_EXCLUDE_DIRS "
        f"(currently: {excluded}; a JSON list such as '[\".git\", \"node_modules\"]'), or raise "
        "ECDAT_MAX_FILES_PER_SCAN if this host can afford the run."
    )
