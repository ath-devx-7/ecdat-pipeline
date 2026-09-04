"""Browser folder upload — bytes in, a directory on disk (SPEC.md §4 step 2).

The ``folder`` source type needs the tree to already be on the machine running
the backend. This one does not: the browser reads a directory the user picked
and posts every file, and this module lays them back out as the same tree under
``work_root/uploads/{upload_id}``. From there staging returns it like any other
source and nothing downstream can tell the difference.

Two things make this the only intake path that takes an attacker-shaped input on
the file side:

* **The manifest is client-supplied.** One relative path per part, in the same
  order, because the multipart body carries only leaf filenames. Nothing about
  it is trusted: a path that is absolute, that contains ``..`` or a NUL, or that
  resolves outside the upload root is refused and the whole upload is dropped.
* **The bytes are ours now.** Unlike a folder we read in place, these were
  copied, so we own them and may delete them — which is what makes the staged
  source ``ephemeral``. :func:`sweep_uploads` makes that true for uploads nobody
  ever turned into a scan.

Storing is not reading. Every byte here goes from the request to a file and is
never parsed; the collectors still open nothing until the paths are approved
(§4 step 5).
"""

from __future__ import annotations

import logging
import shutil
import time
import uuid
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO, Protocol, Sequence

from app.config import Settings, get_settings

logger = logging.getLogger(__name__)

__all__ = ["StoredUpload", "UploadError", "UploadPart", "store_upload", "sweep_uploads", "uploads_root"]

#: Bytes moved per read. Large enough that a big file is not a million calls,
#: small enough that the cap is enforced long before the disk fills.
_CHUNK_BYTES = 1024 * 1024


class UploadError(ValueError):
    """The upload could not be stored. Shown to the user verbatim, as a 400."""


class UploadPart(Protocol):
    """What :func:`store_upload` needs from one multipart part.

    Starlette's ``UploadFile`` satisfies this. It is spelled as a protocol so the
    storage rules can be tested without building a request.
    """

    #: The part's bytes, as a synchronous stream positioned at the start.
    file: BinaryIO


@dataclass(frozen=True, slots=True)
class StoredUpload:
    """A tree on disk, waiting for a scan to name it."""

    upload_id: uuid.UUID
    root: Path
    file_count: int
    total_bytes: int


def uploads_root(settings: Settings | None = None) -> Path:
    """The parent of every upload tree. One directory, so the sweep has one place to look."""
    settings = settings or get_settings()
    return (Path(settings.work_root) / "uploads").resolve()


# --------------------------------------------------------------------------- #
# Storing
# --------------------------------------------------------------------------- #


def store_upload(
    files: Sequence[UploadPart],
    paths: Sequence[str],
    settings: Settings | None = None,
) -> StoredUpload:
    """Write ``files`` under a fresh upload directory using ``paths`` as the tree.

    Blocking: it copies every part to disk, so callers on the event loop run it
    in a threadpool. Raises :class:`UploadError`, having left nothing behind.
    """
    settings = settings or get_settings()

    if len(files) != len(paths):
        raise UploadError(
            f"The upload carries {len(files)} file part(s) but the paths manifest lists "
            f"{len(paths)}. Each part needs exactly one relative path, in the same order."
        )
    if not files:
        raise UploadError("The upload contains no files.")
    if len(files) > settings.max_files_per_scan:
        raise UploadError(
            f"The upload holds {len(files)} files, which exceeds the per-scan cap of "
            f"{settings.max_files_per_scan}. Scans run synchronously in this prototype, so "
            "the cap is a hard guard. Upload a narrower directory, or raise "
            "ECDAT_MAX_FILES_PER_SCAN if this host can afford the run."
        )

    relative_paths = _plan_tree(paths)

    upload_id = uuid.uuid4()
    root = uploads_root(settings) / str(upload_id)
    root.mkdir(parents=True, exist_ok=False)

    total = 0
    try:
        for part, relative in zip(files, relative_paths):
            destination = _resolve_within(root, relative)
            destination.parent.mkdir(parents=True, exist_ok=True)
            total += _copy_part(
                part,
                destination,
                budget=settings.max_upload_bytes - total,
                cap=settings.max_upload_bytes,
            )
    except BaseException:
        # A half-written tree is not a smaller upload, it is a wrong one: the
        # user would approve a file list missing whatever came after the failure.
        shutil.rmtree(root, ignore_errors=True)
        raise

    logger.info(
        "upload %s stored %d file(s), %d byte(s) under %s", upload_id, len(files), total, root
    )
    return StoredUpload(upload_id=upload_id, root=root, file_count=len(files), total_bytes=total)


def _plan_tree(paths: Sequence[str]) -> list[str]:
    """Validate the manifest and drop the leading directory the picker added.

    ``webkitRelativePath`` prefixes every entry with the name of the folder the
    user picked, so an upload of ``demo/`` arrives as ``demo/nginx/nginx.conf``.
    That segment is stripped when every path shares it, which makes the stored
    tree — and therefore the approval list and every ``evidence_location`` built
    from it — identical to a ``folder`` scan of the same directory.
    """
    cleaned = [_clean_path(raw, index) for index, raw in enumerate(paths)]

    leading = {parts[0] for parts in cleaned}
    if len(leading) == 1 and all(len(parts) > 1 for parts in cleaned):
        cleaned = [parts[1:] for parts in cleaned]

    joined = ["/".join(parts) for parts in cleaned]
    duplicates = [path for path, count in Counter(joined).items() if count > 1]
    if duplicates:
        raise UploadError(
            "The paths manifest lists the same file twice: "
            f"{', '.join(sorted(duplicates)[:3])}. One part, one path."
        )
    return joined


def _clean_path(raw: str, index: int) -> list[str]:
    """One manifest entry to its segments, or :class:`UploadError`.

    Refused rather than sanitised. A path we had to repair is a path the client
    did not mean, and quietly storing our own guess of it under a name the user
    never saw would put a file in the approval tree that is not the file they
    picked.
    """
    where = f"entry {index} of the paths manifest"
    if not isinstance(raw, str):
        raise UploadError(f"{where.capitalize()} is not a string.")
    if "\x00" in raw:
        raise UploadError(f"{where.capitalize()} contains a NUL byte.")

    # Windows clients may send backslashes; both are separators here, so a
    # `..\..` cannot slip past a check that only knew about `/`.
    candidate = raw.replace("\\", "/").strip()
    if not candidate:
        raise UploadError(f"{where.capitalize()} is empty.")
    if candidate.startswith("/") or (len(candidate) > 1 and candidate[1] == ":"):
        raise UploadError(
            f"{where.capitalize()} is an absolute path ({raw!r}). Uploaded paths are "
            "relative to the folder that was picked."
        )

    parts = [segment for segment in candidate.split("/") if segment not in ("", ".")]
    if any(segment == ".." for segment in parts):
        raise UploadError(
            f"{where.capitalize()} escapes the upload directory ({raw!r})."
        )
    if not parts:
        raise UploadError(f"{where.capitalize()} names no file ({raw!r}).")
    return parts


def _resolve_within(root: Path, relative: str) -> Path:
    """Join and then prove it landed inside ``root``.

    The segment checks above should make this unreachable. It runs anyway: the
    guarantee this module owes the rest of the system is about where bytes end
    up, and that is a property of the resolved path, not of the parsing that
    produced it.
    """
    destination = root.joinpath(relative)
    resolved = Path(destination).resolve()
    if resolved != root and root not in resolved.parents:
        raise UploadError(f"Upload path escapes the upload directory: {relative!r}")
    return resolved


def _copy_part(part: UploadPart, destination: Path, *, budget: int, cap: int) -> int:
    """Stream one part to disk, stopping the moment it would pass the byte cap.

    Enforced chunk by chunk rather than from a declared ``Content-Length``: the
    part's own header is as client-supplied as the manifest is, so the number
    that stops the write has to be the number of bytes actually written.
    """
    written = 0
    source = part.file
    source.seek(0)
    with open(destination, "wb") as handle:
        while True:
            chunk = source.read(_CHUNK_BYTES)
            if not chunk:
                break
            written += len(chunk)
            if written > budget:
                raise UploadError(
                    f"The upload exceeds the total size cap of {_megabytes(cap)}. Bytes are "
                    "copied onto this host before anything is read from them, so the cap is "
                    "a hard guard. Upload a narrower directory, or raise "
                    "ECDAT_MAX_UPLOAD_BYTES if this host can afford the space."
                )
            handle.write(chunk)
    return written


def _megabytes(value: int) -> str:
    return f"{value / (1024 * 1024):.1f} MB"


# --------------------------------------------------------------------------- #
# Sweeping
# --------------------------------------------------------------------------- #


def sweep_uploads(settings: Settings | None = None) -> int:
    """Delete upload trees older than the retention window. Returns the count.

    An upload that was never turned into a scan has no row anywhere pointing at
    it, so nothing else would ever remove it. Called at startup rather than on a
    timer: this is a synchronous prototype with no scheduler, and a sweep that
    runs whenever the process restarts is enough to keep abandoned trees from
    accumulating for ever.
    """
    settings = settings or get_settings()
    root = uploads_root(settings)
    if not root.is_dir():
        return 0

    cutoff = time.time() - settings.upload_retention_hours * 3600
    removed = 0
    for child in root.iterdir():
        if not child.is_dir():
            continue
        try:
            if child.stat().st_mtime >= cutoff:
                continue
        except OSError:
            continue
        shutil.rmtree(child, ignore_errors=True)
        removed += 1
    if removed:
        logger.info(
            "swept %d upload tree(s) older than %dh from %s",
            removed,
            settings.upload_retention_hours,
            root,
        )
    return removed
