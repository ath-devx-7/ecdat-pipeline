"""Selection gate — the user's explicit permission (SPEC.md §4 step 5).

The one place ``scan_files.approved`` is written. Everything downstream reads
approval from here and from nowhere else, which is what makes "an unapproved
file path is never opened by any collector" (§16) a property of the system
rather than a promise each collector has to keep.

Approval is set to *exactly* the submitted list: a second submission that omits
a path revokes it. Silently keeping an earlier approval would mean the file list
shown in the UI no longer matches what gets read.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from uuid import UUID

import sqlalchemy as sa
from sqlalchemy.orm import Session

from app.models.scan import ScanFile

__all__ = [
    "SelectionError",
    "approve_paths",
    "approved_paths",
    "normalise_path",
    "set_file_lifetimes",
]

#: How many unknown paths an error message names before it stops listing them.
_MAX_REPORTED_UNKNOWN = 10


class SelectionError(RuntimeError):
    """The submitted approval list does not match the scan's file list."""


def normalise_path(path: str) -> str:
    """Match the form the surface scan stored: POSIX, relative, no ``./`` prefix."""
    cleaned = path.strip().replace("\\", "/").lstrip("/")
    while cleaned.startswith("./"):
        cleaned = cleaned[2:]
    return cleaned


def approve_paths(session: Session, scan_id: UUID, paths: Iterable[str]) -> int:
    """Set ``approved`` on exactly ``paths``. Returns the approved count.

    Raises :class:`SelectionError` naming any path that is not in this scan's
    file list. Ignoring an unknown path would leave the user believing something
    is in scope that never gets read.
    """
    requested = {normalise_path(path) for path in paths}
    requested.discard("")

    rows = session.scalars(sa.select(ScanFile).where(ScanFile.scan_id == scan_id)).all()
    known = {row.path for row in rows}

    unknown = sorted(requested - known)
    if unknown:
        shown = ", ".join(unknown[:_MAX_REPORTED_UNKNOWN])
        suffix = "" if len(unknown) <= _MAX_REPORTED_UNKNOWN else f" (+{len(unknown) - _MAX_REPORTED_UNKNOWN} more)"
        raise SelectionError(
            f"{len(unknown)} approved path(s) are not in this scan's file list: "
            f"{shown}{suffix}. Paths must be exactly as returned by "
            "GET /api/scans/{id}/files."
        )

    for row in rows:
        row.approved = row.path in requested
    session.flush()
    return len(requested)


def set_file_lifetimes(
    session: Session, scan_id: UUID, lifetimes: Mapping[str, int]
) -> int:
    """Set each named file's own X, and clear it on every file not named.

    Set to *exactly* the submitted map, for the same reason approval is: a
    lifetime the user removed on the screen must not survive in the row, or the
    scan would be scored against a number that is no longer on any screen.

    Raises :class:`SelectionError` naming paths that are not in this scan's file
    list — an override on a file that does not exist would silently do nothing,
    and the user would read the resulting wave as a judgement about their data.
    """
    requested = {normalise_path(path): years for path, years in lifetimes.items()}
    requested.pop("", None)

    rows = session.scalars(sa.select(ScanFile).where(ScanFile.scan_id == scan_id)).all()
    known = {row.path for row in rows}

    unknown = sorted(set(requested) - known)
    if unknown:
        shown = ", ".join(unknown[:_MAX_REPORTED_UNKNOWN])
        suffix = "" if len(unknown) <= _MAX_REPORTED_UNKNOWN else f" (+{len(unknown) - _MAX_REPORTED_UNKNOWN} more)"
        raise SelectionError(
            f"{len(unknown)} data-lifetime path(s) are not in this scan's file list: "
            f"{shown}{suffix}. Paths must be exactly as returned by "
            "GET /api/scans/{id}/files."
        )

    for row in rows:
        row.data_lifetime_years = requested.get(row.path)
    session.flush()
    return len(requested)


def approved_paths(session: Session, scan_id: UUID) -> list[str]:
    """The approved path list, for the collectors. The only source of scope."""
    return list(
        session.scalars(
            sa.select(ScanFile.path)
            .where(ScanFile.scan_id == scan_id, ScanFile.approved.is_(True))
            .order_by(ScanFile.path)
        ).all()
    )
