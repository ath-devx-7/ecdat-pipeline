"""The collector interface — SPEC.md §7.

Every collector is a pure observer. It reports what it *sees*, in the wording the
artefact used, and never decides whether that is good or bad: verdicts come from
the policy engine (§10) and canonical algorithm identities from the normalizer
(§8). Two consequences run through this module:

* A collector sets ``algorithm_name`` as observed and ``algorithm_oid`` only when
  the artefact literally carries an OID. ``algorithm_family`` is left unset —
  collapsing ``SHA-1``, ``sha1`` and ``1.3.14.3.2.26`` onto one identity is the
  normalizer's job, and doing it twice in two places is how the two answers start
  to disagree.
* ``primitive`` is set only where the observation itself carries it: an SSH
  ``KexAlgorithms`` line is key exchange because that is what the directive
  means. Where the artefact does not say, it stays ``unknown``.

Two properties are enforced here rather than trusted to each collector:

**Scope.** :meth:`ScanContext.iter_files` is the only way a collector reaches the
filesystem, and it yields approved paths only, resolved inside the work
directory. "An unapproved file is never opened" is then a property of this
module, not a promise five collectors each have to keep.

**Survivability.** A collector that raises returns an empty list and marks the
scan ``partial``. It never kills the run — see ``app/runner.py``.
"""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from collections.abc import Iterator, Mapping, Sequence
from dataclasses import dataclass, field, replace
from pathlib import Path
from time import monotonic
from typing import Any, ClassVar
from uuid import UUID

from app.models.enums import CollectorName, Confidence, Primitive, SourceLayer

logger = logging.getLogger(__name__)

__all__ = [
    "Collector",
    "CollectorTimeout",
    "RawFinding",
    "ScanContext",
]


class CollectorTimeout(RuntimeError):
    """A collector ran past its per-collector budget (§2) and stopped itself."""


@dataclass(frozen=True, slots=True)
class RawFinding:
    """One observation, before normalization.

    Maps onto a ``findings`` row in step 5. The fields the normalizer owns —
    ``algorithm_family``, and the canonical spelling of everything else — are
    deliberately absent from what collectors fill in.
    """

    collector: CollectorName
    #: exactly as the artefact spells it: ``sha1WithRSAEncryption``, ``TLSv1``
    algorithm_name: str
    source_layer: SourceLayer
    confidence: Confidence = Confidence.HIGH
    #: only when the artefact carries one — a certificate does, a config file does not
    algorithm_oid: str | None = None
    primitive: Primitive = Primitive.UNKNOWN
    key_size: int | None = None
    mode: str | None = None
    protocol_version: str | None = None
    #: ``path:line`` or ``host:port``
    evidence_location: str | None = None
    #: whatever the collector saw, verbatim, so a disputed finding can be checked
    evidence_raw: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class ScanContext:
    """Everything a collector is allowed to touch.

    The approved path list and the probe target list are both hard scope limits,
    not hints. Nothing here exposes the un-approved remainder of the work tree.
    """

    scan_id: UUID
    #: staged source root; approved paths are relative to it
    work_dir: Path
    #: relative POSIX paths, exactly as ``scan_files`` stored them
    approved_paths: tuple[str, ...] = ()
    #: the prober's allowlist (§7.5) — ``{host, port}`` mappings
    probe_targets: tuple[Mapping[str, Any], ...] = ()
    collector_timeout_seconds: int = 120
    #: monotonic clock reading when this collector's budget started
    started_at: float = field(default_factory=monotonic)

    @classmethod
    def build(
        cls,
        scan_id: UUID,
        work_dir: Path,
        approved_paths: Sequence[str] = (),
        probe_targets: Sequence[Mapping[str, Any]] = (),
        collector_timeout_seconds: int = 120,
    ) -> "ScanContext":
        return cls(
            scan_id=scan_id,
            work_dir=Path(work_dir).resolve(),
            approved_paths=tuple(approved_paths),
            probe_targets=tuple(probe_targets),
            collector_timeout_seconds=collector_timeout_seconds,
        )

    # ----------------------------------------------------------------- budget

    def restarted(self) -> "ScanContext":
        """A copy whose timeout budget starts now. The runner calls this per collector."""
        return replace(self, started_at=monotonic())

    def elapsed_seconds(self) -> float:
        return monotonic() - self.started_at

    def check_budget(self, doing: str = "") -> None:
        """Stop if this collector has used its budget.

        Cooperative rather than pre-emptive: a thread cannot be interrupted mid
        ``read()`` without leaking it, and SPEC.md §2 already names async workers
        as the production path. Collectors call this between files, which is
        where a runaway scan actually spends its time.
        """
        if self.elapsed_seconds() <= self.collector_timeout_seconds:
            return
        raise CollectorTimeout(
            f"exceeded the {self.collector_timeout_seconds}s per-collector budget"
            + (f" while {doing}" if doing else "")
        )

    # ------------------------------------------------------------------ files

    def iter_files(self) -> Iterator[tuple[str, Path]]:
        """Yield ``(relative_path, absolute_path)`` for approved regular files only.

        Three things are dropped silently, all for the same reason — they would
        take the collector outside what the user approved:

        * a path that resolves outside the work directory,
        * a symlink (the surface scan did not offer them either),
        * a path that no longer exists or is not a regular file.
        """
        root = self.work_dir
        for relative in self.approved_paths:
            absolute = root / relative
            if absolute.is_symlink():
                continue
            try:
                resolved = absolute.resolve()
                if not resolved.is_file():
                    continue
            except OSError:
                continue
            if resolved != root and root not in resolved.parents:
                logger.warning(
                    "scan %s: approved path %r resolves outside the work directory; skipped",
                    self.scan_id,
                    relative,
                )
                continue
            yield relative, resolved


class Collector(ABC):
    """SPEC.md §7. Six of these; the registry lives in ``app/runner.py``."""

    name: ClassVar[CollectorName]

    @abstractmethod
    def collect(self, ctx: ScanContext) -> list[RawFinding]:
        """Observe, and return what was seen. Raising is survivable, not fatal."""

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"<{type(self).__name__} {self.name.value}>"
