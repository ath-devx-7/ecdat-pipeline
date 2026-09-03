"""The scan runner — SPEC.md §4 step 6, §7.

Builds one :class:`ScanContext` from an approved scan and walks the registered
collectors over it. Two rules from the spec are implemented here rather than in
each collector, because a rule that every collector has to remember is a rule
that eventually gets forgotten:

**A collector that raises returns an empty list and marks the scan ``partial``.**
It never kills the run. Losing the certificate findings because the nginx parser
tripped over one file would be a worse outcome than an honest partial result, and
``partial`` is a status the API reports so nobody mistakes it for a clean scan.

**One collector's timeout is its own.** Each gets a fresh budget (§2), enforced
cooperatively inside the collector's own loop — see ``ScanContext.check_budget``.

The loop below is deliberately dull: ``for collector in collectors`` with the
results appended. SPEC.md §2 names Celery workers as the production path, and
swapping this loop for a queue must not require touching a single collector.

**Collecting and storing are separate.** :func:`run_collectors` observes and
returns; :func:`run_scan` hands what it observed to the normalizer (§8), which is
the only thing in the system that writes ``findings`` rows. The split is why a
collector can be tested without a database and why the store has exactly one
door. The later stages hang off ``run_scan`` in §4's order: the policy engine
(§10) classifies what the normalizer stored, and steps 8 to 10 slot the alignment
check in front of it and the advisor and risk scorer behind it.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, replace as dataclass_replace
from datetime import datetime, timezone
from time import monotonic

from sqlalchemy.orm import Session

from app.collectors.base import Collector, RawFinding, ScanContext
from app.collectors.certs import CertificateCollector
from app.collectors.config import ConfigCollector
from app.config import Settings, get_settings
from app.core.normalizer import normalize
from app.core.policy import apply_policy
from app.intake.selection import approved_paths
from app.intake.stage import work_dir_for
from app.models.analysis import VerdictRow
from app.models.enums import CollectorName, ScanMode, ScanStatus
from app.models.scan import Scan

logger = logging.getLogger(__name__)

__all__ = [
    "CollectorRun",
    "FILE_COLLECTORS",
    "RunResult",
    "build_context",
    "collectors_for",
    "run_collectors",
    "run_scan",
]

#: Collectors that read the approved file tree. Registration order is run order.
#: Step 11 appends the code and binary collectors; step 12 the CBOM importer.
FILE_COLLECTORS: tuple[Collector, ...] = (CertificateCollector(), ConfigCollector())

#: Collectors that read the probe target list. Step 7 puts the network prober here.
PROBE_COLLECTORS: tuple[Collector, ...] = ()


@dataclass(frozen=True, slots=True)
class CollectorRun:
    """What one collector did. Reported to the user, so a failure is visible."""

    name: CollectorName
    finding_count: int
    duration_seconds: float
    error: str | None = None

    @property
    def failed(self) -> bool:
        return self.error is not None


@dataclass(frozen=True, slots=True)
class RunResult:
    findings: tuple[RawFinding, ...]
    runs: tuple[CollectorRun, ...]
    #: ``findings`` rows written by the normalizer. One per observation — it
    #: renames, it does not merge — so this equals ``len(findings)`` after a
    #: stored run and stays 0 for :func:`run_collectors`, which never stores.
    stored_count: int = 0
    #: ``verdicts`` rows written by the policy engine (§10), one per finding.
    verdicts: tuple[VerdictRow, ...] = ()

    @property
    def verdict_counts(self) -> dict[str, int]:
        """Findings per outcome. Deliberately five keys, never one number —
        ``broken_now`` and ``quantum_vulnerable`` are independent (§10)."""
        counts: dict[str, int] = {}
        for row in self.verdicts:
            counts[row.verdict.value] = counts.get(row.verdict.value, 0) + 1
        return counts

    @property
    def failures(self) -> tuple[CollectorRun, ...]:
        return tuple(run for run in self.runs if run.failed)

    @property
    def status(self) -> ScanStatus:
        """``partial`` when any collector failed — never ``complete`` over a hole."""
        return ScanStatus.PARTIAL if self.failures else ScanStatus.COMPLETE


def collectors_for(mode: ScanMode) -> tuple[Collector, ...]:
    """The collectors a mode runs. ``probe_only`` reads no files at all (§4)."""
    if mode is ScanMode.PROBE_ONLY:
        return PROBE_COLLECTORS
    if mode is ScanMode.FILES:
        return FILE_COLLECTORS
    return FILE_COLLECTORS + PROBE_COLLECTORS


def build_context(session: Session, scan: Scan, settings: Settings | None = None) -> ScanContext:
    """The scope a collector is handed: approved paths and declared probe targets.

    The work directory is re-derived from the ``scans`` row rather than stored, so
    a path recorded at staging time cannot go stale between then and the run.
    """
    settings = settings or get_settings()
    paths = () if scan.mode is ScanMode.PROBE_ONLY else approved_paths(session, scan.id)
    work_dir = work_dir_for(scan.id, scan.source_type, scan.source_ref, settings)
    return ScanContext.build(
        scan_id=scan.id,
        work_dir=work_dir,
        approved_paths=paths,
        probe_targets=tuple(scan.probe_targets or ()),
        collector_timeout_seconds=settings.collector_timeout_seconds,
    )


def run_collectors(ctx: ScanContext, collectors: tuple[Collector, ...]) -> RunResult:
    """Run each collector under its own budget, surviving whatever any of them does."""
    findings: list[RawFinding] = []
    runs: list[CollectorRun] = []

    for collector in collectors:
        started = monotonic()
        try:
            produced = collector.collect(ctx.restarted())
            error = None
        except Exception as exc:  # noqa: BLE001 - survivability is the point
            # Deliberately broad. A collector is third-party-ish code over
            # attacker-influenced input; any exception it can raise must cost
            # its own findings and nothing else.
            produced, error = [], f"{type(exc).__name__}: {exc}"
            logger.exception(
                "scan %s: collector %s failed; continuing with a partial result",
                ctx.scan_id,
                collector.name.value,
            )

        findings.extend(produced)
        runs.append(
            CollectorRun(
                name=collector.name,
                finding_count=len(produced),
                duration_seconds=round(monotonic() - started, 3),
                error=error,
            )
        )
        logger.info(
            "scan %s: collector %s produced %d finding(s) in %.2fs%s",
            ctx.scan_id,
            collector.name.value,
            len(produced),
            runs[-1].duration_seconds,
            "" if error is None else f" before failing: {error}",
        )

    return RunResult(findings=tuple(findings), runs=tuple(runs))


def run_scan(session: Session, scan: Scan, settings: Settings | None = None) -> RunResult:
    """Run every collector this scan's mode calls for, store the result, stamp the scan.

    The normalizer runs even when a collector failed. A ``partial`` scan is one
    whose findings are incomplete, not one whose findings are unavailable, and
    throwing away what did come back would turn a gap into a blackout.
    """
    settings = settings or get_settings()
    scan.status = ScanStatus.RUNNING
    session.flush()

    result = run_collectors(build_context(session, scan, settings), collectors_for(scan.mode))
    stored = normalize(session, scan.id, result.findings)
    # §9 puts the alignment check between these two: it runs after the store and
    # before the policy engine, so a finding already carries its drift note by the
    # time it is classified. Step 8 inserts it here.
    verdicts = apply_policy(session, scan.id)
    result = dataclass_replace(result, stored_count=len(stored), verdicts=tuple(verdicts))

    scan.status = result.status
    scan.completed_at = datetime.now(timezone.utc)
    session.flush()

    logger.info(
        "scan %s finished %s: %d raw finding(s) from %d collector(s), %d stored, %d verdict(s)",
        scan.id,
        scan.status.value,
        len(result.findings),
        len(result.runs),
        result.stored_count,
        len(result.verdicts),
    )
    return result
