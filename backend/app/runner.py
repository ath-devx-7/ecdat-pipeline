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

Findings are returned, not stored. Writing ``findings`` rows is the normalizer's
job (§8, build step 5), and it is the only thing that stands between this runner
and a populated database.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from time import monotonic

from sqlalchemy.orm import Session

from app.collectors.base import Collector, RawFinding, ScanContext
from app.collectors.certs import CertificateCollector
from app.collectors.config import ConfigCollector
from app.config import Settings, get_settings
from app.intake.selection import approved_paths
from app.intake.stage import work_dir_for
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
    """Run every collector this scan's mode calls for and stamp the outcome.

    Step 5 pipes ``result.findings`` through the normalizer into the ``findings``
    table on the way out of here; today they go no further than the response.
    """
    settings = settings or get_settings()
    scan.status = ScanStatus.RUNNING
    session.flush()

    result = run_collectors(build_context(session, scan, settings), collectors_for(scan.mode))

    scan.status = result.status
    scan.completed_at = datetime.now(timezone.utc)
    session.flush()

    logger.info(
        "scan %s finished %s: %d raw finding(s) from %d collector(s)",
        scan.id,
        scan.status.value,
        len(result.findings),
        len(result.runs),
    )
    return result
