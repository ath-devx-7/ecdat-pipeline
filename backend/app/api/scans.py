"""Scan intake endpoints — SPEC.md §4, steps 1 to 5.

Three endpoints, one lifecycle:

``POST /api/scans``                 create, stage, surface-scan  → awaiting_approval
``GET  /api/scans/{id}/files``      the tree the user picks from
``POST /api/scans/{id}/approve``    the permission gate          → running

Scans run synchronously (§2), so both ``POST`` endpoints block: creation through
staging and enumeration, approval through the collector run. That is a deliberate
prototype simplification, guarded by the file cap, the probe-target cap and the
per-collector timeout enforced here and in ``app/runner.py``.

Approval runs the collectors, the normalizer that writes their output into
``findings`` (§8) and the policy engine that gives each row a cited verdict (§10).
``finding_count`` is the number of observations, which is also the number of rows
stored: normalization resolves identities, it does not merge or drop them.
"""

from __future__ import annotations

import logging
from uuid import UUID

import sqlalchemy as sa
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.config import Settings, get_settings
from app.core.policy_loader import PolicyPack, get_policy
from app.db import get_session
from app.intake.selection import SelectionError, approve_paths
from app.intake.stage import StagingError, stage_source
from app.intake.surface import FileCapExceeded, walk_surface
from app.models.enums import ScanMode, ScanStatus
from app.models.scan import Scan, ScanFile
from app.runner import run_scan
from app.schemas.scans import (
    ApproveRequest,
    ApproveResponse,
    CollectorRunSummary,
    FileTreeResponse,
    ScanCreate,
    ScanResponse,
    build_tree,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/scans", tags=["scans"])


def _load_scan(session: Session, scan_id: UUID) -> Scan:
    scan = session.get(Scan, scan_id)
    if scan is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, f"No scan {scan_id}")
    return scan


@router.post("", response_model=ScanResponse, status_code=status.HTTP_201_CREATED)
def create_scan(
    payload: ScanCreate,
    session: Session = Depends(get_session),
    settings: Settings = Depends(get_settings),
    policy: PolicyPack = Depends(get_policy),
) -> Scan:
    """Create a scan, stage its source, and enumerate it for approval.

    The policy version is stamped now, at creation, not when the report is read:
    a verdict has to stay reproducible against the pack that produced it (§6).
    """
    if len(payload.probe_targets) > settings.max_probe_targets:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            f"{len(payload.probe_targets)} probe targets exceeds the per-scan cap of "
            f"{settings.max_probe_targets}. Split the run, or raise "
            "ECDAT_MAX_PROBE_TARGETS.",
        )

    scan = Scan(
        mode=payload.mode,
        source_type=payload.source_type,
        source_ref=payload.source_ref,
        probe_targets=[target.model_dump() for target in payload.probe_targets],
        data_lifetime_years=payload.data_lifetime_years,
        policy_version=policy.version.version,
        status=ScanStatus.STAGING,
    )
    session.add(scan)
    session.flush()  # assigns scan.id, which the work directory is named after

    if payload.mode is ScanMode.PROBE_ONLY:
        # Nothing to stage and nothing to approve: the scope is the probe target
        # list the user already gave us, so the run starts here (§4). Until the
        # network prober lands in step 7 it has no collectors to run, and a scan
        # that runs nothing completes rather than hanging in `running`.
        logger.info(
            "scan %s created in probe_only mode, %d target(s)",
            scan.id,
            len(scan.probe_targets or []),
        )
        run_scan(session, scan, settings)
        return scan

    try:
        staged = stage_source(
            scan_id=scan.id,
            source_type=payload.source_type,
            source_ref=payload.source_ref,
            settings=settings,
        )
        files = walk_surface(
            staged.work_dir,
            max_files=settings.max_files_per_scan,
            exclude_dirs=settings.surface_exclude_dirs,
        )
    except (StagingError, FileCapExceeded, OSError) as exc:
        # Keep the failed row: a rejected scan is part of the audit trail, so it
        # is committed before the error propagates and rolls the session back.
        scan.status = ScanStatus.FAILED
        session.commit()
        logger.warning("scan %s failed during intake: %s", scan.id, exc)
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc

    session.add_all(
        ScanFile(scan_id=scan.id, path=item.path, size_bytes=item.size_bytes, approved=False)
        for item in files
    )
    scan.file_count = len(files)
    scan.approved_count = 0
    scan.status = ScanStatus.AWAITING_APPROVAL
    session.flush()

    logger.info(
        "scan %s staged %s (%s) into %s: %d file(s) awaiting approval",
        scan.id,
        payload.source_ref,
        payload.source_type.value,
        staged.work_dir,
        len(files),
    )
    return scan


@router.get("/{scan_id}", response_model=ScanResponse)
def get_scan(scan_id: UUID, session: Session = Depends(get_session)) -> Scan:
    return _load_scan(session, scan_id)


@router.get("/{scan_id}/files", response_model=FileTreeResponse)
def get_scan_files(
    scan_id: UUID, session: Session = Depends(get_session)
) -> FileTreeResponse:
    """The surface scan as a tree. Path and size only — nothing has been read."""
    scan = _load_scan(session, scan_id)
    rows = session.scalars(
        sa.select(ScanFile).where(ScanFile.scan_id == scan_id).order_by(ScanFile.path)
    ).all()
    return FileTreeResponse(
        scan_id=scan.id,
        status=scan.status,
        file_count=scan.file_count,
        approved_count=scan.approved_count,
        root=build_tree(rows),
    )


@router.post("/{scan_id}/approve", response_model=ApproveResponse)
def approve_scan_files(
    scan_id: UUID,
    payload: ApproveRequest,
    session: Session = Depends(get_session),
    settings: Settings = Depends(get_settings),
) -> ApproveResponse:
    """The permission gate, and the run it releases.

    Only the paths approved here are ever opened by a collector, and this call
    blocks until every collector has finished (§2). A collector that fails costs
    its own findings and nothing else: the scan comes back ``partial`` naming it.
    """
    scan = _load_scan(session, scan_id)

    if scan.mode is ScanMode.PROBE_ONLY:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            "A probe_only scan has no files to approve; its scope is its probe targets.",
        )
    if scan.status is not ScanStatus.AWAITING_APPROVAL:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            f"Scan {scan_id} is '{scan.status.value}', not 'awaiting_approval'.",
        )

    try:
        approved = approve_paths(session, scan_id, payload.paths)
    except SelectionError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc

    scan.approved_count = approved
    session.flush()
    logger.info("scan %s approved %d of %d file(s)", scan.id, approved, scan.file_count)

    result = run_scan(session, scan, settings)

    return ApproveResponse(
        scan_id=scan.id,
        status=scan.status,
        approved_count=scan.approved_count,
        file_count=scan.file_count,
        finding_count=len(result.findings),
        collectors=[CollectorRunSummary.model_validate(run) for run in result.runs],
        verdict_counts=result.verdict_counts,
        alignment=result.alignment.as_dict() if result.alignment else {},
        wave_counts=result.wave_counts,
        recommendation_counts=result.recommendation_counts,
    )
