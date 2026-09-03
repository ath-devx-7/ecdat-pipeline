"""Results endpoints — what the dashboard reads (SPEC.md §13).

Everything here is a query. Nothing is computed at scan time and cached for the
UI: the overview counts, the readiness number and the roadmap are derived from
the ``findings``, ``verdicts``, ``risk_scores``, ``recommendations`` and
``alignment_notes`` tables on every request, which is what keeps a re-score or a
CBOM import from leaving a stale number on screen.

The one endpoint that writes is ``POST /rescore``. Z — years until a
cryptographically relevant quantum computer — is an assumption, not a
measurement, and §12 asks for it as a slider. Moving it re-runs the scorer over
the scan and replaces the wave rows, with the Z used stored on each one.
"""

from __future__ import annotations

import logging
from collections import Counter
from uuid import UUID

import sqlalchemy as sa
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.core.alignment import describe_alignment
from app.core.policy_loader import PolicyPack, get_policy
from app.core.risk import score_scan
from app.core.visibility import hidden_verdicts, visible_only, visible_verdict_keys
from app.db import get_session
from app.models.analysis import Recommendation, RiskScore, VerdictRow
from app.models.enums import (
    CollectorName,
    Confidence,
    RecommendationStatus,
    ScanStatus,
    SourceLayer,
    Verdict,
    Wave,
)
from app.models.finding import AlignmentNote, Finding, ProvenanceBlob
from app.models.scan import Scan
from app.schemas.results import (
    AlignmentNoteView,
    AlignmentView,
    FindingBrief,
    FindingDetail,
    FindingPage,
    OverviewResponse,
    PolicyResponse,
    Readiness,
    RecommendationView,
    RescoreRequest,
    RescoreResponse,
    RiskView,
    RoadmapItem,
    RoadmapResponse,
    VerdictView,
)
from app.schemas.scans import ScanResponse

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api", tags=["results"])

#: Scans whose results are readable. A scan mid-run has half a table.
_READABLE = frozenset({ScanStatus.COMPLETE, ScanStatus.PARTIAL, ScanStatus.AWAITING_APPROVAL})


def _load_scan(session: Session, scan_id: UUID) -> Scan:
    scan = session.get(Scan, scan_id)
    if scan is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, f"No scan {scan_id}")
    return scan


def policy_view(policy: PolicyPack) -> PolicyResponse:
    version = policy.version
    return PolicyResponse(
        version=version.version,
        published=version.published,
        age_days=version.age_days(),
        stale=version.is_stale(),
        staleness_warning_days=version.staleness_warning_days,
        z_years_default=version.z_years_default,
        y_years_default=version.y_years_default,
        algorithm_rule_count=len(policy.algorithms),
        pqc_target_count=len(policy.pqc_targets),
        prefer_hybrid=policy.prefer_hybrid,
    )


@router.get("/policy", response_model=PolicyResponse)
def get_policy_stamp(policy: PolicyPack = Depends(get_policy)) -> PolicyResponse:
    """The loaded pack's stamp, its staleness, and the Mosca defaults the slider starts from (§6)."""
    return policy_view(policy)


@router.get("/scans", response_model=list[ScanResponse])
def list_scans(
    session: Session = Depends(get_session), limit: int = Query(50, ge=1, le=500)
) -> list[Scan]:
    """Most recent first."""
    return list(
        session.scalars(sa.select(Scan).order_by(Scan.created_at.desc(), Scan.id).limit(limit))
    )


# --------------------------------------------------------------------------- #
# Loading one scan's analysis
# --------------------------------------------------------------------------- #


class _Loaded:
    """One scan's findings and analysis rows, read once per request."""

    def __init__(self, session: Session, scan: Scan) -> None:
        self.scan = scan
        self.findings: list[Finding] = list(
            session.scalars(
                sa.select(Finding)
                .where(Finding.scan_id == scan.id)
                .order_by(Finding.evidence_location, Finding.created_at, Finding.id)
            )
        )
        ids = sa.select(Finding.id).where(Finding.scan_id == scan.id)
        self.verdicts: dict[UUID, VerdictRow] = {
            row.finding_id: row
            for row in session.scalars(sa.select(VerdictRow).where(VerdictRow.finding_id.in_(ids)))
        }
        self.scores: dict[UUID, RiskScore] = {
            row.finding_id: row
            for row in session.scalars(sa.select(RiskScore).where(RiskScore.finding_id.in_(ids)))
        }
        self.recommendations: dict[UUID, list[Recommendation]] = {}
        for row in session.scalars(
            sa.select(Recommendation)
            .where(Recommendation.finding_id.in_(ids))
            .order_by(Recommendation.id)
        ):
            self.recommendations.setdefault(row.finding_id, []).append(row)
        #: every row, for the numbers that need the whole population (readiness)
        self.all_findings: list[Finding] = list(self.findings)
        #: what the user is shown — hidden verdicts removed (core/visibility.py)
        self.findings = visible_only(self.all_findings, self.verdicts)
        self.hidden_count = len(self.all_findings) - len(self.findings)

    def detail(self, finding: Finding) -> FindingDetail:
        verdict = self.verdicts.get(finding.id)
        score = self.scores.get(finding.id)
        return FindingDetail(
            **FindingBrief.model_validate(finding).model_dump(),
            evidence_raw=finding.evidence_raw,
            created_at=finding.created_at,
            verdict=VerdictView.model_validate(verdict) if verdict else None,
            risk=RiskView.model_validate(score) if score else None,
            recommendations=[
                RecommendationView.model_validate(row)
                for row in self.recommendations.get(finding.id, ())
            ],
        )

    def z_years_used(self) -> int | None:
        used = {row.z_years for row in self.scores.values() if row.z_years is not None}
        return max(used) if used else None


def _all_keys(counter: Counter[str], keys) -> dict[str, int]:
    return {key.value: counter.get(key.value, 0) for key in keys}


def _readiness(loaded: _Loaded) -> Readiness:
    counts = Counter(row.verdict.value for row in loaded.verdicts.values())
    safe = counts.get(Verdict.QUANTUM_SAFE.value, 0)
    vulnerable = counts.get(Verdict.QUANTUM_VULNERABLE.value, 0)
    broken = counts.get(Verdict.BROKEN_NOW.value, 0)
    assessed = safe + vulnerable + broken
    return Readiness(
        percent=round(100.0 * safe / assessed, 1) if assessed else None,
        quantum_safe=safe,
        quantum_vulnerable=vulnerable,
        broken_now=broken,
        hygiene=counts.get(Verdict.HYGIENE.value, 0),
        unassessed=counts.get(Verdict.UNKNOWN.value, 0),
        assessed=assessed,
    )


def _alignment_view(session: Session, scan: Scan) -> AlignmentView:
    result = describe_alignment(session, scan)
    if result.skipped:
        return AlignmentView(status=result.status, reason=result.reason)
    notes: list[AlignmentNoteView] = []
    for note in result.notes:
        config = session.get(Finding, note.config_finding_id)
        live = session.get(Finding, note.live_finding_id)
        if config is None or live is None:
            continue
        notes.append(
            AlignmentNoteView(
                id=note.id,
                asset_key=note.asset_key,
                note=note.note,
                config=FindingBrief.model_validate(config),
                live=FindingBrief.model_validate(live),
                declared=_declared(config),
                observed=_observed(live),
            )
        )
    return AlignmentView(
        status=result.status,
        note_count=len(notes),
        notes=notes,
        compared_services=list(result.compared_services),
        scope_skipped=list(result.scope_skipped),
    )


def _declared(finding: Finding) -> dict:
    evidence = finding.evidence_raw or {}
    return {
        "observation": evidence.get("observation"),
        "file": evidence.get("file"),
        "line": (finding.evidence_location or "").rpartition(":")[2] or None,
        "directive": evidence.get("directive") or evidence.get("key"),
        "declared": evidence.get("declared") or evidence.get("args"),
        "protocol_version": finding.protocol_version,
        "server": evidence.get("server"),
        "activated_by_openssl_conf": evidence.get("activated_by_openssl_conf"),
    }


def _observed(finding: Finding) -> dict:
    evidence = finding.evidence_raw or {}
    return {
        "observation": evidence.get("observation"),
        "host": evidence.get("host"),
        "port": evidence.get("port"),
        "version": evidence.get("version"),
        "protocol_version": finding.protocol_version,
        "offered": evidence.get("offered"),
        "accepted_suite_count": evidence.get("accepted_suite_count"),
        "rejected_suite_count": evidence.get("rejected_suite_count"),
    }


# --------------------------------------------------------------------------- #
# Screens
# --------------------------------------------------------------------------- #


@router.get("/scans/{scan_id}/overview", response_model=OverviewResponse)
def get_overview(
    scan_id: UUID,
    session: Session = Depends(get_session),
    policy: PolicyPack = Depends(get_policy),
) -> OverviewResponse:
    """§13 screen 3. Every count, the readiness number with its denominator, all four statuses."""
    scan = _load_scan(session, scan_id)
    loaded = _Loaded(session, scan)
    provenance_count = session.scalar(
        sa.select(sa.func.count()).select_from(ProvenanceBlob).where(ProvenanceBlob.scan_id == scan.id)
    )
    return OverviewResponse(
        scan=ScanResponse.model_validate(scan),
        finding_count=len(loaded.findings),
        readiness=_readiness(loaded),
        verdict_counts={
            key: count
            for key, count in _all_keys(Counter(r.verdict.value for r in loaded.verdicts.values()), Verdict).items()
            if key in visible_verdict_keys()
        },
        wave_counts=_all_keys(Counter(r.wave.value for r in loaded.scores.values()), Wave),
        recommendation_counts=_all_keys(
            Counter(r.status.value for rows in loaded.recommendations.values() for r in rows),
            RecommendationStatus,
        ),
        primitive_counts=dict(Counter(f.primitive.value for f in loaded.findings)),
        collector_counts=dict(Counter(f.collector.value for f in loaded.findings)),
        source_layer_counts=dict(Counter(f.source_layer.value for f in loaded.findings)),
        alignment=_alignment_view(session, scan),
        policy=policy_view(policy),
        z_years_used=loaded.z_years_used(),
        provenance_count=int(provenance_count or 0),
    )


@router.get("/scans/{scan_id}/findings", response_model=FindingPage)
def list_findings(
    scan_id: UUID,
    session: Session = Depends(get_session),
    verdict: list[Verdict] | None = Query(None),
    wave: list[Wave] | None = Query(None),
    collector: list[CollectorName] | None = Query(None),
    confidence: list[Confidence] | None = Query(None),
    source_layer: list[SourceLayer] | None = Query(None),
    q: str | None = Query(None, description="substring of the algorithm name, family or location"),
    offset: int = Query(0, ge=0),
    limit: int = Query(200, ge=1, le=2000),
) -> FindingPage:
    """§13 screen 4. Filters are OR within a field and AND across fields."""
    scan = _load_scan(session, scan_id)
    loaded = _Loaded(session, scan)

    verdict_set = {v for v in verdict or ()}
    wave_set = {w for w in wave or ()}
    collector_set = {c for c in collector or ()}
    confidence_set = {c for c in confidence or ()}
    layer_set = {s for s in source_layer or ()}
    needle = (q or "").strip().lower()

    selected: list[Finding] = []
    for finding in loaded.findings:
        verdict_row = loaded.verdicts.get(finding.id)
        score = loaded.scores.get(finding.id)
        if verdict_set and (verdict_row is None or verdict_row.verdict not in verdict_set):
            continue
        if wave_set and (score is None or score.wave not in wave_set):
            continue
        if collector_set and finding.collector not in collector_set:
            continue
        if confidence_set and finding.confidence not in confidence_set:
            continue
        if layer_set and finding.source_layer not in layer_set:
            continue
        if needle and needle not in " ".join(
            filter(None, (finding.algorithm_name, finding.algorithm_family, finding.evidence_location))
        ).lower():
            continue
        selected.append(finding)

    facets = {
        "verdict": sorted(
            {r.verdict.value for r in loaded.verdicts.values() if r.verdict not in hidden_verdicts()}
        ),
        "wave": sorted({r.wave.value for r in loaded.scores.values()}),
        "collector": sorted({f.collector.value for f in loaded.findings}),
        "confidence": sorted({f.confidence.value for f in loaded.findings}),
        "source_layer": sorted({f.source_layer.value for f in loaded.findings}),
    }
    page = selected[offset : offset + limit]
    return FindingPage(
        total=len(selected),
        offset=offset,
        limit=limit,
        items=[loaded.detail(finding) for finding in page],
        facets=facets,
    )


@router.get("/scans/{scan_id}/findings/{finding_id}", response_model=FindingDetail)
def get_finding(
    scan_id: UUID, finding_id: UUID, session: Session = Depends(get_session)
) -> FindingDetail:
    scan = _load_scan(session, scan_id)
    finding = session.get(Finding, finding_id)
    if finding is None or finding.scan_id != scan.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, f"No finding {finding_id} in scan {scan_id}")
    return _Loaded(session, scan).detail(finding)


@router.get("/scans/{scan_id}/alignment", response_model=AlignmentView)
def get_alignment(scan_id: UUID, session: Session = Depends(get_session)) -> AlignmentView:
    """§13 screen 5. The skipped state is a first-class answer, never an empty list."""
    return _alignment_view(session, _load_scan(session, scan_id))


@router.get("/scans/{scan_id}/roadmap", response_model=RoadmapResponse)
def get_roadmap(scan_id: UUID, session: Session = Depends(get_session)) -> RoadmapResponse:
    """§13 screen 6. Findings grouped by wave with target, prerequisites and action class."""
    scan = _load_scan(session, scan_id)
    loaded = _Loaded(session, scan)
    waves: dict[str, list[RoadmapItem]] = {wave.value: [] for wave in Wave}
    unscored = 0
    for finding in loaded.findings:
        score = loaded.scores.get(finding.id)
        if score is None:
            unscored += 1
            continue
        verdict = loaded.verdicts.get(finding.id)
        waves[score.wave.value].append(
            RoadmapItem(
                finding=FindingBrief.model_validate(finding),
                verdict=verdict.verdict if verdict else None,
                urgency_years=score.urgency_years,
                rationale=score.rationale,
                recommendations=[
                    RecommendationView.model_validate(row)
                    for row in loaded.recommendations.get(finding.id, ())
                ],
            )
        )
    # Most overdue first within a wave; ties keep the location order.
    for items in waves.values():
        items.sort(key=lambda item: -(item.urgency_years if item.urgency_years is not None else -10**6))
    return RoadmapResponse(
        waves=waves,
        wave_counts={wave: len(items) for wave, items in waves.items()},
        unscored=unscored,
        z_years_used=loaded.z_years_used(),
    )


@router.post("/scans/{scan_id}/rescore", response_model=RescoreResponse)
def rescore(
    scan_id: UUID, payload: RescoreRequest, session: Session = Depends(get_session)
) -> RescoreResponse:
    """The Z slider (§12). Re-scores every finding against a different arrival assumption."""
    scan = _load_scan(session, scan_id)
    if scan.status not in _READABLE:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            f"Scan {scan_id} is '{scan.status.value}'; re-scoring needs a finished scan.",
        )
    scores = score_scan(session, scan, z_years=payload.z_years)
    session.flush()
    counts = Counter(row.wave.value for row in scores)
    logger.info("scan %s re-scored at Z=%d: %s", scan.id, payload.z_years, dict(counts))
    return RescoreResponse(
        scan_id=scan.id,
        z_years=payload.z_years,
        wave_counts=_all_keys(counts, Wave),
    )
