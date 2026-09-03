"""Response bodies for the results endpoints — SPEC.md §13's six screens.

Every number the dashboard shows comes from one of these, and each one is built
from a query over the analysis tables rather than from anything cached at scan
time. The two rules §13 states about what a dashboard must not hide are encoded
here as shapes: ``RecommendationCounts`` always carries all four statuses, and
``AlignmentView`` always carries a status, with a reason when it is ``skipped``.
"""

from __future__ import annotations

from datetime import date, datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from app.models.enums import (
    ActionClass,
    CollectorName,
    Confidence,
    Primitive,
    RecommendationStatus,
    SourceLayer,
    Verdict,
    Wave,
)
from app.schemas.scans import ScanResponse

__all__ = [
    "AlignmentNoteView",
    "AlignmentView",
    "FindingBrief",
    "FindingDetail",
    "FindingPage",
    "OverviewResponse",
    "PolicyResponse",
    "Readiness",
    "RecommendationView",
    "RescoreRequest",
    "RescoreResponse",
    "RiskView",
    "RoadmapItem",
    "RoadmapResponse",
    "VerdictView",
]


class PolicyResponse(BaseModel):
    """``GET /api/policy`` — the stamp the UI shows, and the slider's default."""

    version: str
    published: date
    age_days: int
    stale: bool
    staleness_warning_days: int
    z_years_default: int
    y_years_default: int
    algorithm_rule_count: int
    pqc_target_count: int
    prefer_hybrid: bool


class VerdictView(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    verdict: Verdict
    rule_id: str | None
    source_citation: str | None
    policy_version: str | None


class RiskView(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    wave: Wave
    urgency_years: int | None
    x_years: int | None
    y_years: int | None
    z_years: int | None
    rationale: Any | None


class RecommendationView(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    status: RecommendationStatus
    target: str | None
    hybrid_target: str | None
    action_class: ActionClass | None
    prerequisites: Any | None
    side_effects: str | None
    source_citation: str | None


class FindingBrief(BaseModel):
    """Enough of a finding to name it in a table row or a drift panel."""

    model_config = ConfigDict(from_attributes=True)

    id: UUID
    collector: CollectorName
    algorithm_name: str
    algorithm_family: str | None
    algorithm_oid: str | None
    primitive: Primitive
    key_size: int | None
    mode: str | None
    protocol_version: str | None
    evidence_location: str | None
    confidence: Confidence
    source_layer: SourceLayer


class FindingDetail(FindingBrief):
    """A row plus everything the analysis said about it — the drill-in (§13 screen 4)."""

    evidence_raw: Any | None
    created_at: datetime | None
    verdict: VerdictView | None = None
    risk: RiskView | None = None
    recommendations: list[RecommendationView] = Field(default_factory=list)


class FindingPage(BaseModel):
    total: int
    offset: int
    limit: int
    items: list[FindingDetail]
    #: The distinct values present in this scan, so the filter controls offer
    #: only choices that select something.
    facets: dict[str, list[str]] = Field(default_factory=dict)


class Readiness(BaseModel):
    """PQC readiness, with its denominator stated (§13 screen 3).

    ``percent`` is ``quantum_safe`` over every finding the pack could classify as
    safe, vulnerable or broken. ``unassessed`` — the ``unknown`` verdicts — are
    counted beside it rather than folded in, because a readiness number that
    quietly treats "not assessed" as either "safe" or "vulnerable" is a number
    nobody should act on (§7.5).
    """

    percent: float | None
    quantum_safe: int
    quantum_vulnerable: int
    broken_now: int
    hygiene: int
    unassessed: int
    assessed: int


class AlignmentNoteView(BaseModel):
    id: UUID
    asset_key: str
    note: str
    config: FindingBrief
    live: FindingBrief
    #: what the config line declared and what the probe observed, as the
    #: collectors wrote them — the two halves of the side-by-side
    declared: Any | None = None
    observed: Any | None = None


class AlignmentView(BaseModel):
    """Always a status; a reason whenever it is ``skipped`` (§9, §13 screen 5)."""

    status: str
    reason: str | None = None
    note_count: int = 0
    notes: list[AlignmentNoteView] = Field(default_factory=list)
    compared_services: list[str] = Field(default_factory=list)
    scope_skipped: list[str] = Field(default_factory=list)


class OverviewResponse(BaseModel):
    scan: ScanResponse
    finding_count: int
    readiness: Readiness
    verdict_counts: dict[str, int]
    wave_counts: dict[str, int]
    #: all four keys, always
    recommendation_counts: dict[str, int]
    primitive_counts: dict[str, int]
    collector_counts: dict[str, int]
    source_layer_counts: dict[str, int]
    alignment: AlignmentView
    policy: PolicyResponse
    #: the Z the stored risk rows were scored with — the slider's current position
    z_years_used: int | None
    provenance_count: int


class RoadmapItem(BaseModel):
    finding: FindingBrief
    verdict: Verdict | None
    urgency_years: int | None
    rationale: Any | None
    recommendations: list[RecommendationView] = Field(default_factory=list)


class RoadmapResponse(BaseModel):
    """Findings grouped by wave (§13 screen 6). Every wave key is present, empty or not."""

    waves: dict[str, list[RoadmapItem]]
    wave_counts: dict[str, int]
    #: findings with no wave — quantum_safe and hygiene need no migration
    unscored: int
    z_years_used: int | None


class RescoreRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    #: years until a cryptographically relevant quantum computer — the Z slider
    z_years: int = Field(ge=0, le=100)


class RescoreResponse(BaseModel):
    scan_id: UUID
    z_years: int
    wave_counts: dict[str, int]
