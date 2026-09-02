"""``verdicts``, ``recommendations`` and ``risk_scores`` — SPEC.md §5, §10–§12."""

from __future__ import annotations

import uuid
from typing import Any

import sqlalchemy as sa
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import JSONB, Base, pg_enum, uuid_pk
from app.models.enums import ActionClass, RecommendationStatus, Verdict, Wave
from app.models.finding import Finding


class VerdictRow(Base):
    """Policy-engine output. One per finding, always traceable to a citation (§10)."""

    __tablename__ = "verdicts"

    id: Mapped[uuid.UUID] = uuid_pk()
    finding_id: Mapped[uuid.UUID] = mapped_column(
        sa.ForeignKey("findings.id", ondelete="CASCADE"), nullable=False, index=True
    )
    verdict: Mapped[Verdict] = mapped_column(pg_enum(Verdict, "verdict"), nullable=False)
    #: which algorithms.yaml entry fired
    rule_id: Mapped[str | None] = mapped_column(sa.Text, nullable=True)
    #: e.g. "NIST SP 800-131A Rev.2"
    source_citation: Mapped[str | None] = mapped_column(sa.Text, nullable=True)
    policy_version: Mapped[str | None] = mapped_column(sa.Text, nullable=True)

    finding: Mapped[Finding] = relationship()


class Recommendation(Base):
    """Advisor output (§11). ``prerequisites`` is the blocker chain — the highest-value field."""

    __tablename__ = "recommendations"

    id: Mapped[uuid.UUID] = uuid_pk()
    finding_id: Mapped[uuid.UUID] = mapped_column(
        sa.ForeignKey("findings.id", ondelete="CASCADE"), nullable=False, index=True
    )
    status: Mapped[RecommendationStatus] = mapped_column(
        pg_enum(RecommendationStatus, "recommendation_status"), nullable=False
    )
    #: e.g. ML-KEM-768
    target: Mapped[str | None] = mapped_column(sa.Text, nullable=True)
    hybrid_target: Mapped[str | None] = mapped_column(sa.Text, nullable=True)
    action_class: Mapped[ActionClass | None] = mapped_column(
        pg_enum(ActionClass, "action_class"), nullable=True
    )
    #: ordered list of unmet requirements
    prerequisites: Mapped[Any | None] = mapped_column(JSONB, nullable=True)
    side_effects: Mapped[str | None] = mapped_column(sa.Text, nullable=True)
    source_citation: Mapped[str | None] = mapped_column(sa.Text, nullable=True)

    finding: Mapped[Finding] = relationship()


class RiskScore(Base):
    """Mosca inputs and the resulting wave (§12).

    The three inputs are stored, not just the result: an auditor must be able to
    reconstruct any wave assignment from this row.
    """

    __tablename__ = "risk_scores"

    id: Mapped[uuid.UUID] = uuid_pk()
    finding_id: Mapped[uuid.UUID] = mapped_column(
        sa.ForeignKey("findings.id", ondelete="CASCADE"), nullable=False, index=True
    )
    x_years: Mapped[int | None] = mapped_column(sa.Integer, nullable=True)
    y_years: Mapped[int | None] = mapped_column(sa.Integer, nullable=True)
    z_years: Mapped[int | None] = mapped_column(sa.Integer, nullable=True)
    #: (X + Y) − Z. NULL for authentication primitives — Mosca does not apply.
    urgency_years: Mapped[int | None] = mapped_column(sa.Integer, nullable=True)
    wave: Mapped[Wave] = mapped_column(pg_enum(Wave, "wave"), nullable=False)
    #: every factor that produced the wave
    rationale: Mapped[Any | None] = mapped_column(JSONB, nullable=True)

    finding: Mapped[Finding] = relationship()
