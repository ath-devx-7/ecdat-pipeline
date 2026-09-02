"""``findings``, ``alignment_notes`` and ``provenance_blobs`` — SPEC.md §5, §7.6."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

import sqlalchemy as sa
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import JSONB, Base, created_at_col, pg_enum, uuid_pk
from app.models.enums import CollectorName, Confidence, Primitive, SourceLayer


class Finding(Base):
    """One row per observed crypto use. The core table."""

    __tablename__ = "findings"

    id: Mapped[uuid.UUID] = uuid_pk()
    scan_id: Mapped[uuid.UUID] = mapped_column(
        sa.ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True
    )
    collector: Mapped[CollectorName] = mapped_column(
        pg_enum(CollectorName, "collector_name"), nullable=False
    )
    #: as observed, before alias resolution
    algorithm_name: Mapped[str] = mapped_column(sa.Text, nullable=False)
    #: resolved by the normalizer (§8)
    algorithm_oid: Mapped[str | None] = mapped_column(sa.Text, nullable=True)
    algorithm_family: Mapped[str | None] = mapped_column(sa.Text, nullable=True)
    primitive: Mapped[Primitive] = mapped_column(
        pg_enum(Primitive, "primitive"), nullable=False, default=Primitive.UNKNOWN
    )
    key_size: Mapped[int | None] = mapped_column(sa.Integer, nullable=True)
    #: GCM, ECB, CBC
    mode: Mapped[str | None] = mapped_column(sa.Text, nullable=True)
    protocol_version: Mapped[str | None] = mapped_column(sa.Text, nullable=True)
    #: ``path:line`` or ``host:port``
    evidence_location: Mapped[str | None] = mapped_column(sa.Text, nullable=True)
    #: original collector output for this finding
    evidence_raw: Mapped[Any | None] = mapped_column(JSONB, nullable=True)
    confidence: Mapped[Confidence] = mapped_column(
        pg_enum(Confidence, "confidence"), nullable=False, default=Confidence.MEDIUM
    )
    source_layer: Mapped[SourceLayer] = mapped_column(
        pg_enum(SourceLayer, "source_layer"), nullable=False
    )
    created_at: Mapped[datetime] = created_at_col()


class AlignmentNote(Base):
    """A live/config divergence at one usage site (§9). Never classified — only reported."""

    __tablename__ = "alignment_notes"

    id: Mapped[uuid.UUID] = uuid_pk()
    scan_id: Mapped[uuid.UUID] = mapped_column(
        sa.ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True
    )
    live_finding_id: Mapped[uuid.UUID] = mapped_column(
        sa.ForeignKey("findings.id", ondelete="CASCADE"), nullable=False
    )
    config_finding_id: Mapped[uuid.UUID] = mapped_column(
        sa.ForeignKey("findings.id", ondelete="CASCADE"), nullable=False
    )
    #: what matched the two findings (§9 asset key)
    asset_key: Mapped[str] = mapped_column(sa.Text, nullable=False)
    note: Mapped[str] = mapped_column(sa.Text, nullable=False)

    live_finding: Mapped[Finding] = relationship(foreign_keys=[live_finding_id])
    config_finding: Mapped[Finding] = relationship(foreign_keys=[config_finding_id])


class ProvenanceBlob(Base):
    """A CBOM exactly as uploaded (§7.6).

    Stored so a disputed finding can be traced to what the source tool actually
    said. Never re-parsed.
    """

    __tablename__ = "provenance_blobs"

    id: Mapped[uuid.UUID] = uuid_pk()
    scan_id: Mapped[uuid.UUID] = mapped_column(
        sa.ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True
    )
    raw_document: Mapped[Any] = mapped_column(JSONB, nullable=False)
    created_at: Mapped[datetime] = created_at_col()
