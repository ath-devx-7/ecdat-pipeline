"""``scans`` and ``scan_files`` — SPEC.md §5."""

from __future__ import annotations

import uuid
from datetime import datetime

import sqlalchemy as sa
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import JSONB, TIMESTAMPTZ, Base, created_at_col, pg_enum, uuid_pk
from app.models.enums import ScanMode, ScanStatus, SourceType


class Scan(Base):
    __tablename__ = "scans"

    id: Mapped[uuid.UUID] = uuid_pk()
    mode: Mapped[ScanMode] = mapped_column(pg_enum(ScanMode, "scan_mode"), nullable=False)
    source_type: Mapped[SourceType] = mapped_column(
        pg_enum(SourceType, "source_type"), nullable=False
    )
    #: path, repo URL, or image tag
    source_ref: Mapped[str | None] = mapped_column(sa.Text, nullable=True)
    #: list of {host, port} — the prober's hard allowlist (§7.5)
    probe_targets: Mapped[list | None] = mapped_column(JSONB, nullable=True)
    #: X in Mosca's inequality, from the intake form (§12)
    data_lifetime_years: Mapped[int | None] = mapped_column(sa.Integer, nullable=True)
    #: stamped from the loaded policy pack at scan creation (§6)
    policy_version: Mapped[str | None] = mapped_column(sa.Text, nullable=True)
    status: Mapped[ScanStatus] = mapped_column(
        pg_enum(ScanStatus, "scan_status"), nullable=False, default=ScanStatus.STAGING
    )
    file_count: Mapped[int] = mapped_column(sa.Integer, nullable=False, default=0)
    approved_count: Mapped[int] = mapped_column(sa.Integer, nullable=False, default=0)
    #: Why the result looks the way it does (§2's partial reporting): per
    #: collector whether it ran, what it was handed and what it returned, plus
    #: approved files against findings per extension. Written by the runner at
    #: the end of a run, so a dashboard opened days later can still say which
    #: collector degraded rather than only that one did.
    diagnostics: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    created_at: Mapped[datetime] = created_at_col()
    completed_at: Mapped[datetime | None] = mapped_column(TIMESTAMPTZ, nullable=True)

    files: Mapped[list["ScanFile"]] = relationship(
        back_populates="scan", cascade="all, delete-orphan"
    )


class ScanFile(Base):
    """Surface-scan output, presented to the UI for approval. No parsing (§4)."""

    __tablename__ = "scan_files"

    id: Mapped[uuid.UUID] = uuid_pk()
    scan_id: Mapped[uuid.UUID] = mapped_column(
        sa.ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True
    )
    #: relative to the work dir
    path: Mapped[str] = mapped_column(sa.Text, nullable=False)
    size_bytes: Mapped[int | None] = mapped_column(sa.BigInteger, nullable=True)
    approved: Mapped[bool] = mapped_column(sa.Boolean, nullable=False, default=False)

    scan: Mapped[Scan] = relationship(back_populates="files")

    __table_args__ = (sa.UniqueConstraint("scan_id", "path", name="uq_scan_files_scan_path"),)
