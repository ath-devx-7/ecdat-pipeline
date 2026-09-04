"""Schema and migration — SPEC.md §5.

Downstream steps address these tables, columns and enum values by name, so this
file pins the names rather than merely checking that something was created.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import sqlalchemy as sa

from app.models import Base
from app.models.enums import (
    ActionClass,
    CollectorName,
    Confidence,
    Primitive,
    RecommendationStatus,
    ScanMode,
    ScanStatus,
    SourceLayer,
    SourceType,
    Verdict,
    Wave,
)

BACKEND_ROOT = Path(__file__).resolve().parent.parent

EXPECTED_TABLES = {
    "scans",
    "scan_files",
    "findings",
    "alignment_notes",
    "verdicts",
    "recommendations",
    "risk_scores",
    "provenance_blobs",
}


def test_metadata_declares_the_eight_tables() -> None:
    assert set(Base.metadata.tables) == EXPECTED_TABLES


def test_alembic_upgrade_head_creates_every_table(tmp_path: Path) -> None:
    db_path = tmp_path / "ecdat.sqlite"
    result = subprocess.run(
        [sys.executable, "-m", "alembic", "upgrade", "head"],
        cwd=BACKEND_ROOT,
        env={
            **__import__("os").environ,
            "ECDAT_DATABASE_URL": f"sqlite+pysqlite:///{db_path.as_posix()}",
        },
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr

    engine = sa.create_engine(f"sqlite+pysqlite:///{db_path.as_posix()}")
    try:
        created = set(sa.inspect(engine).get_table_names())
    finally:
        engine.dispose()

    assert EXPECTED_TABLES <= created
    assert "alembic_version" in created


def test_findings_columns_match_the_spec() -> None:
    columns = set(Base.metadata.tables["findings"].columns.keys())
    assert columns == {
        "id",
        "scan_id",
        "collector",
        "algorithm_name",
        "algorithm_oid",
        "algorithm_family",
        "primitive",
        "key_size",
        "mode",
        "protocol_version",
        "evidence_location",
        "evidence_raw",
        "confidence",
        "source_layer",
        "created_at",
    }


def test_risk_scores_store_all_three_mosca_inputs() -> None:
    """§12: an auditor must be able to reconstruct a wave from the stored row."""
    columns = Base.metadata.tables["risk_scores"].columns
    for name in ("x_years", "y_years", "z_years", "rationale"):
        assert name in columns
    # urgency_years is null for authentication primitives — Mosca does not apply.
    assert columns["urgency_years"].nullable is True


def test_scans_table_carries_the_scan_scope_fields() -> None:
    columns = Base.metadata.tables["scans"].columns
    for name in ("probe_targets", "data_lifetime_years", "policy_version"):
        assert name in columns


def test_enum_values_are_the_spec_strings() -> None:
    """Enums store their values, not their Python member names."""
    assert [m.value for m in ScanMode] == ["probe_only", "files", "files_and_probe"]
    assert [m.value for m in SourceType] == [
        "folder",
        "github",
        "docker_image",
        "upload",
        "none",
    ]
    assert [m.value for m in ScanStatus] == [
        "staging",
        "awaiting_approval",
        "running",
        "complete",
        "partial",
        "failed",
    ]
    assert [m.value for m in CollectorName] == [
        "code",
        "binary",
        "certs",
        "config",
        "network",
        "cbom_import",
    ]
    assert [m.value for m in Primitive] == [
        "key_exchange",
        "signature",
        "hash",
        "cipher",
        "protocol",
        "unknown",
    ]
    assert [m.value for m in Confidence] == ["high", "medium", "low"]
    # Ordered by closeness to execution — this ordering is the precedence rule (§8).
    assert [m.value for m in SourceLayer] == ["live", "artifact", "config", "source"]
    assert [m.value for m in Verdict] == [
        "broken_now",
        "quantum_vulnerable",
        "quantum_safe",
        "hygiene",
        "unknown",
    ]
    assert [m.value for m in RecommendationStatus] == [
        "recommended",
        "blocked",
        "no_path",
        "unknown",
    ]
    # Ordered cheapest-first — the advisor's third tie-break (§11).
    assert [m.value for m in ActionClass] == [
        "config",
        "library_upgrade",
        "code_change",
        "hardware",
    ]
    assert [m.value for m in Wave] == ["wave_0", "wave_1", "wave_2", "wave_3", "verify"]


def test_enum_columns_persist_values_not_member_names() -> None:
    column_type = Base.metadata.tables["verdicts"].columns["verdict"].type
    assert isinstance(column_type, sa.Enum)
    assert set(column_type.enums) == {v.value for v in Verdict}
