"""Quantum-safe findings are stored, and hidden from every output by default."""

from __future__ import annotations

import json
from uuid import UUID

import pytest
import sqlalchemy as sa

from app.core.visibility import hidden_verdicts, is_visible, visible_verdict_keys
from app.export.cyclonedx import export_cbom
from app.export.pdf import render_html
from app.models.analysis import VerdictRow
from app.models.enums import Verdict
from app.models.finding import Finding
from app.models.scan import Scan


def safe_finding_ids(session, scan_id: UUID) -> set[UUID]:
    rows = session.execute(
        sa.select(Finding.id)
        .join(VerdictRow, VerdictRow.finding_id == Finding.id)
        .where(Finding.scan_id == scan_id, VerdictRow.verdict == Verdict.QUANTUM_SAFE)
    )
    return {row[0] for row in rows}


def test_the_default_hides_only_quantum_safe(settings) -> None:
    assert settings.hide_quantum_safe is True
    assert hidden_verdicts() == {Verdict.QUANTUM_SAFE}
    assert is_visible(Verdict.QUANTUM_SAFE) is False
    assert is_visible(Verdict.QUANTUM_VULNERABLE) and is_visible(None)
    assert "quantum_safe" not in visible_verdict_keys()
    assert set(visible_verdict_keys()) == {"broken_now", "quantum_vulnerable", "hygiene", "unknown"}


def test_the_store_keeps_them_and_the_outputs_do_not(client, demo_scan, db_session) -> None:
    scan_id = UUID(demo_scan["scan_id"])
    safe = safe_finding_ids(db_session, scan_id)
    assert safe, "the demo has quantum-safe findings (AES suites, SHA-256)"

    listed = client.get(f"/api/scans/{scan_id}/findings").json()
    assert not {UUID(item["id"]) for item in listed["items"]} & safe
    assert "quantum_safe" not in listed["facets"]["verdict"]

    overview = client.get(f"/api/scans/{scan_id}/overview").json()
    assert "quantum_safe" not in overview["verdict_counts"]
    # The readiness percentage still counts them — it is the numerator.
    assert overview["readiness"]["quantum_safe"] == len(safe)
    assert overview["readiness"]["percent"] > 0

    roadmap = client.get(f"/api/scans/{scan_id}/roadmap").json()
    assert not {UUID(item["finding"]["id"]) for items in roadmap["waves"].values() for item in items} & safe

    exported = json.loads(client.get(f"/api/scans/{scan_id}/cbom").text)
    occurrences = "\n".join(
        o.get("additional_context", "")
        for c in exported["components"]
        for o in c.get("evidence", {}).get("occurrences", [])
    )
    assert not any(str(finding_id) in occurrences for finding_id in safe)
    properties = {p["name"]: p["value"] for p in exported["metadata"]["component"]["properties"]}
    assert "quantum_safe" in properties["ecdat:excluded_observations"]

    report = client.get(f"/api/scans/{scan_id}/report.html").text
    assert "not listed in this report" in report
    assert not any(str(finding_id) in report for finding_id in safe)


def test_turning_the_setting_off_shows_them_again(client, demo_scan, db_session, settings, monkeypatch) -> None:
    scan_id = UUID(demo_scan["scan_id"])
    safe = safe_finding_ids(db_session, scan_id)
    monkeypatch.setattr(settings, "hide_quantum_safe", False)

    listed = client.get(f"/api/scans/{scan_id}/findings").json()
    assert {UUID(item["id"]) for item in listed["items"]} >= safe
    assert "quantum_safe" in client.get(f"/api/scans/{scan_id}/overview").json()["verdict_counts"]

    scan = db_session.get(Scan, scan_id)
    assert "not listed in this report" not in render_html(db_session, scan)
    assert "hidden by ECDAT_HIDE_QUANTUM_SAFE" not in export_cbom(db_session, scan)
