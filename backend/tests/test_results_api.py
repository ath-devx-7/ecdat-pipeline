"""The results endpoints behind the dashboard — SPEC.md §13.

What §13 says a dashboard must not hide is what these tests hold the API to:
all four recommendation statuses whether or not they have members, the
readiness number with its denominator and its unassessed count beside it, and a
drift panel that says *why* it is empty rather than being empty.
"""

from __future__ import annotations

from uuid import uuid4

import pytest

from app.core.policy_loader import get_policy


@pytest.fixture
def scan_id(demo_scan) -> str:
    return demo_scan["scan_id"]


def test_the_policy_stamp_carries_the_slider_default(client) -> None:
    payload = client.get("/api/policy").json()
    policy = get_policy().version

    assert payload["version"] == policy.version
    assert payload["z_years_default"] == policy.z_years_default
    assert payload["y_years_default"] == policy.y_years_default
    assert payload["staleness_warning_days"] == policy.staleness_warning_days
    assert isinstance(payload["stale"], bool)


def test_scans_are_listed_most_recent_first(client, scan_id) -> None:
    listed = client.get("/api/scans").json()
    assert listed[0]["id"] == scan_id


# --------------------------------------------------------------------------- #
# Overview
# --------------------------------------------------------------------------- #


def test_the_overview_shows_every_status_and_states_the_readiness_denominator(client, scan_id) -> None:
    overview = client.get(f"/api/scans/{scan_id}/overview").json()

    assert overview["scan"]["id"] == scan_id
    assert overview["finding_count"] > 0
    # All four, always — reporting only `recommended` hides the hard part (§11).
    assert set(overview["recommendation_counts"]) == {"recommended", "blocked", "no_path", "unknown"}
    assert overview["recommendation_counts"]["no_path"] == 0
    # quantum_safe is kept in the store and hidden from every output by default.
    assert set(overview["verdict_counts"]) == {"broken_now", "quantum_vulnerable", "hygiene", "unknown"}
    assert set(overview["wave_counts"]) == {"wave_0", "wave_1", "wave_2", "wave_3", "verify"}

    readiness = overview["readiness"]
    assert readiness["assessed"] == readiness["quantum_safe"] + readiness["quantum_vulnerable"] + readiness["broken_now"]
    assert readiness["percent"] == round(100.0 * readiness["quantum_safe"] / readiness["assessed"], 1)
    # The unassessed count sits beside the number rather than inside it (§7.5).
    assert readiness["unassessed"] == overview["verdict_counts"]["unknown"] > 0

    # The slider can only move what Mosca applies to, and the overview says how many that is.
    # Everything overdue is in wave_1 or wave_2; what is subject but not overdue sits in wave_3.
    assert overview["mosca"]["overdue"] == overview["wave_counts"]["wave_1"] + overview["wave_counts"]["wave_2"]
    assert overview["mosca"]["subject"] >= overview["mosca"]["overdue"] > 0
    assert overview["mosca"]["unknown_primitive"] >= 0

    assert overview["policy"]["version"] == "2026.09"
    assert overview["alignment"]["status"] == "skipped"
    assert "no live findings" in overview["alignment"]["reason"]
    assert overview["z_years_used"] == 12


def test_an_unknown_scan_is_a_404(client) -> None:
    assert client.get(f"/api/scans/{uuid4()}/overview").status_code == 404
    assert client.get(f"/api/scans/{uuid4()}/findings").status_code == 404
    assert client.get(f"/api/scans/{uuid4()}/roadmap").status_code == 404


# --------------------------------------------------------------------------- #
# Findings
# --------------------------------------------------------------------------- #


def test_findings_are_filterable_and_carry_their_full_rationale(client, scan_id) -> None:
    everything = client.get(f"/api/scans/{scan_id}/findings").json()
    assert everything["total"] == len(everything["items"]) > 0
    assert set(everything["facets"]) == {"verdict", "wave", "collector", "confidence", "source_layer"}

    broken = client.get(f"/api/scans/{scan_id}/findings", params={"verdict": "broken_now"}).json()
    assert 0 < broken["total"] < everything["total"]
    assert all(item["verdict"]["verdict"] == "broken_now" for item in broken["items"])
    # Every classified row names its rule and its citation, and a scored row its wave.
    for item in broken["items"]:
        assert item["verdict"]["source_citation"]
        assert item["risk"]["wave"] == "wave_0"
        assert item["evidence_raw"]

    # Filters AND across fields, OR within one.
    two = client.get(
        f"/api/scans/{scan_id}/findings",
        params=[("verdict", "broken_now"), ("verdict", "quantum_vulnerable"), ("collector", "certs")],
    ).json()
    assert all(item["collector"] == "certs" for item in two["items"])
    assert {item["verdict"]["verdict"] for item in two["items"]} <= {"broken_now", "quantum_vulnerable"}

    wave_1 = client.get(f"/api/scans/{scan_id}/findings", params={"wave": "wave_1"}).json()
    assert wave_1["total"] > 0
    assert all(item["risk"]["urgency_years"] is not None for item in wave_1["items"])
    assert all(item["recommendations"] for item in wave_1["items"])

    searched = client.get(f"/api/scans/{scan_id}/findings", params={"q": "sshd_config"}).json()
    assert searched["total"] > 0
    assert all("sshd_config" in item["evidence_location"] for item in searched["items"])

    paged = client.get(f"/api/scans/{scan_id}/findings", params={"limit": 5, "offset": 5}).json()
    assert len(paged["items"]) == 5 and paged["offset"] == 5 and paged["total"] == everything["total"]


def test_a_single_finding_can_be_fetched_by_id(client, scan_id) -> None:
    first = client.get(f"/api/scans/{scan_id}/findings", params={"limit": 1}).json()["items"][0]

    one = client.get(f"/api/scans/{scan_id}/findings/{first['id']}").json()

    assert one == first
    assert client.get(f"/api/scans/{scan_id}/findings/{uuid4()}").status_code == 404


# --------------------------------------------------------------------------- #
# Drift
# --------------------------------------------------------------------------- #


def test_the_drift_panel_says_why_it_is_empty(client, scan_id) -> None:
    """§9: display the skipped state, not an empty panel."""
    alignment = client.get(f"/api/scans/{scan_id}/alignment").json()

    assert alignment["status"] == "skipped"
    assert "files scan probes nothing" in alignment["reason"]
    assert alignment["notes"] == []


def test_the_drift_panel_shows_both_halves_of_a_note(client, db_session, local_tls_server, tmp_path) -> None:
    """A real declared floor against a real handshake, then read back side by side."""
    from app.core.alignment import align
    from app.collectors.base import ScanContext
    from app.collectors.config import ConfigCollector
    from app.collectors.network import NetworkCollector
    from app.core.normalizer import normalize
    from app.models.enums import ScanMode, ScanStatus, SourceType
    from app.models.scan import Scan
    from tests.test_alignment import OPENSSL_CNF

    host, port = local_tls_server
    scan = Scan(
        mode=ScanMode.FILES_AND_PROBE, source_type=SourceType.FOLDER, source_ref=str(tmp_path),
        data_lifetime_years=20, policy_version="2026.09", status=ScanStatus.COMPLETE,
    )
    db_session.add(scan)
    db_session.flush()
    (tmp_path / "etc").mkdir()
    (tmp_path / "etc" / "openssl.cnf").write_text(OPENSSL_CNF, encoding="utf-8", newline="\n")
    file_ctx = ScanContext.build(scan_id=scan.id, work_dir=tmp_path, approved_paths=["etc/openssl.cnf"])
    probe_ctx = ScanContext.build(scan_id=scan.id, work_dir=tmp_path, probe_targets=[{"host": host, "port": port}])
    normalize(db_session, scan.id, ConfigCollector().collect(file_ctx) + NetworkCollector().collect(probe_ctx))
    align(db_session, scan)
    db_session.commit()

    alignment = client.get(f"/api/scans/{scan.id}/alignment").json()

    assert alignment["status"] == "compared"
    assert alignment["note_count"] == 1
    note = alignment["notes"][0]
    assert note["config"]["source_layer"] == "config"
    assert note["live"]["source_layer"] == "live"
    assert note["declared"]["observation"] == "protocol_floor"
    assert note["declared"]["protocol_version"] == "1.3"
    assert note["observed"]["protocol_version"] == "1.2"
    assert note["observed"]["host"] == host
    assert "does not align" in note["note"]
    assert f"{host}:{port}" in alignment["compared_services"]


# --------------------------------------------------------------------------- #
# Roadmap and the Z slider
# --------------------------------------------------------------------------- #


def test_the_roadmap_groups_by_wave_with_targets_and_prerequisites(client, scan_id) -> None:
    roadmap = client.get(f"/api/scans/{scan_id}/roadmap").json()

    assert set(roadmap["waves"]) == {"wave_0", "wave_1", "wave_2", "wave_3", "verify"}
    assert roadmap["wave_counts"]["wave_1"] > 0 and roadmap["wave_counts"]["wave_0"] > 0
    assert roadmap["unscored"] > 0  # quantum_safe and hygiene need no wave
    assert roadmap["z_years_used"] == 12

    for item in roadmap["waves"]["wave_1"]:
        assert item["finding"]["primitive"] == "key_exchange"
        assert item["urgency_years"] == 9
        assert item["recommendations"]
        for rec in item["recommendations"]:
            assert rec["status"] in {"recommended", "blocked", "no_path", "unknown"}
            assert rec["action_class"] == "config"
            if rec["status"] == "blocked":
                assert rec["prerequisites"]
    # Signatures are in wave_3 with no urgency at all (§12's primitive gate).
    for item in roadmap["waves"]["wave_3"]:
        if item["finding"]["primitive"] == "signature":
            assert item["urgency_years"] is None


def test_the_roadmap_rolls_identical_blocker_chains_up_beside_the_rows(client, scan_id) -> None:
    """§11 step 3, counted by work. Beside the per-finding rows, never instead of them."""
    roadmap = client.get(f"/api/scans/{scan_id}/roadmap").json()

    blocked = {
        item["finding"]["id"]
        for items in roadmap["waves"].values()
        for item in items
        for rec in item["recommendations"]
        if rec["status"] == "blocked"
    }
    chains = roadmap["blocked_chains"]

    assert sum(chain["finding_count"] for chain in chains) == len(blocked)
    for chain in chains:
        assert chain["prerequisites"] and chain["assets"]
        assert all({"unmet", "observed"} == set(item) for item in chain["prerequisites"])


def test_a_blocked_scan_reports_its_chain_once_with_the_asset_named(client, blocked_scan) -> None:
    """The committed demo tree has no blocked rows, so this one is built to have one."""
    roadmap = client.get(f"/api/scans/{blocked_scan.id}/roadmap").json()

    assert len(roadmap["blocked_chains"]) == 1
    chain = roadmap["blocked_chains"][0]
    # Long-lead first: the procurement item, then the config line.
    assert [item["unmet"] for item in chain["prerequisites"]] == ["openssl>=3.5", "TLS 1.3"]
    assert [item["observed"] for item in chain["prerequisites"]] == [None, "TLS 1.2"]
    assert chain["finding_count"] == 1
    assert chain["assets"] == ["localhost:8443"]


def test_moving_the_z_slider_rescores_the_scan(client, scan_id) -> None:
    """§12: Z is an assumption. Bring the quantum computer forward and the waves change."""
    before = client.get(f"/api/scans/{scan_id}/overview").json()["wave_counts"]

    sooner = client.post(f"/api/scans/{scan_id}/rescore", json={"z_years": 3}).json()
    assert sooner["z_years"] == 3
    assert set(sooner["wave_counts"]) == set(before)

    later = client.post(f"/api/scans/{scan_id}/rescore", json={"z_years": 40}).json()
    # At Z=40 nothing is overdue: the wave_1 key exchanges move to wave_3.
    assert later["wave_counts"]["wave_1"] == 0
    assert later["wave_counts"]["wave_3"] > before["wave_3"]
    # What is broken today is unmoved by any assumption about tomorrow.
    assert later["wave_counts"]["wave_0"] == before["wave_0"]

    overview = client.get(f"/api/scans/{scan_id}/overview").json()
    assert overview["z_years_used"] == 40
    assert overview["wave_counts"] == later["wave_counts"]
    # At Z=40 nothing is overdue, but the same findings are still the ones Z can move.
    assert overview["mosca"]["overdue"] == 0
    assert overview["mosca"]["subject"] == before["wave_1"] + before["wave_2"]

    assert client.post(f"/api/scans/{scan_id}/rescore", json={"z_years": -1}).status_code == 422
    assert client.post(f"/api/scans/{uuid4()}/rescore", json={"z_years": 5}).status_code == 404
