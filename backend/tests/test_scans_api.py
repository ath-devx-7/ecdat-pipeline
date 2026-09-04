"""The intake endpoints end to end — SPEC.md §4.

Covers the four behaviours build step 2 is defined by: a folder of ten files
produces ten rows, approving three sets ``approved_count = 3``, a folder over
the cap is rejected with a message a user can act on, and ``probe_only`` creates
no ``scan_files`` rows at all.
"""

from __future__ import annotations

from uuid import UUID

import sqlalchemy as sa

from app.collectors.base import Collector, CollectorTimeout, RawFinding, ScanContext
from app.core.policy_loader import get_policy
from app.models.enums import CollectorName
from app.models.scan import Scan, ScanFile


def _create_folder_scan(client, folder, **overrides) -> dict:
    body = {
        "mode": "files",
        "source_type": "folder",
        "source_ref": str(folder),
        "data_lifetime_years": 20,
    }
    body.update(overrides)
    response = client.post("/api/scans", json=body)
    assert response.status_code == 201, response.text
    return response.json()


def test_health_reports_the_loaded_policy_stamp(client) -> None:
    payload = client.get("/api/health").json()

    assert payload["status"] == "ok"
    assert payload["policy_version"] == get_policy().version.version


def test_folder_of_ten_files_produces_ten_scan_file_rows(
    client, db_session, source_folder
) -> None:
    scan = _create_folder_scan(client, source_folder(10))

    assert scan["status"] == "awaiting_approval"
    assert scan["file_count"] == 10
    assert scan["approved_count"] == 0
    rows = db_session.scalars(
        sa.select(ScanFile).where(ScanFile.scan_id == UUID(scan["id"]))
    ).all()
    assert len(rows) == 10
    assert all(row.approved is False for row in rows)


def test_scan_stamps_the_policy_version_at_creation(client, source_folder) -> None:
    """A verdict has to stay reproducible against the pack that produced it (§6)."""
    scan = _create_folder_scan(client, source_folder(2))

    assert scan["policy_version"] == get_policy().version.version


def test_files_endpoint_returns_a_nested_tree(client, source_folder) -> None:
    scan = _create_folder_scan(client, source_folder(10))

    payload = client.get(f"/api/scans/{scan['id']}/files").json()

    assert payload["file_count"] == 10
    root = payload["root"]
    assert root["type"] == "directory" and root["file_count"] == 10
    nested = next(child for child in root["children"] if child["type"] == "directory")
    assert nested["name"] == "nested"
    assert all(child["type"] == "file" for child in nested["children"])
    assert nested["children"][0]["path"].startswith("nested/")
    # Path and size only — the surface scan reads no content (§4 step 3).
    assert set(nested["children"][0]) == {
        "type",
        "id",
        "name",
        "path",
        "size_bytes",
        "approved",
    }


def test_approving_three_paths_sets_approved_count_to_three(
    client, db_session, source_folder
) -> None:
    scan = _create_folder_scan(client, source_folder(10))
    tree = client.get(f"/api/scans/{scan['id']}/files").json()
    paths = sorted(_files(tree["root"]))[:3]

    response = client.post(f"/api/scans/{scan['id']}/approve", json={"paths": paths})

    assert response.status_code == 200, response.text
    assert response.json()["approved_count"] == 3
    assert response.json()["status"] == "complete"
    approved = db_session.scalars(
        sa.select(ScanFile.path).where(
            ScanFile.scan_id == UUID(scan["id"]), ScanFile.approved.is_(True)
        )
    ).all()
    assert sorted(approved) == paths


def test_approving_an_unknown_path_is_rejected(client, source_folder) -> None:
    """Silently dropping it would let the user believe a file is in scope."""
    scan = _create_folder_scan(client, source_folder(4))

    response = client.post(
        f"/api/scans/{scan['id']}/approve", json={"paths": ["../../etc/shadow"]}
    )

    assert response.status_code == 400
    assert "not in this scan's file list" in response.json()["detail"]


def test_folder_over_the_file_cap_is_rejected_with_a_clear_message(
    client, db_session, settings, source_folder, monkeypatch
) -> None:
    monkeypatch.setattr(settings, "max_files_per_scan", 5)

    response = client.post(
        "/api/scans",
        json={
            "mode": "files",
            "source_type": "folder",
            "source_ref": str(source_folder(12)),
            "data_lifetime_years": 5,
        },
    )

    assert response.status_code == 400
    detail = response.json()["detail"]
    assert "file cap of 5" in detail and "ECDAT_MAX_FILES_PER_SCAN" in detail
    # The rejected scan is kept, marked failed — it is part of the audit trail.
    statuses = db_session.scalars(sa.text("SELECT status FROM scans")).all()
    assert statuses == ["failed"]


def test_probe_only_creates_a_scan_with_no_scan_files(client, db_session) -> None:
    response = client.post(
        "/api/scans",
        json={
            "mode": "probe_only",
            "probe_targets": [{"host": "localhost", "port": 8443}],
            "data_lifetime_years": 20,
        },
    )

    assert response.status_code == 201, response.text
    scan = response.json()
    # probe_only skips staging and approval entirely (§4), so the run starts and
    # finishes inside this one request. It completes rather than hanging in
    # `running` because the network prober is not registered until step 7 — at
    # which point this scan does real work and the status still lands here.
    assert scan["status"] == "complete"
    assert scan["source_type"] == "none"
    assert scan["file_count"] == 0
    assert scan["probe_targets"] == [{"host": "localhost", "port": 8443}]
    assert db_session.scalars(sa.select(sa.func.count()).select_from(ScanFile)).one() == 0


def test_probe_only_scan_cannot_be_approved(client) -> None:
    scan = client.post(
        "/api/scans",
        json={"mode": "probe_only", "probe_targets": [{"host": "localhost", "port": 443}]},
    ).json()

    response = client.post(f"/api/scans/{scan['id']}/approve", json={"paths": []})

    assert response.status_code == 409
    assert "no files to approve" in response.json()["detail"]


def test_probe_target_cap_is_enforced(client, settings, monkeypatch) -> None:
    monkeypatch.setattr(settings, "max_probe_targets", 2)

    response = client.post(
        "/api/scans",
        json={
            "mode": "probe_only",
            "probe_targets": [{"host": f"h{i}.test", "port": 443} for i in range(3)],
        },
    )

    assert response.status_code == 400
    assert "cap of 2" in response.json()["detail"]


def test_files_mode_rejects_probe_targets(client, source_folder) -> None:
    response = client.post(
        "/api/scans",
        json={
            "mode": "files",
            "source_type": "folder",
            "source_ref": str(source_folder(1)),
            "probe_targets": [{"host": "localhost", "port": 443}],
        },
    )

    assert response.status_code == 422


def test_probe_only_rejects_a_source_ref(client, tmp_path) -> None:
    response = client.post(
        "/api/scans",
        json={
            "mode": "probe_only",
            "source_type": "folder",
            "source_ref": str(tmp_path),
            "probe_targets": [{"host": "localhost", "port": 443}],
        },
    )

    assert response.status_code == 422


def test_double_approval_replaces_the_earlier_selection(client, source_folder) -> None:
    """Approval is exactly the submitted list, so nothing stays in scope silently."""
    scan = _create_folder_scan(client, source_folder(6))
    paths = sorted(_files(client.get(f"/api/scans/{scan['id']}/files").json()["root"]))

    first = client.post(f"/api/scans/{scan['id']}/approve", json={"paths": paths[:4]})
    assert first.json()["approved_count"] == 4
    # The scan is complete now, so a second submission is refused outright.
    second = client.post(f"/api/scans/{scan['id']}/approve", json={"paths": paths[:1]})
    assert second.status_code == 409


def _files(node) -> list[str]:
    if node["type"] == "file":
        return [node["path"]]
    return [path for child in node["children"] for path in _files(child)]


# --------------------------------------------------------------------------- #
# A partial scan has to say what degraded — and keep saying it (§2)
#
# The reason is produced inside a collector, carried by the runner, stored on the
# ``scans`` row, and served by the detail endpoint. Every one of those steps can
# drop it silently, so the assertion is made at the far end.
# --------------------------------------------------------------------------- #


class TimingOutCollector(Collector):
    """A collector that spends its budget and says so, as §2 asks it to."""

    name = CollectorName.CODE
    message = "exceeded the 120s per-collector budget while running semgrep"

    def collect(self, ctx: ScanContext) -> list[RawFinding]:
        raise CollectorTimeout(self.message)


def test_a_timed_out_collectors_reason_reaches_the_scan_detail_endpoint(
    client, db_session, source_folder, approve_all_files, monkeypatch
) -> None:
    monkeypatch.setattr("app.runner.FILE_COLLECTORS", (TimingOutCollector(),))
    scan = _create_folder_scan(client, source_folder(4))

    approved = approve_all_files(scan["id"])
    assert approved["status"] == "partial"

    detail = client.get(f"/api/scans/{scan['id']}")
    assert detail.status_code == 200, detail.text
    collectors = detail.json()["diagnostics"]["collectors"]
    code = next(run for run in collectors if run["name"] == "code")

    assert code["ran"] is True
    assert code["reason"] == TimingOutCollector.message
    assert code["error"].startswith("CollectorTimeout: ")
    assert code["file_count"] == approved["approved_count"]
    # It survived the round trip through the row, not just the response object.
    db_session.expire_all()
    stored = db_session.get(Scan, UUID(scan["id"])).diagnostics
    assert stored["collectors"][0]["reason"] == TimingOutCollector.message


def test_the_approve_response_and_the_detail_endpoint_agree(
    client, source_folder, approve_all_files, monkeypatch
) -> None:
    monkeypatch.setattr("app.runner.FILE_COLLECTORS", (TimingOutCollector(),))
    scan = _create_folder_scan(client, source_folder(4))

    approved = approve_all_files(scan["id"])
    detail = client.get(f"/api/scans/{scan['id']}").json()

    assert approved["diagnostics"] == detail["diagnostics"]


def test_a_collector_the_mode_never_ran_is_reported_as_such(
    client, source_folder, approve_all_files
) -> None:
    """A ``files`` scan runs no prober, and the UI must not read that as "clean"."""
    scan = _create_folder_scan(client, source_folder(4))
    approve_all_files(scan["id"])

    collectors = client.get(f"/api/scans/{scan['id']}").json()["diagnostics"]["collectors"]
    network = next(run for run in collectors if run["name"] == "network")

    assert network["ran"] is False
    assert network["finding_count"] == 0


def test_the_detail_endpoint_carries_the_per_extension_breakdown(
    client, tmp_path, approve_all_files
) -> None:
    """"300 .go files, 0 findings, no Go rules" has to be readable off the API."""
    folder = tmp_path / "src"
    folder.mkdir()
    (folder / "app.rs").write_text("fn main() {}\n", encoding="utf-8")
    (folder / "app.go").write_text("package main\n", encoding="utf-8")
    (folder / "notes.txt").write_text("nothing\n", encoding="utf-8")

    scan = _create_folder_scan(client, folder)
    approve_all_files(scan["id"])

    extensions = {
        row["extension"]: row
        for row in client.get(f"/api/scans/{scan['id']}").json()["diagnostics"]["extensions"]
    }

    assert extensions[".rs"] == {
        "extension": ".rs",
        "approved_files": 1,
        "finding_count": 0,
        "code_scanned": True,
        "ruled": False,
    }
    assert extensions[".go"]["ruled"] is True
    assert extensions[".txt"]["code_scanned"] is False


def test_a_scan_that_has_not_run_has_no_diagnostics(client, source_folder) -> None:
    """Null, not empty. An empty object would read as "every collector was fine"."""
    scan = _create_folder_scan(client, source_folder(4))

    assert client.get(f"/api/scans/{scan['id']}").json()["diagnostics"] is None
