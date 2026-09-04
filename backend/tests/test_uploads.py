"""Browser folder upload — SPEC.md §4 step 2's fourth source type.

Every other intake path takes a name the user typed; this one takes bytes and a
client-supplied manifest of where to put them. So the tests here are mostly
about what is *refused*: a traversing path, a manifest that does not match the
parts, an upload over the file cap. The last one is the opposite claim — that an
upload of a directory produces exactly the tree a ``folder`` scan of the same
directory does, because everything downstream of staging assumes it.
"""

from __future__ import annotations

import json
import os
import time
from pathlib import Path
from uuid import UUID, uuid4

import pytest

from app.intake.stage import StagingError, stage_source
from app.intake.upload import sweep_uploads, uploads_root
from app.models.enums import SourceType


@pytest.fixture
def work_root(settings, tmp_path: Path, monkeypatch) -> Path:
    root = tmp_path / "work"
    monkeypatch.setattr(settings, "work_root", root)
    return root


def _post_upload(client, parts: dict[str, str], paths: list[str] | None = None):
    """POST ``{relative path: contents}`` as a multipart folder upload.

    ``paths`` overrides the manifest, which is how the mismatch and traversal
    cases are expressed: the manifest is a separate field precisely because a
    multipart body carries only leaf filenames.
    """
    manifest = list(parts) if paths is None else paths
    files = [
        ("files", (relative.rsplit("/", 1)[-1], contents.encode(), "application/octet-stream"))
        for relative, contents in parts.items()
    ]
    return client.post(
        "/api/uploads", files=files, data={"paths": json.dumps(manifest)}
    )


def _tree_paths(client, scan_id: str) -> list[str]:
    payload = client.get(f"/api/scans/{scan_id}/files").json()
    found: list[str] = []

    def walk(node: dict) -> None:
        for child in node["children"]:
            if child["type"] == "file":
                found.append(child["path"])
            else:
                walk(child)

    walk(payload["root"])
    return sorted(found)


# --------------------------------------------------------------------------- #
# The manifest is untrusted
# --------------------------------------------------------------------------- #


def test_a_traversing_path_is_refused_and_leaves_no_directory_behind(
    client, work_root
) -> None:
    """Refused, and refused *whole*: a partial tree is a wrong file list, not a short one."""
    response = _post_upload(
        client,
        {"a.txt": "kept", "b.txt": "escaping"},
        paths=["a.txt", "../../etc/shadow"],
    )

    assert response.status_code == 400
    assert "escapes the upload directory" in response.json()["detail"]
    root = uploads_root()
    assert not root.exists() or list(root.iterdir()) == []


def test_an_absolute_path_is_refused(client, work_root) -> None:
    response = _post_upload(client, {"a.txt": "x"}, paths=["/etc/shadow"])

    assert response.status_code == 400
    assert "absolute path" in response.json()["detail"]


def test_a_backslash_traversal_is_refused_too(client, work_root) -> None:
    """Both separators are separators here, so a Windows-shaped ``..`` cannot slip past."""
    response = _post_upload(client, {"a.txt": "x"}, paths=["src\\..\\..\\evil.txt"])

    assert response.status_code == 400
    assert "escapes the upload directory" in response.json()["detail"]


def test_a_manifest_that_does_not_match_the_parts_is_rejected(client, work_root) -> None:
    response = _post_upload(
        client, {"a.txt": "one", "b.txt": "two"}, paths=["only/one.txt"]
    )

    assert response.status_code == 400
    detail = response.json()["detail"]
    assert "2 file part(s)" in detail and "lists 1" in detail


def test_a_paths_field_that_is_not_a_json_array_is_rejected(client, work_root) -> None:
    response = client.post(
        "/api/uploads",
        files=[("files", ("a.txt", b"x", "application/octet-stream"))],
        data={"paths": "a.txt"},
    )

    assert response.status_code == 400
    assert "JSON array" in response.json()["detail"]


# --------------------------------------------------------------------------- #
# Caps
# --------------------------------------------------------------------------- #


def test_an_upload_over_the_file_cap_is_refused_naming_the_env_var(
    client, work_root, settings, monkeypatch
) -> None:
    monkeypatch.setattr(settings, "max_files_per_scan", 3)

    response = _post_upload(client, {f"pick/f{index}.txt": "x" for index in range(4)})

    assert response.status_code == 400
    detail = response.json()["detail"]
    assert "exceeds the per-scan cap of 3" in detail
    assert "ECDAT_MAX_FILES_PER_SCAN" in detail
    # Nothing was written: the count is known before the first byte is copied.
    root = uploads_root()
    assert not root.exists() or list(root.iterdir()) == []


def test_more_than_a_thousand_files_is_not_the_limit(client, work_root) -> None:
    """Starlette stops a multipart body at 1000 parts by default; ECDAT does not.

    A real folder passes 1000 files easily, and the default refuses it with a
    number that appears in no setting an operator can change. The parser is
    given ECDAT's own cap so that ``ECDAT_MAX_FILES_PER_SCAN`` is the number
    that decides.
    """
    response = _post_upload(client, {f"pick/f{index:05d}.txt": "x" for index in range(1100)})

    assert response.status_code == 201, response.text
    assert response.json()["file_count"] == 1100


def test_the_parsers_own_cap_still_names_the_env_var(
    client, work_root, settings, monkeypatch
) -> None:
    """Past the cap by more than the parser's slack, so the parser refuses first.

    It has to say the same thing the count check does. A caller cannot tell
    which of the two stopped them, and should not have to.
    """
    monkeypatch.setattr(settings, "max_files_per_scan", 3)

    response = _post_upload(client, {f"pick/f{index}.txt": "x" for index in range(40)})

    assert response.status_code == 400
    detail = response.json()["detail"]
    assert "ECDAT_MAX_FILES_PER_SCAN" in detail
    assert "cap of 3 files" in detail


def test_a_manifest_larger_than_a_megabyte_is_read(client, work_root) -> None:
    """The default field cap is 1 MB, and the manifest is one field holding every path.

    Sent with a deliberately wrong part count so nothing is written: what is
    being asserted is that the manifest was *parsed* — a parser that had refused
    it would answer with its own message rather than the count mismatch.
    """
    manifest = [f"pick/{'d' * 200}/f{index:05d}.txt" for index in range(6000)]
    assert len(json.dumps(manifest)) > 1024 * 1024

    response = _post_upload(client, {"pick/a.txt": "x"}, paths=manifest)

    assert response.status_code == 400
    assert "1 file part(s)" in response.json()["detail"]


def test_an_upload_over_the_byte_cap_is_refused_naming_the_env_var(
    client, work_root, settings, monkeypatch
) -> None:
    monkeypatch.setattr(settings, "max_upload_bytes", 32)

    response = _post_upload(client, {"pick/big.bin": "x" * 64})

    assert response.status_code == 400
    detail = response.json()["detail"]
    assert "total size cap" in detail
    assert "ECDAT_MAX_UPLOAD_BYTES" in detail
    root = uploads_root()
    assert not root.exists() or list(root.iterdir()) == []


# --------------------------------------------------------------------------- #
# Storing, staging, sweeping
# --------------------------------------------------------------------------- #


def test_upload_strips_the_picked_folders_name_from_every_path(client, work_root) -> None:
    """``webkitRelativePath`` leads with the picked folder; the stored tree must not."""
    response = _post_upload(
        client, {"demo/nginx/nginx.conf": "ssl;", "demo/app.py": "import ssl"}
    )

    assert response.status_code == 201, response.text
    body = response.json()
    assert body["file_count"] == 2
    root = uploads_root() / body["upload_id"]
    assert (root / "app.py").is_file()
    assert (root / "nginx" / "nginx.conf").is_file()
    assert not (root / "demo").exists()


def test_staging_an_upload_is_ephemeral_and_a_missing_one_says_so(
    client, work_root
) -> None:
    body = _post_upload(client, {"pick/a.txt": "x"}).json()

    staged = stage_source(uuid4(), SourceType.UPLOAD, body["upload_id"])

    assert staged.ephemeral is True
    assert staged.source_type is SourceType.UPLOAD
    assert staged.work_dir == uploads_root() / body["upload_id"]

    with pytest.raises(StagingError, match="was not found"):
        stage_source(uuid4(), SourceType.UPLOAD, str(uuid4()))


def test_a_source_ref_that_is_not_an_upload_id_is_refused(work_root) -> None:
    with pytest.raises(StagingError, match="is not an upload id"):
        stage_source(uuid4(), SourceType.UPLOAD, "../../../etc")


def test_the_sweep_deletes_abandoned_uploads_and_keeps_fresh_ones(
    client, work_root, settings
) -> None:
    """``ephemeral`` has to stay true for an upload nobody ever scanned."""
    stale = _post_upload(client, {"pick/old.txt": "x"}).json()["upload_id"]
    fresh = _post_upload(client, {"pick/new.txt": "x"}).json()["upload_id"]
    old_enough = time.time() - (settings.upload_retention_hours + 1) * 3600
    os.utime(uploads_root() / stale, (old_enough, old_enough))

    assert sweep_uploads(settings) == 1

    assert not (uploads_root() / stale).exists()
    assert (uploads_root() / fresh).is_dir()


def test_an_uploaded_folder_scans_to_the_same_tree_as_the_folder_itself(
    client, work_root, source_folder, approve_all_files
) -> None:
    """The point of the whole source type: downstream cannot tell the two apart."""
    folder = source_folder(6, name="picked")
    parts = {
        f"picked/{path.relative_to(folder).as_posix()}": path.read_text(encoding="utf-8")
        for path in sorted(folder.rglob("*"))
        if path.is_file()
    }

    upload = _post_upload(client, parts).json()
    uploaded = client.post(
        "/api/scans",
        json={
            "mode": "files",
            "source_type": "upload",
            "source_ref": upload["upload_id"],
            "data_lifetime_years": 20,
        },
    )
    assert uploaded.status_code == 201, uploaded.text
    direct = client.post(
        "/api/scans",
        json={
            "mode": "files",
            "source_type": "folder",
            "source_ref": str(folder),
            "data_lifetime_years": 20,
        },
    )
    assert direct.status_code == 201, direct.text

    assert uploaded.json()["file_count"] == direct.json()["file_count"] == 6
    assert _tree_paths(client, uploaded.json()["id"]) == _tree_paths(client, direct.json()["id"])

    # And the run resolves the approved paths against the upload directory.
    approved = approve_all_files(uploaded.json()["id"])
    assert approved["status"] == "complete"
    assert approved["approved_count"] == 6


def test_the_upload_id_is_a_uuid(client, work_root) -> None:
    body = _post_upload(client, {"pick/a.txt": "x"}).json()

    assert UUID(body["upload_id"])
    assert body["total_bytes"] == 1
