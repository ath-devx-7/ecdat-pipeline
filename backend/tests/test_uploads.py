"""The two browser uploads — SPEC.md §4 step 2's fourth and fifth source types.

Every other intake path takes a name the user typed; these take bytes. So the
tests here are mostly about what is *refused*: a traversing path, a manifest
that does not match the parts, an upload over a cap. The rest are the opposite
claim — that an uploaded folder produces exactly the tree a ``folder`` scan of
the same directory does, and that an uploaded ``docker save`` tar produces
exactly the tree the ``docker_image`` path would have, because everything
downstream of staging assumes it.
"""

from __future__ import annotations

import io
import json
import os
import tarfile
import time
from pathlib import Path
from uuid import UUID, uuid4

import pytest

from app.intake.stage import StagingError, stage_source
from app.intake.upload import archive_path, archives_root, sweep_uploads, uploads_root
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


# --------------------------------------------------------------------------- #
# The image archive
# --------------------------------------------------------------------------- #


def _tar(entries: dict[str, bytes]) -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as tar:
        for name, content in entries.items():
            info = tarfile.TarInfo(name)
            info.size = len(content)
            tar.addfile(info, io.BytesIO(content))
    return buffer.getvalue()


def _image_tar(files: dict[str, bytes]) -> bytes:
    """One-layer ``docker save`` output holding ``files``."""
    layer = _tar(files)
    return _tar(
        {
            "layer0/layer.tar": layer,
            "manifest.json": json.dumps([{"Layers": ["layer0/layer.tar"]}]).encode(),
        }
    )


def _post_archive(client, archive_bytes: bytes):
    return client.post(
        "/api/uploads/image",
        content=archive_bytes,
        headers={"content-type": "application/x-tar"},
    )


def test_an_image_archive_is_stored_whole_and_named_by_a_uuid(client, work_root) -> None:
    archive = _image_tar({"etc/app.conf": b"ssl;"})

    response = _post_archive(client, archive)

    assert response.status_code == 201, response.text
    body = response.json()
    assert body["total_bytes"] == len(archive)
    stored = archive_path(UUID(body["archive_id"]))
    # Stored, not read: the bytes on disk are the bytes that were sent.
    assert stored.read_bytes() == archive


def test_an_empty_archive_body_is_refused(client, work_root) -> None:
    response = _post_archive(client, b"")

    assert response.status_code == 400
    assert "empty" in response.json()["detail"]
    root = archives_root()
    assert not root.exists() or list(root.iterdir()) == []


def test_an_archive_over_the_byte_cap_is_refused_naming_the_env_var(
    client, work_root, settings, monkeypatch
) -> None:
    monkeypatch.setattr(settings, "max_image_archive_bytes", 32)

    response = _post_archive(client, b"x" * 64)

    assert response.status_code == 400
    detail = response.json()["detail"]
    assert "size cap" in detail
    assert "ECDAT_MAX_IMAGE_ARCHIVE_BYTES" in detail
    # A truncated tar is not a smaller image: nothing partial survives.
    root = archives_root()
    assert not root.exists() or list(root.iterdir()) == []


def test_the_sweep_deletes_abandoned_archives_and_keeps_fresh_ones(
    client, work_root, settings
) -> None:
    stale = _post_archive(client, _image_tar({"a": b"x"})).json()["archive_id"]
    fresh = _post_archive(client, _image_tar({"b": b"y"})).json()["archive_id"]
    old_enough = time.time() - (settings.upload_retention_hours + 1) * 3600
    os.utime(archives_root() / stale, (old_enough, old_enough))

    assert sweep_uploads(settings) == 1

    assert not (archives_root() / stale).exists()
    assert archive_path(UUID(fresh)).is_file()


def test_an_uploaded_image_scans_end_to_end_from_the_tar_alone(
    client, work_root, approve_all_files
) -> None:
    """The whole point of the source type: a tar in, the image's files out.

    Nothing about the analysis changes — the merged filesystem is a directory
    like any other by the time the surface scan walks it, so the same approval
    gate and the same collectors run over it.
    """
    archive = _image_tar(
        {
            "etc/nginx/nginx.conf": (
                b"events {}\n"
                b"http {\n"
                b"  server {\n"
                b"    listen 443 ssl;\n"
                b"    ssl_protocols TLSv1.2;\n"
                b"    ssl_ciphers AES128-SHA;\n"
                b"  }\n"
                b"}\n"
            ),
            "app/tls.py": b"import ssl\n",
        }
    )
    uploaded = _post_archive(client, archive)
    assert uploaded.status_code == 201, uploaded.text

    created = client.post(
        "/api/scans",
        json={
            "mode": "files",
            "source_type": "docker_archive",
            "source_ref": uploaded.json()["archive_id"],
            "data_lifetime_years": 20,
        },
    )
    assert created.status_code == 201, created.text
    scan = created.json()
    assert scan["status"] == "awaiting_approval"
    assert scan["file_count"] == 2

    assert _tree_paths(client, scan["id"]) == ["app/tls.py", "etc/nginx/nginx.conf"]

    approved = approve_all_files(scan["id"])
    assert approved["status"] in ("complete", "partial")
    assert approved["approved_count"] == 2
    # The config collector read the unpacked nginx.conf like any other file.
    assert approved["finding_count"] > 0


def test_a_scan_naming_an_archive_that_was_swept_fails_with_a_reason(
    client, work_root
) -> None:
    created = client.post(
        "/api/scans",
        json={
            "mode": "files",
            "source_type": "docker_archive",
            "source_ref": str(uuid4()),
            "data_lifetime_years": 20,
        },
    )

    assert created.status_code == 400
    assert "was not found" in created.json()["detail"]


def test_an_unreadable_archive_fails_the_scan_rather_than_the_process(
    client, work_root
) -> None:
    """A tar is stored without being opened, so the first read of it is at staging."""
    uploaded = _post_archive(client, b"not a tar at all")
    assert uploaded.status_code == 201, uploaded.text

    created = client.post(
        "/api/scans",
        json={
            "mode": "files",
            "source_type": "docker_archive",
            "source_ref": uploaded.json()["archive_id"],
            "data_lifetime_years": 20,
        },
    )

    assert created.status_code == 400
    assert "not a readable tar archive" in created.json()["detail"]
