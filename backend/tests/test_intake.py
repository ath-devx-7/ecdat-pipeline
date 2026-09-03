"""Staging and the surface scan — SPEC.md §4 steps 2 and 3.

The surface scan is the last stage before the user grants permission, so what it
does *not* do matters as much as what it does: no file contents are read, links
are not followed out of the tree, and the file cap stops a runaway walk.
"""

from __future__ import annotations

import tarfile
from pathlib import Path
from uuid import uuid4

import pytest

from app.intake.stage import StagingError, _safe_extract, stage_source, work_dir_for
from app.intake.surface import FileCapExceeded, walk_surface
from app.models.enums import SourceType


# --------------------------------------------------------------------------- #
# Surface scan
# --------------------------------------------------------------------------- #


def test_walk_records_every_file_with_a_relative_posix_path(source_folder) -> None:
    root = source_folder(10)

    files = walk_surface(root, max_files=5000)

    assert len(files) == 10
    assert all(not item.path.startswith("/") and "\\" not in item.path for item in files)
    assert "nested/file_001.txt" in {item.path for item in files}
    assert all(item.size_bytes and item.size_bytes > 0 for item in files)


def test_walk_rejects_a_tree_over_the_file_cap(source_folder) -> None:
    root = source_folder(12)

    with pytest.raises(FileCapExceeded) as excinfo:
        walk_surface(root, max_files=10)

    message = str(excinfo.value)
    assert "10" in message and "ECDAT_MAX_FILES_PER_SCAN" in message


def test_the_cap_message_names_the_directory_responsible(tmp_path: Path) -> None:
    """A committed node_modules is the usual cause, and "exceeds 5000" does not say so."""
    (tmp_path / "app").mkdir()
    (tmp_path / "app" / "main.py").write_text("x = 1\n", encoding="utf-8")
    heavy = tmp_path / "frontend" / "node_modules"
    heavy.mkdir(parents=True)
    for index in range(40):
        (heavy / f"dep_{index:03d}.js").write_text("//\n", encoding="utf-8")

    with pytest.raises(FileCapExceeded) as excinfo:
        walk_surface(tmp_path, max_files=10)

    message = str(excinfo.value)
    assert "41 found" in message
    assert "frontend/node_modules (40 files)" in message
    assert "ECDAT_SURFACE_EXCLUDE_DIRS" in message and "node_modules" in message

    # Excluding it is what makes the same tree scannable.
    files = walk_surface(tmp_path, max_files=10, exclude_dirs=("node_modules",))
    assert [item.path for item in files] == ["app/main.py"]


def test_walk_prunes_excluded_directories(tmp_path: Path) -> None:
    (tmp_path / ".git" / "objects").mkdir(parents=True)
    (tmp_path / ".git" / "objects" / "pack").write_bytes(b"binary")
    (tmp_path / "main.py").write_text("x = 1\n", encoding="utf-8")

    files = walk_surface(tmp_path, max_files=5000, exclude_dirs=(".git",))

    assert [item.path for item in files] == ["main.py"]


def test_walk_does_not_follow_symlinks(tmp_path: Path) -> None:
    """A link would take the scan outside the tree the user is about to approve."""
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.pem").write_text("elsewhere\n", encoding="utf-8")
    inside = tmp_path / "inside"
    inside.mkdir()
    (inside / "app.py").write_text("x = 1\n", encoding="utf-8")
    try:
        (inside / "link").symlink_to(outside, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("this platform does not permit creating symlinks unprivileged")

    files = walk_surface(inside, max_files=5000)

    assert [item.path for item in files] == ["app.py"]


# --------------------------------------------------------------------------- #
# Staging
# --------------------------------------------------------------------------- #


def test_folder_staging_uses_the_directory_in_place(source_folder) -> None:
    root = source_folder(3)

    staged = stage_source(uuid4(), SourceType.FOLDER, str(root))

    assert staged.work_dir == root.resolve()
    assert staged.ephemeral is False


def test_folder_staging_reports_a_missing_directory_clearly(tmp_path: Path) -> None:
    with pytest.raises(StagingError, match="Folder not found"):
        stage_source(uuid4(), SourceType.FOLDER, str(tmp_path / "nope"))


def test_work_dir_for_non_folder_sources_is_scoped_to_the_scan(settings) -> None:
    scan_id = uuid4()

    work_dir = work_dir_for(scan_id, SourceType.GITHUB, "https://example.test/repo.git")

    assert work_dir.name == str(scan_id)
    assert work_dir.parent == Path(settings.work_root).resolve()


@pytest.mark.parametrize(
    "url",
    [
        "--upload-pack=touch /tmp/pwned",
        "/etc",
        "file:///etc",
        "C:\\Windows",
    ],
)
def test_clone_refuses_option_like_and_local_refs(url: str) -> None:
    """A clone URL is a URL. Local paths go through the 'folder' source type."""
    with pytest.raises(StagingError):
        stage_source(uuid4(), SourceType.GITHUB, url)


def test_layer_extraction_drops_traversal_and_link_members(tmp_path: Path) -> None:
    """Image layers are third-party input: nothing may land outside the work dir."""
    archive = tmp_path / "layer.tar"
    payload = tmp_path / "payload"
    payload.write_text("ok\n", encoding="utf-8")
    with tarfile.open(archive, "w") as tar:
        tar.add(payload, arcname="app/config.yaml")
        tar.add(payload, arcname="../escaped.txt")
        tar.add(payload, arcname="etc/.wh.deleted.conf")
        link = tarfile.TarInfo("app/link")
        link.type = tarfile.SYMTYPE
        link.linkname = "/etc/passwd"
        tar.addfile(link)

    destination = tmp_path / "merged"
    destination.mkdir()
    with tarfile.open(archive) as tar:
        _safe_extract(tar, destination, skip_whiteouts=True)

    written = sorted(p.relative_to(destination).as_posix() for p in destination.rglob("*") if p.is_file())
    assert written == ["app/config.yaml"]
    assert not (tmp_path / "escaped.txt").exists()
