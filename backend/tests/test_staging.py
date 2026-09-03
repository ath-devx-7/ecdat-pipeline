"""Staging's two outbound paths and the session dependency — SPEC.md §4 step 2.

``git clone`` and ``docker save`` are the only outbound operations on the file
side, and both are user-initiated (§1). Neither a network nor a Docker daemon
exists in the test environment, so the subprocess is stood in for: what is
asserted is the exact command that would run, what the collector does with its
output, and that a failure reaches the user as a :class:`StagingError` with the
tool's own last line rather than a stack trace.
"""

from __future__ import annotations

import io
import json
import subprocess
import tarfile
from pathlib import Path
from uuid import uuid4

import pytest

from app.intake import stage as stage_module
from app.intake.stage import StagingError, stage_source
from app.models.enums import SourceType


@pytest.fixture
def work_root(settings, tmp_path: Path, monkeypatch) -> Path:
    root = tmp_path / "work"
    monkeypatch.setattr(settings, "work_root", root)
    return root


class FakeRun:
    """Records every ``subprocess.run`` call and plays a scripted answer."""

    def __init__(self, behaviour=None) -> None:
        self.calls: list[dict] = []
        self.behaviour = behaviour or (lambda argv, kwargs: subprocess.CompletedProcess(argv, 0, "", ""))

    def __call__(self, argv, **kwargs):
        self.calls.append({"argv": list(argv), **kwargs})
        return self.behaviour(argv, kwargs)


@pytest.fixture
def fake_run(monkeypatch) -> FakeRun:
    runner = FakeRun()
    monkeypatch.setattr(stage_module.subprocess, "run", runner)
    return runner


# --------------------------------------------------------------------------- #
# github
# --------------------------------------------------------------------------- #


def test_a_github_source_is_a_shallow_clone_into_the_scan_work_dir(work_root, fake_run, settings) -> None:
    scan_id = uuid4()

    staged = stage_source(scan_id, SourceType.GITHUB, "https://github.com/example/repo.git")

    assert staged.ephemeral is True
    assert staged.source_type is SourceType.GITHUB
    assert staged.work_dir == (work_root / str(scan_id)).resolve()
    assert staged.work_dir.is_dir()

    assert len(fake_run.calls) == 1
    call = fake_run.calls[0]
    assert call["argv"][:7] == ["git", "clone", "--depth", "1", "--single-branch", "--no-tags", "--"]
    assert call["argv"][7] == "https://github.com/example/repo.git"
    assert call["argv"][8] == str(staged.work_dir)
    assert call["timeout"] == settings.git_clone_timeout_seconds
    # A credential prompt would hang the synchronous request; git is told not to ask.
    assert call["env"]["GIT_TERMINAL_PROMPT"] == "0"


def test_scp_like_remotes_are_accepted(work_root, fake_run) -> None:
    staged = stage_source(uuid4(), SourceType.GITHUB, "git@github.com:example/repo.git")
    assert fake_run.calls[0]["argv"][7] == "git@github.com:example/repo.git"
    assert staged.ephemeral


def test_a_failed_clone_reports_gits_last_line(work_root, monkeypatch) -> None:
    def failing(argv, kwargs):
        return subprocess.CompletedProcess(argv, 128, "", "Cloning into 'x'...\nfatal: repository not found\n")

    monkeypatch.setattr(stage_module.subprocess, "run", FakeRun(failing))

    with pytest.raises(StagingError) as raised:
        stage_source(uuid4(), SourceType.GITHUB, "https://github.com/example/missing.git")

    assert "exit 128" in str(raised.value)
    assert "repository not found" in str(raised.value)


def test_a_missing_git_is_reported_by_name(work_root, monkeypatch) -> None:
    def not_installed(argv, kwargs):
        raise FileNotFoundError(argv[0])

    monkeypatch.setattr(stage_module.subprocess, "run", FakeRun(not_installed))

    with pytest.raises(StagingError, match="git is not installed"):
        stage_source(uuid4(), SourceType.GITHUB, "https://github.com/example/repo.git")


def test_a_clone_that_hangs_is_abandoned_at_the_timeout(work_root, monkeypatch, settings) -> None:
    def hangs(argv, kwargs):
        raise subprocess.TimeoutExpired(argv, kwargs["timeout"])

    monkeypatch.setattr(stage_module.subprocess, "run", FakeRun(hangs))

    with pytest.raises(StagingError, match=f"exceeded {settings.git_clone_timeout_seconds}s"):
        stage_source(uuid4(), SourceType.GITHUB, "https://github.com/example/repo.git")


def test_an_empty_source_ref_is_refused_before_anything_runs(work_root, fake_run) -> None:
    with pytest.raises(StagingError, match="needs a source_ref"):
        stage_source(uuid4(), SourceType.GITHUB, "   ")
    assert fake_run.calls == []


def test_a_source_type_that_cannot_be_staged_is_refused(work_root, fake_run) -> None:
    with pytest.raises(StagingError, match="cannot be staged"):
        stage_source(uuid4(), SourceType.NONE, "anything")
    assert fake_run.calls == []


# --------------------------------------------------------------------------- #
# docker_image
# --------------------------------------------------------------------------- #


def _tar_bytes(entries: dict[str, bytes | None]) -> bytes:
    """A tar with ``entries``; a ``None`` value is a directory."""
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as tar:
        for name, content in entries.items():
            info = tarfile.TarInfo(name)
            if content is None:
                info.type = tarfile.DIRTYPE
                tar.addfile(info)
            else:
                info.size = len(content)
                tar.addfile(info, io.BytesIO(content))
    return buffer.getvalue()


def _image_archive(layers: list[dict[str, bytes | None]]) -> bytes:
    """What ``docker save`` writes: layer tars plus a manifest naming their order."""
    entries: dict[str, bytes | None] = {}
    names = []
    for index, layer in enumerate(layers):
        name = f"layer{index}/layer.tar"
        entries[name] = _tar_bytes(layer)
        names.append(name)
    entries["manifest.json"] = json.dumps([{"Config": "cfg.json", "Layers": names}]).encode()
    return _tar_bytes(entries)


def _docker_save_writing(archive_bytes: bytes):
    def behaviour(argv, kwargs):
        if argv[:2] == ["docker", "save"]:
            Path(argv[argv.index("--output") + 1]).write_bytes(archive_bytes)
        return subprocess.CompletedProcess(argv, 0, "", "")

    return behaviour


def test_a_docker_image_is_saved_and_its_layers_merged_in_manifest_order(
    work_root, monkeypatch, settings
) -> None:
    """Later layers win, whiteouts delete, and only the merged tree remains."""
    archive = _image_archive(
        [
            {"etc/": None, "etc/app.conf": b"v1", "etc/secret.key": b"old", "bin/tool": b"tool"},
            {"etc/app.conf": b"v2", "etc/.wh.secret.key": b"", "usr/lib/libcrypto.so.3": b"elf"},
        ]
    )
    runner = FakeRun(_docker_save_writing(archive))
    monkeypatch.setattr(stage_module.subprocess, "run", runner)
    scan_id = uuid4()

    staged = stage_source(scan_id, SourceType.DOCKER_IMAGE, "example/app:1.0")

    assert staged.ephemeral and staged.source_type is SourceType.DOCKER_IMAGE
    assert (staged.work_dir / "etc" / "app.conf").read_bytes() == b"v2"
    assert (staged.work_dir / "bin" / "tool").read_bytes() == b"tool"
    assert (staged.work_dir / "usr" / "lib" / "libcrypto.so.3").is_file()
    # The whiteout marker itself is not materialised. The file it deletes is
    # still present: per-layer deletion handling is roadmap, as the module says,
    # and this test pins the documented behaviour rather than a better one.
    assert not (staged.work_dir / "etc" / ".wh.secret.key").exists()
    assert (staged.work_dir / "etc" / "secret.key").read_bytes() == b"old"

    call = runner.calls[0]
    assert call["argv"][:3] == ["docker", "save", "--output"]
    assert call["argv"][-2:] == ["--", "example/app:1.0"]
    assert call["timeout"] == settings.docker_save_timeout_seconds
    # The export scratch space is gone; only the merged tree is scanned.
    assert not (work_root / f"{scan_id}.export").exists()


def test_a_docker_save_without_a_manifest_is_reported(work_root, monkeypatch) -> None:
    runner = FakeRun(_docker_save_writing(_tar_bytes({"layer0/layer.tar": _tar_bytes({"a": b"x"})})))
    monkeypatch.setattr(stage_module.subprocess, "run", runner)

    with pytest.raises(StagingError, match="no manifest.json"):
        stage_source(uuid4(), SourceType.DOCKER_IMAGE, "example/app:1.0")


def test_a_manifest_naming_a_missing_layer_is_reported(work_root, monkeypatch) -> None:
    archive = _tar_bytes(
        {"manifest.json": json.dumps([{"Layers": ["gone/layer.tar"]}]).encode()}
    )
    monkeypatch.setattr(stage_module.subprocess, "run", FakeRun(_docker_save_writing(archive)))

    with pytest.raises(StagingError, match="missing: gone/layer.tar"):
        stage_source(uuid4(), SourceType.DOCKER_IMAGE, "example/app:1.0")


def test_a_manifest_listing_no_layers_is_reported(work_root, monkeypatch) -> None:
    archive = _tar_bytes({"manifest.json": json.dumps([{"Layers": []}]).encode()})
    monkeypatch.setattr(stage_module.subprocess, "run", FakeRun(_docker_save_writing(archive)))

    with pytest.raises(StagingError, match="lists no layers"):
        stage_source(uuid4(), SourceType.DOCKER_IMAGE, "example/app:1.0")


def test_an_empty_manifest_is_reported(work_root, monkeypatch) -> None:
    archive = _tar_bytes({"manifest.json": b"[]"})
    monkeypatch.setattr(stage_module.subprocess, "run", FakeRun(_docker_save_writing(archive)))

    with pytest.raises(StagingError, match="Empty manifest.json"):
        stage_source(uuid4(), SourceType.DOCKER_IMAGE, "example/app:1.0")


def test_an_option_like_image_reference_is_refused(work_root, fake_run) -> None:
    with pytest.raises(StagingError, match="may not start with '-'"):
        stage_source(uuid4(), SourceType.DOCKER_IMAGE, "--rm")
    assert fake_run.calls == []


def test_a_failed_docker_save_cleans_up_its_scratch_space(work_root, monkeypatch) -> None:
    def failing(argv, kwargs):
        return subprocess.CompletedProcess(argv, 1, "", "Error response from daemon: No such image\n")

    monkeypatch.setattr(stage_module.subprocess, "run", FakeRun(failing))
    scan_id = uuid4()

    with pytest.raises(StagingError, match="No such image"):
        stage_source(scan_id, SourceType.DOCKER_IMAGE, "example/missing:1.0")

    assert not (work_root / f"{scan_id}.export").exists()


# --------------------------------------------------------------------------- #
# The session dependency
# --------------------------------------------------------------------------- #


class FakeSession:
    def __init__(self) -> None:
        self.events: list[str] = []

    def commit(self) -> None:
        self.events.append("commit")

    def rollback(self) -> None:
        self.events.append("rollback")

    def close(self) -> None:
        self.events.append("close")


def test_the_request_session_commits_on_success_and_always_closes(monkeypatch) -> None:
    from app import db

    session = FakeSession()
    monkeypatch.setattr(db, "SessionLocal", lambda: session)

    generator = db.get_session()
    assert next(generator) is session
    with pytest.raises(StopIteration):
        next(generator)

    assert session.events == ["commit", "close"]


def test_the_request_session_rolls_back_when_the_request_raises(monkeypatch) -> None:
    from app import db

    session = FakeSession()
    monkeypatch.setattr(db, "SessionLocal", lambda: session)

    generator = db.get_session()
    next(generator)
    with pytest.raises(RuntimeError, match="handler failed"):
        generator.throw(RuntimeError("handler failed"))

    assert session.events == ["rollback", "close"]
