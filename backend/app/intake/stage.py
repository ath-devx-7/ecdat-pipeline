"""Staging — a user-named source becomes a directory on disk (SPEC.md §4 step 2).

Five source types, one output: a work directory that the surface scan walks
and that every later collector resolves approved paths against.

* ``folder``         — used in place. Nothing is copied.
* ``upload``         — already on disk: ``app/intake/upload.py`` wrote the tree
  when the browser posted it, and this only resolves and checks it.
* ``github``         — ``git clone --depth 1`` into the work root.
* ``docker_image``   — ``docker save``, then each layer tar extracted in
  manifest order into one merged tree.
* ``docker_archive`` — the same unpacking, over a ``docker save`` tar the
  browser already sent us. No daemon, no registry, no subprocess at all.

Only two of these shell out, and they are the only outbound operations the
product performs on the file side (§1): a clone of a repo the user named and a
save of an image the user named. Neither consults GitHub's API, a registry
index, or any metadata service — a clone is a clone. ``docker_archive`` is the
path for a host with no Docker daemon on it, and for an image that was saved
somewhere else and carried in: it reaches nothing at all.
"""

from __future__ import annotations

import json
import logging
import os
import re
import shutil
import subprocess
import tarfile
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse
from uuid import UUID

from app.config import Settings, get_settings
from app.intake.upload import archive_path, uploads_root
from app.models.enums import SourceType

logger = logging.getLogger(__name__)

__all__ = ["StagedSource", "StagingError", "stage_source", "work_dir_for"]

#: ``user@host:path/repo.git`` — git's scp-like syntax, which has no URL scheme.
_SCP_LIKE_REMOTE = re.compile(r"^[A-Za-z0-9._-]+@[A-Za-z0-9._-]+:[^\s]+$")
_ALLOWED_CLONE_SCHEMES = frozenset({"http", "https", "ssh", "git"})

#: OverlayFS deletion markers inside a layer tar.
_WHITEOUT_PREFIX = ".wh."


class StagingError(RuntimeError):
    """The source could not be turned into a directory. Shown to the user verbatim."""


@dataclass(frozen=True, slots=True)
class StagedSource:
    """Where the scan's files ended up."""

    work_dir: Path
    source_type: SourceType
    #: True when we created the directory, and therefore may delete it.
    ephemeral: bool


def work_dir_for(
    scan_id: UUID,
    source_type: SourceType,
    source_ref: str | None,
    settings: Settings | None = None,
) -> Path:
    """The work directory for a scan, derived rather than stored.

    ``folder`` sources live wherever the user said and ``upload`` sources under
    the upload id the browser was given; everything else is unpacked under
    ``work_root/{scan_id}``. Later steps re-derive this from the ``scans`` row
    instead of persisting a path that could go stale.
    """
    settings = settings or get_settings()
    if source_type is SourceType.FOLDER:
        if not source_ref:
            raise StagingError("A folder scan needs a source_ref naming the directory.")
        return Path(source_ref).expanduser().resolve()
    if source_type is SourceType.UPLOAD:
        if not source_ref:
            raise StagingError("An upload scan needs a source_ref naming the upload.")
        return uploads_root(settings) / str(_upload_id(source_ref))
    return (Path(settings.work_root) / str(scan_id)).resolve()


# --------------------------------------------------------------------------- #
# Entry point
# --------------------------------------------------------------------------- #


def stage_source(
    scan_id: UUID,
    source_type: SourceType,
    source_ref: str | None,
    settings: Settings | None = None,
) -> StagedSource:
    """Materialise ``source_ref`` as a directory. Raises :class:`StagingError`."""
    settings = settings or get_settings()
    if not source_ref or not source_ref.strip():
        raise StagingError(f"A {source_type.value} scan needs a source_ref.")
    source_ref = source_ref.strip()

    if source_type is SourceType.FOLDER:
        return _stage_folder(source_ref)
    if source_type is SourceType.UPLOAD:
        return _stage_upload(source_ref, settings)
    if source_type is SourceType.GITHUB:
        return _stage_github(scan_id, source_ref, settings)
    if source_type is SourceType.DOCKER_IMAGE:
        return _stage_docker_image(scan_id, source_ref, settings)
    if source_type is SourceType.DOCKER_ARCHIVE:
        return _stage_docker_archive(scan_id, source_ref, settings)
    raise StagingError(f"source_type '{source_type.value}' cannot be staged.")


# --------------------------------------------------------------------------- #
# folder
# --------------------------------------------------------------------------- #


def _stage_folder(source_ref: str) -> StagedSource:
    """Used directly — no copy. The user pointed at it; we read it where it lives."""
    path = Path(source_ref).expanduser()
    try:
        resolved = path.resolve(strict=True)
    except OSError as exc:
        raise StagingError(f"Folder not found: {path}") from exc
    if not resolved.is_dir():
        raise StagingError(f"Not a directory: {resolved}")
    return StagedSource(work_dir=resolved, source_type=SourceType.FOLDER, ephemeral=False)


# --------------------------------------------------------------------------- #
# upload
# --------------------------------------------------------------------------- #


def _upload_id(source_ref: str) -> UUID:
    """The ref is an upload id and nothing else.

    Parsing it as a UUID is the whole path check: a value that survives this
    cannot contain a separator, a ``..`` or a drive letter, so joining it onto
    the upload root can only ever name a direct child of that root.
    """
    try:
        return UUID(source_ref.strip())
    except (AttributeError, ValueError) as exc:
        raise StagingError(
            f"{source_ref!r} is not an upload id. Post the folder to /api/uploads first "
            "and use the upload_id it returns as source_ref."
        ) from exc


def _stage_upload(source_ref: str, settings: Settings) -> StagedSource:
    """Bytes the browser already sent us. Ephemeral: we wrote them, we may delete them."""
    upload_id = _upload_id(source_ref)
    destination = uploads_root(settings) / str(upload_id)
    if not destination.is_dir():
        raise StagingError(
            f"Upload {upload_id} was not found. Uploads are kept for "
            f"{settings.upload_retention_hours}h and are swept after that; post the folder "
            "again."
        )
    return StagedSource(work_dir=destination, source_type=SourceType.UPLOAD, ephemeral=True)


# --------------------------------------------------------------------------- #
# github
# --------------------------------------------------------------------------- #


def _validate_clone_url(source_ref: str) -> str:
    """Refuse anything git would read as an option or as a local path.

    A ref beginning with ``-`` is an argument, not a URL. Bare local paths and
    ``file://`` are refused too: a scan request should not be able to reach an
    arbitrary directory on the host through the clone path — that is what the
    ``folder`` source type is for, where the user states the path plainly.
    """
    if source_ref.startswith("-"):
        raise StagingError(f"Repository URL may not start with '-': {source_ref!r}")
    if _SCP_LIKE_REMOTE.match(source_ref):
        return source_ref
    scheme = urlparse(source_ref).scheme.lower()
    if scheme not in _ALLOWED_CLONE_SCHEMES:
        raise StagingError(
            f"Unsupported repository URL {source_ref!r}. Use an http(s), ssh or git "
            "URL, or scan the checkout as a 'folder' source."
        )
    return source_ref


def _stage_github(scan_id: UUID, source_ref: str, settings: Settings) -> StagedSource:
    url = _validate_clone_url(source_ref)
    destination = work_dir_for(scan_id, SourceType.GITHUB, source_ref, settings)
    _fresh_dir(destination)

    logger.info("staging scan %s: cloning %s", scan_id, url)
    _run(
        [
            "git",
            "clone",
            "--depth",
            "1",
            "--single-branch",
            "--no-tags",
            "--",
            url,
            str(destination),
        ],
        timeout=settings.git_clone_timeout_seconds,
        # Never prompt: an interactive credential prompt would hang the
        # synchronous request until the scan timeout.
        env_overrides={"GIT_TERMINAL_PROMPT": "0", "GIT_ASKPASS": "echo"},
        what=f"git clone of {url}",
    )
    return StagedSource(work_dir=destination, source_type=SourceType.GITHUB, ephemeral=True)


# --------------------------------------------------------------------------- #
# docker_image and docker_archive
# --------------------------------------------------------------------------- #


def _stage_docker_image(scan_id: UUID, source_ref: str, settings: Settings) -> StagedSource:
    """``docker save`` the image, then unpack the tar it writes."""
    if source_ref.startswith("-"):
        raise StagingError(f"Image reference may not start with '-': {source_ref!r}")

    destination = work_dir_for(scan_id, SourceType.DOCKER_IMAGE, source_ref, settings)
    _fresh_dir(destination)
    export_dir = destination.parent / f"{destination.name}.export"
    _fresh_dir(export_dir)
    archive = export_dir / "image.tar"

    try:
        logger.info("staging scan %s: docker save %s", scan_id, source_ref)
        _run(
            ["docker", "save", "--output", str(archive), "--", source_ref],
            timeout=settings.docker_save_timeout_seconds,
            what=f"docker save of {source_ref}",
        )
        _unpack_image_archive(archive, destination, source_ref, export_dir)
    finally:
        # The export is scratch: only the merged tree is scanned.
        shutil.rmtree(export_dir, ignore_errors=True)

    return StagedSource(
        work_dir=destination, source_type=SourceType.DOCKER_IMAGE, ephemeral=True
    )


def _archive_id(source_ref: str) -> UUID:
    """The ref is an archive id and nothing else — see :func:`_upload_id`."""
    try:
        return UUID(source_ref.strip())
    except (AttributeError, ValueError) as exc:
        raise StagingError(
            f"{source_ref!r} is not an image archive id. Post the tar to "
            "/api/uploads/image first and use the archive_id it returns as source_ref. "
            "An image tag names an image inside a daemon and belongs to the "
            "'docker_image' source type instead."
        ) from exc


def _stage_docker_archive(scan_id: UUID, source_ref: str, settings: Settings) -> StagedSource:
    """Unpack a ``docker save`` tar the browser already sent us.

    Identical to ``docker_image`` from the tar onwards. What it skips is the part
    before that: no daemon is contacted, so an image built elsewhere and carried
    in as a file can be scanned on a host that has no Docker on it at all.
    """
    archive_uuid = _archive_id(source_ref)
    archive = archive_path(archive_uuid, settings)
    if not archive.is_file():
        raise StagingError(
            f"Image archive {archive_uuid} was not found. Archives are kept for "
            f"{settings.upload_retention_hours}h and are swept after that; upload the tar "
            "again."
        )

    destination = work_dir_for(scan_id, SourceType.DOCKER_ARCHIVE, source_ref, settings)
    _fresh_dir(destination)
    export_dir = destination.parent / f"{destination.name}.export"
    _fresh_dir(export_dir)
    try:
        logger.info("staging scan %s: unpacking image archive %s", scan_id, archive_uuid)
        # The uploaded tar is read where it lies rather than copied into the
        # export: the user's bytes stay in one place until the sweep takes them,
        # and staging the same archive twice costs no second copy of it.
        _unpack_image_archive(archive, destination, f"archive {archive_uuid}", export_dir)
    finally:
        shutil.rmtree(export_dir, ignore_errors=True)

    return StagedSource(
        work_dir=destination, source_type=SourceType.DOCKER_ARCHIVE, ephemeral=True
    )


def _unpack_image_archive(
    archive: Path, destination: Path, label: str, export_dir: Path
) -> None:
    """An image tar to that image's filesystem, merged into ``destination``.

    The tar holds layer tars plus an index naming their order; both are opened
    here, and every extraction goes through :func:`_safe_extract` because all of
    it was built by someone else.

    Whiteout entries (``.wh.*``) are skipped, so the merged tree is the last
    layer's view of the image. Per-layer scanning — which finds a secret added in
    one layer and deleted in a later one but still present in the pulled image —
    is a roadmap item; it needs a per-layer dimension the findings schema does
    not carry yet.
    """
    unpacked = export_dir / "image"
    unpacked.mkdir(parents=True, exist_ok=True)
    try:
        with tarfile.open(archive, mode="r:*") as tar:
            _safe_extract(tar, unpacked)
    except tarfile.TarError as exc:
        raise StagingError(
            f"{label} is not a readable tar archive: {exc}. Expected the output of "
            "`docker save`."
        ) from exc

    for layer in _layer_paths(unpacked, label):
        try:
            with tarfile.open(layer, mode="r:*") as tar:
                _safe_extract(tar, destination, skip_whiteouts=True)
        except tarfile.TarError as exc:
            raise StagingError(f"A layer of {label} could not be read: {exc}") from exc


def _layer_paths(unpacked: Path, label: str) -> list[Path]:
    """Layer tars in order — bottom-most first. Order is the merge order.

    Two archive shapes reach here. ``docker save`` writes a ``manifest.json``
    naming its layers directly. An OCI archive — what ``docker buildx --output
    type=oci`` and ``skopeo copy`` write — has no such file: it has an
    ``index.json`` pointing at a manifest blob, which points at the layers. Both
    are things a person can hand us as "the tar for my image", so both are read.
    """
    if (unpacked / "manifest.json").is_file():
        return _docker_layer_paths(unpacked, label)
    if (unpacked / "index.json").is_file():
        return _oci_layer_paths(unpacked, label)
    raise StagingError(
        f"{label} holds neither a manifest.json nor an index.json, so its layer order "
        "cannot be determined. Expected the output of `docker save`, or an OCI image "
        "layout."
    )


def _docker_layer_paths(unpacked: Path, label: str) -> list[Path]:
    manifest = _read_json(unpacked / "manifest.json", label)
    if not isinstance(manifest, list) or not manifest:
        raise StagingError(f"Empty manifest.json in {label}.")
    if not isinstance(manifest[0], dict):
        raise StagingError(
            f"Malformed manifest.json in {label}: its first entry is not an object."
        )

    layers = [
        _member(unpacked, relative, label)
        for relative in manifest[0].get("Layers") or []
        if isinstance(relative, str)
    ]
    if not layers:
        raise StagingError(f"manifest.json for {label} lists no layers.")
    return layers


def _oci_layer_paths(unpacked: Path, label: str) -> list[Path]:
    """Walk ``index.json`` to a manifest blob, and that manifest to its layers.

    A multi-architecture archive's index points at another index rather than at
    a manifest, so a bounded number of those is followed. The first entry listed
    wins: which architecture a Go binary was built for does not change the
    crypto in its TLS stack, and choosing is better than refusing a tar the user
    plainly meant to scan.
    """
    document: object = _read_json(unpacked / "index.json", label)
    if not isinstance(document, dict):
        raise StagingError(f"Malformed index.json in {label}: not an object.")

    seen: set[str] = set()
    for _ in range(4):  # index → (index) → manifest; the bound stops a cycle
        entries = document.get("manifests") if isinstance(document, dict) else None
        if not isinstance(entries, list) or not entries:
            break
        digest = next(
            (
                entry["digest"]
                for entry in entries
                if isinstance(entry, dict) and isinstance(entry.get("digest"), str)
            ),
            None,
        )
        if digest is None or digest in seen:
            break
        seen.add(digest)
        document = _read_json(_blob(unpacked, digest, label), label)

    entries = document.get("layers") if isinstance(document, dict) else None
    if not isinstance(entries, list) or not entries:
        raise StagingError(
            f"The OCI index in {label} does not lead to an image manifest listing layers."
        )
    return [
        _blob(unpacked, entry["digest"], label)
        for entry in entries
        if isinstance(entry, dict) and isinstance(entry.get("digest"), str)
    ]


def _blob(unpacked: Path, digest: str, label: str) -> Path:
    """``sha256:abc…`` to ``blobs/sha256/abc…``, checked like any other member."""
    algorithm, _, value = digest.partition(":")
    if not algorithm or not value:
        raise StagingError(f"Malformed content digest in {label}: {digest!r}")
    return _member(unpacked, f"blobs/{algorithm}/{value}", label)


def _member(unpacked: Path, relative: str, label: str) -> Path:
    """A path named from inside the archive, resolved and proved to be under it."""
    root = unpacked.resolve()
    candidate = (unpacked / relative).resolve()
    if root not in candidate.parents or not candidate.is_file():
        raise StagingError(f"{label} references a file it does not contain: {relative}")
    return candidate


def _read_json(path: Path, label: str) -> object:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise StagingError(f"Unreadable {path.name} in {label}: {exc}") from exc


# --------------------------------------------------------------------------- #
# Shared helpers
# --------------------------------------------------------------------------- #


def _fresh_dir(path: Path) -> None:
    shutil.rmtree(path, ignore_errors=True)
    path.mkdir(parents=True, exist_ok=True)


def _run(
    argv: list[str],
    *,
    timeout: int,
    what: str,
    env_overrides: dict[str, str] | None = None,
) -> None:
    env = {**os.environ, **(env_overrides or {})}
    try:
        completed = subprocess.run(
            argv,
            capture_output=True,
            text=True,
            timeout=timeout,
            env=env,
            check=False,
        )
    except FileNotFoundError as exc:
        raise StagingError(f"{argv[0]} is not installed, so the {what} cannot run.") from exc
    except subprocess.TimeoutExpired as exc:
        raise StagingError(f"The {what} exceeded {timeout}s and was abandoned.") from exc
    if completed.returncode != 0:
        detail = (completed.stderr or completed.stdout or "").strip().splitlines()
        raise StagingError(
            f"The {what} failed (exit {completed.returncode}): "
            f"{detail[-1] if detail else 'no output'}"
        )


def _safe_extract(
    tar: tarfile.TarFile, destination: Path, *, skip_whiteouts: bool = False
) -> None:
    """Extract regular files and directories only, never outside ``destination``.

    A tar is attacker-controlled input — the image was built by someone else.
    Absolute paths, ``..`` traversal and every link type are dropped rather than
    sanitised: a symlink in particular would let a later layer's extraction
    write *through* the link and out of the tree, and the collectors have no use
    for links because the surface scan skips them anyway.
    """
    root = destination.resolve()
    for member in tar.getmembers():
        if not (member.isfile() or member.isdir()):
            continue  # symlink, hardlink, device, fifo
        name = member.name.replace("\\", "/").lstrip("/")
        parts = [part for part in name.split("/") if part not in ("", ".")]
        if not parts:
            continue
        if any(part == ".." for part in parts):
            logger.warning("skipping tar member escaping the work dir: %s", member.name)
            continue
        if skip_whiteouts and any(part.startswith(_WHITEOUT_PREFIX) for part in parts):
            continue
        target = root.joinpath(*parts)
        if member.isdir():
            target.mkdir(parents=True, exist_ok=True)
            continue
        target.parent.mkdir(parents=True, exist_ok=True)
        extracted = tar.extractfile(member)
        if extracted is None:
            continue
        # A later layer replacing an earlier layer's file is expected, hence 'wb'.
        with extracted, open(target, "wb") as handle:
            shutil.copyfileobj(extracted, handle)
