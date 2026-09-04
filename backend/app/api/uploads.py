"""``POST /api/uploads`` — a folder picked in the browser, stored on this host.

The first half of a two-step flow. It exists so that ``POST /api/scans`` can stay
a JSON body with ``extra="forbid"``: a multipart scan-creation endpoint would
have to accept the whole ``ScanCreate`` shape as loose form fields and lose that.
So the bytes land here, the response names them, and the scan is created after:

    POST /api/uploads   (multipart)  →  {"upload_id": …, "file_count": …}
    POST /api/scans     {"source_type": "upload", "source_ref": <upload_id>}

The body is read through :meth:`Request.form` rather than declared as
``files: list[UploadFile] = File(...)``. The declarative form is nicer, but its
limits are Starlette's defaults — 1000 parts and a 1 MB cap on non-file fields —
and this endpoint has its own caps that are both larger and user-facing. A real
folder passes 1000 files easily, and refusing it with "Maximum number of files is
1000" would name a number that appears in no setting the operator can change.
Reading the form ourselves lets ``ECDAT_MAX_FILES_PER_SCAN`` be the number that
actually decides, and be the number in the message.

Storing is not reading (§4). This endpoint writes the tree and returns; not one
byte of it is parsed until the user has seen the file list and approved paths.
"""

from __future__ import annotations

import json
import logging

from fastapi import APIRouter, Depends, HTTPException, Request, UploadFile, status
from starlette.datastructures import UploadFile as StarletteUploadFile
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.formparsers import MultiPartException
from starlette.concurrency import run_in_threadpool

from app.config import Settings, get_settings
from app.intake.upload import UploadError, store_upload
from app.schemas.scans import UploadResponse

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/uploads", tags=["scans"])

#: Headroom over the file cap, so the parser is never the thing that refuses.
#: One part past the cap is enough to reject with our own message; the slack
#: covers the ``paths`` field and anything a future client adds beside it.
_PART_SLACK = 16

#: The ``paths`` manifest is one field holding every relative path, so it is far
#: larger than the 1 MB Starlette allows a field by default: 5000 deep paths run
#: to a couple of megabytes. Sized from the file cap rather than fixed.
_MANIFEST_BYTES_PER_FILE = 1024
_MANIFEST_FLOOR = 4 * 1024 * 1024


@router.post(
    "",
    response_model=UploadResponse,
    status_code=status.HTTP_201_CREATED,
    # Declared by hand because the body is parsed by hand — without this the
    # generated OpenAPI would show no request body at all.
    openapi_extra={
        "requestBody": {
            "required": True,
            "content": {
                "multipart/form-data": {
                    "schema": {
                        "type": "object",
                        "required": ["files", "paths"],
                        "properties": {
                            "files": {
                                "type": "array",
                                "items": {"type": "string", "format": "binary"},
                                "description": "One part per file, in manifest order.",
                            },
                            "paths": {
                                "type": "string",
                                "description": (
                                    "JSON array of relative paths, one per part, "
                                    "same order."
                                ),
                            },
                        },
                    }
                }
            },
        }
    },
)
async def create_upload(
    request: Request,
    settings: Settings = Depends(get_settings),
) -> UploadResponse:
    """Store one browser folder upload and return the id a scan can name.

    ``paths`` is a JSON array of relative paths, one per part and in the same
    order — the multipart body itself carries only leaf filenames, so the tree
    has to be stated separately. It is client-supplied and treated as such;
    ``app/intake/upload.py`` refuses anything that does not land inside the
    upload directory rather than repairing it.
    """
    files, manifest = await _read_multipart(request, settings)

    try:
        stored = await run_in_threadpool(store_upload, files, manifest, settings)
    except UploadError as exc:
        logger.warning("upload rejected: %s", exc)
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc
    except OSError as exc:
        # A name this filesystem will not take, a path past its length limit, a
        # full disk. The user can act on any of them; a 500 tells them nothing.
        logger.warning("upload could not be written: %s", exc)
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST, f"The upload could not be written: {exc}"
        ) from exc

    return UploadResponse(
        upload_id=stored.upload_id,
        file_count=stored.file_count,
        total_bytes=stored.total_bytes,
    )


async def _read_multipart(
    request: Request, settings: Settings
) -> tuple[list[UploadFile], list[str]]:
    """Parse the body under ECDAT's caps, not Starlette's."""
    try:
        form = await request.form(
            max_files=settings.max_files_per_scan + _PART_SLACK,
            max_fields=_PART_SLACK,
            max_part_size=max(
                _MANIFEST_FLOOR, settings.max_files_per_scan * _MANIFEST_BYTES_PER_FILE
            ),
        )
    except (MultiPartException, StarletteHTTPException) as exc:
        # Starlette turns its own MultiPartException into an HTTPException(400)
        # on the way out of `form()` when it is running inside an app, so both
        # are the same event and this is the only call that can raise either —
        # `_parse_manifest` runs outside this block. It raises *Starlette's*
        # HTTPException, and FastAPI's is a subclass of it, so catching
        # FastAPI's would not see it.
        #
        # Almost always the file cap: the parser stops one part past it, so the
        # count in our own message would be a lower bound rather than the truth.
        message = getattr(exc, "message", None) or getattr(exc, "detail", None) or str(exc)
        logger.warning("upload rejected by the multipart parser: %s", message)
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            f"The upload could not be read: {message} Scans run synchronously in this "
            f"prototype, so the per-scan cap of {settings.max_files_per_scan} files is a "
            "hard guard. Upload a narrower directory, or raise "
            "ECDAT_MAX_FILES_PER_SCAN if this host can afford the run.",
        ) from exc

    try:
        files = [part for part in form.getlist("files") if isinstance(part, StarletteUploadFile)]
        raw_manifest = form.get("paths")
        if not isinstance(raw_manifest, str):
            raise HTTPException(
                status.HTTP_400_BAD_REQUEST,
                "The upload needs a 'paths' field: a JSON array of relative paths, one "
                "per file part, in the same order.",
            )
        if not files:
            raise HTTPException(
                status.HTTP_400_BAD_REQUEST,
                "The upload carries no 'files' parts.",
            )
        return files, _parse_manifest(raw_manifest)
    except BaseException:
        await form.close()
        raise


def _parse_manifest(paths: str) -> list[str]:
    try:
        manifest = json.loads(paths)
    except json.JSONDecodeError as exc:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            f"The 'paths' field must be a JSON array of relative paths: {exc}",
        ) from exc
    if not isinstance(manifest, list) or not all(isinstance(item, str) for item in manifest):
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            "The 'paths' field must be a JSON array of strings, one per file part.",
        )
    return manifest
