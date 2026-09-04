"""Request and response bodies for ``/api/scans`` (SPEC.md §4).

The cross-field rules in :class:`ScanCreate` are the ones the rest of the system
assumes: a ``probe_only`` scan has no source and a ``files`` scan has no probe
targets. Rejecting a contradictory request here is cheaper — and far clearer to
the user — than silently ignoring the field that does not apply.
"""

from __future__ import annotations

from datetime import datetime
from typing import Annotated, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from app.models.enums import CollectorName, ScanMode, ScanStatus, SourceType

__all__ = [
    "ApproveRequest",
    "ApproveResponse",
    "CbomImportResponse",
    "CollectorRunSummary",
    "DirectoryNode",
    "ExtensionCoverageView",
    "FileNode",
    "FileTreeResponse",
    "ProbeTarget",
    "ScanCreate",
    "ScanDiagnosticsView",
    "ScanResponse",
    "UploadResponse",
    "build_tree",
]


class ProbeTarget(BaseModel):
    """One entry of the prober's hard allowlist (§7.5).

    Entered explicitly by the user and never inferred from scanned files. The
    network collector in step 7 refuses any target absent from this list.
    """

    model_config = ConfigDict(extra="forbid")

    host: Annotated[str, Field(min_length=1, max_length=253)]
    port: Annotated[int, Field(ge=1, le=65535)] = 443

    @field_validator("host")
    @classmethod
    def _host_is_bare(cls, value: str) -> str:
        host = value.strip()
        if any(character in host for character in "/\\ @"):
            raise ValueError(
                f"probe target host must be a bare hostname or IP, got {value!r}"
            )
        return host


class ScanCreate(BaseModel):
    """``POST /api/scans``."""

    model_config = ConfigDict(extra="forbid", use_enum_values=False)

    mode: ScanMode
    source_type: SourceType = SourceType.NONE
    #: path, repo URL or image tag
    source_ref: str | None = None
    probe_targets: list[ProbeTarget] = Field(default_factory=list)
    #: X in Mosca's inequality — how long this data must stay confidential (§12).
    data_lifetime_years: int | None = Field(default=None, ge=0, le=100)

    @model_validator(mode="after")
    def _mode_matches_inputs(self) -> "ScanCreate":
        wants_files = self.mode in (ScanMode.FILES, ScanMode.FILES_AND_PROBE)
        wants_probe = self.mode in (ScanMode.PROBE_ONLY, ScanMode.FILES_AND_PROBE)

        if wants_files:
            if self.source_type is SourceType.NONE:
                raise ValueError(
                    f"mode '{self.mode.value}' needs a source_type of "
                    "folder, upload, github or docker_image"
                )
            if not (self.source_ref or "").strip():
                raise ValueError(f"mode '{self.mode.value}' needs a source_ref")
        else:
            if self.source_type is not SourceType.NONE:
                raise ValueError(
                    f"mode '{self.mode.value}' scans no files, so source_type must be 'none'"
                )
            if self.source_ref:
                raise ValueError(
                    f"mode '{self.mode.value}' scans no files, so source_ref must be omitted"
                )

        if wants_probe and not self.probe_targets:
            raise ValueError(
                f"mode '{self.mode.value}' needs at least one probe target — the probe "
                "host is entered explicitly and is never inferred from scanned files"
            )
        if not wants_probe and self.probe_targets:
            raise ValueError(
                f"mode '{self.mode.value}' does not probe, so probe_targets must be empty"
            )
        return self


class UploadResponse(BaseModel):
    """``POST /api/uploads`` — what the browser's folder became.

    ``upload_id`` is the ``source_ref`` of the scan that follows. The counts are
    what was actually written, not what the request declared: they are how the
    UI can say "3 412 files stored" before anyone approves a single one of them.
    """

    upload_id: UUID
    file_count: int
    total_bytes: int


class CollectorRunSummary(BaseModel):
    """One collector's contribution to a run.

    Reported per collector rather than as a single total so a ``partial`` scan
    says *which* collector fell over. "Some findings are missing" is not an
    actionable statement; "the config collector died after 0.4s" is.

    ``ran`` is false for a collector this scan's mode never called: a
    ``probe_only`` scan opens no files, and "the certificate collector found
    nothing" and "the certificate collector was not run" are different claims
    about the tree. ``reason`` is the collector's own words for the gap —
    ``error`` is the same thing with the exception class in front of it.
    """

    model_config = ConfigDict(from_attributes=True)

    name: CollectorName
    finding_count: int = 0
    duration_seconds: float = 0.0
    error: str | None = None
    ran: bool = True
    #: approved files handed to it; zero for a prober, which reads none
    file_count: int = 0
    reason: str | None = None


class ExtensionCoverageView(BaseModel):
    """Approved files of one extension against findings produced from them.

    The pair is the point. 300 approved ``.go`` files and 0 findings is either a
    codebase with no crypto in it or a scanner with no Go rules, and ``ruled``
    is the field that separates them.
    """

    model_config = ConfigDict(from_attributes=True)

    extension: str
    approved_files: int
    finding_count: int
    #: sent to Semgrep at all
    code_scanned: bool = False
    #: some rule declares a language covering it
    ruled: bool = False


class ScanDiagnosticsView(BaseModel):
    """Why a scan's result looks the way it does (§2's partial reporting)."""

    model_config = ConfigDict(from_attributes=True)

    collectors: list[CollectorRunSummary] = Field(default_factory=list)
    extensions: list[ExtensionCoverageView] = Field(default_factory=list)


class ScanResponse(BaseModel):
    """The ``scans`` row as the API presents it."""

    model_config = ConfigDict(from_attributes=True)

    id: UUID
    mode: ScanMode
    source_type: SourceType
    source_ref: str | None
    probe_targets: list[dict] | None
    data_lifetime_years: int | None
    policy_version: str | None
    status: ScanStatus
    file_count: int
    approved_count: int
    created_at: datetime | None
    completed_at: datetime | None
    #: Present once the collectors have run. ``None`` before that, and for a
    #: scan stored before this field existed — which is not the same as an empty
    #: one, so the UI must not render "nothing degraded" from a missing value.
    diagnostics: ScanDiagnosticsView | None = None


class FileNode(BaseModel):
    """A leaf of the approval tree. ``path`` is the key submitted to /approve."""

    type: Literal["file"] = "file"
    id: UUID
    name: str
    path: str
    size_bytes: int | None
    approved: bool


class DirectoryNode(BaseModel):
    type: Literal["directory"] = "directory"
    name: str
    path: str
    children: list["DirectoryNode | FileNode"] = Field(default_factory=list)
    #: Totals over the whole subtree, so per-directory toggles can show counts.
    file_count: int = 0
    size_bytes: int = 0


class FileTreeResponse(BaseModel):
    """``GET /api/scans/{id}/files`` — the surface scan, ready to render."""

    scan_id: UUID
    status: ScanStatus
    file_count: int
    approved_count: int
    root: DirectoryNode


class ApproveRequest(BaseModel):
    """``POST /api/scans/{id}/approve``. Paths exactly as the tree returned them."""

    model_config = ConfigDict(extra="forbid")

    paths: list[str] = Field(default_factory=list)


class ApproveResponse(BaseModel):
    scan_id: UUID
    status: ScanStatus
    approved_count: int
    file_count: int
    #: Observations from the collectors, which is also the number of ``findings``
    #: rows the normalizer wrote: it resolves identities without merging or
    #: dropping anything (§8).
    finding_count: int = 0
    collectors: list[CollectorRunSummary] = Field(default_factory=list)
    #: The same collector rows plus the per-extension breakdown, in the shape
    #: ``GET /api/scans/{id}`` serves them — so a caller that only ever sees the
    #: approve response reads the gap the same way the dashboard does.
    diagnostics: ScanDiagnosticsView | None = None
    #: Verdicts by outcome (§10). ``broken_now`` and ``quantum_vulnerable`` are
    #: separate keys and stay separate: they are independent classifications, and
    #: a caller that adds them together has already lost the distinction.
    verdict_counts: dict[str, int] = Field(default_factory=dict)
    #: The drift check (§9). Always present, and explicitly ``skipped`` with a
    #: reason when there was nothing to compare — the UI has to show that rather
    #: than an empty panel, because "no drift" and "not checked" are different
    #: statements about a host.
    alignment: dict = Field(default_factory=dict)
    #: Findings per migration wave (§12). Absent from this map are the findings
    #: that need no migration at all — a quantum_safe or hygiene verdict gets no
    #: wave rather than a reassuring one.
    wave_counts: dict[str, int] = Field(default_factory=dict)
    #: Recommendations by status (§11). All four keys are always present:
    #: ``blocked``, ``no_path`` and ``unknown`` are the hard part of a migration,
    #: and a dashboard that shows only ``recommended`` hides it.
    recommendation_counts: dict[str, int] = Field(default_factory=dict)


class CbomImportResponse(BaseModel):
    """``POST /api/scans/{id}/cbom`` — what the upload became (§7.6)."""

    scan_id: UUID
    status: ScanStatus
    #: the ``provenance_blobs`` row holding the upload byte for byte
    provenance_id: UUID
    #: the producer named in the document's metadata, if any
    tool: str | None = None
    component_count: int = 0
    #: findings written — one per observed use, so usually more than components
    finding_count: int = 0
    #: components that produced no finding, each with the reason — never silent
    skipped: list[str] = Field(default_factory=list)
    #: The analysis re-run over the whole scan, imported findings included.
    verdict_counts: dict[str, int] = Field(default_factory=dict)
    alignment: dict = Field(default_factory=dict)
    wave_counts: dict[str, int] = Field(default_factory=dict)
    recommendation_counts: dict[str, int] = Field(default_factory=dict)


# --------------------------------------------------------------------------- #
# Tree assembly
# --------------------------------------------------------------------------- #


def build_tree(rows) -> DirectoryNode:
    """Fold flat ``scan_files`` rows into the nested structure the UI renders.

    ``rows`` is any iterable of objects carrying ``id``, ``path``, ``size_bytes``
    and ``approved`` — the ORM rows in production, plain records in tests.
    """
    root = DirectoryNode(name="", path="")
    directories: dict[str, DirectoryNode] = {"": root}

    for row in sorted(rows, key=lambda item: item.path):
        parts = row.path.split("/")
        parent = root
        walked: list[str] = []
        for part in parts[:-1]:
            walked.append(part)
            key = "/".join(walked)
            node = directories.get(key)
            if node is None:
                node = DirectoryNode(name=part, path=key)
                directories[key] = node
                parent.children.append(node)
            parent = node

        parent.children.append(
            FileNode(
                id=row.id,
                name=parts[-1],
                path=row.path,
                size_bytes=row.size_bytes,
                approved=row.approved,
            )
        )
        # Roll the file up through every ancestor so a directory row can show
        # its own totals without the frontend walking the subtree.
        walked = []
        node = root
        node.file_count += 1
        node.size_bytes += row.size_bytes or 0
        for part in parts[:-1]:
            walked.append(part)
            node = directories["/".join(walked)]
            node.file_count += 1
            node.size_bytes += row.size_bytes or 0

    _sort_directories_first(root)
    return root


def _sort_directories_first(node: DirectoryNode) -> None:
    node.children.sort(key=lambda child: (child.type == "file", child.name))
    for child in node.children:
        if isinstance(child, DirectoryNode):
            _sort_directories_first(child)

