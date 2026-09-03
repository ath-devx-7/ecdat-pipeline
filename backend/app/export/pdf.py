"""PDF report — SPEC.md §13, build step 14.

``GET /api/scans/{id}/report.pdf`` renders an HTML template through WeasyPrint.
The report is the artefact that leaves the room: it goes to a review board, a
procurement meeting, an auditor. Three decisions follow from that.

**Every verdict shows its source citation.** A report that says "RSA-1024 is
broken" is an opinion; one that says "RSA-1024 is broken — NIST SP 800-131A
Rev.2" is evidence. The citation column is never dropped to save space, and the
methodology section lists every standard the scan relied on.

**The hard parts are their own sections.** Blocked prerequisites and unknown
findings each get a heading, not a footnote, because a report that shows only
the recommended targets shows the easy half of the migration.

**The HTML is the report; the PDF is a rendering of it.** ``render_html`` builds
the whole document from the same queries the dashboard uses, and ``render_pdf``
converts it. They are separate so the report can be tested — and read — without
WeasyPrint's native libraries, which on some platforms (Windows in particular)
need Pango and GObject installed alongside Python. When they are missing the
endpoint says so, with the troubleshooting pointer, rather than failing with a
stack trace; the HTML version is served at ``report.html`` either way.
"""

from __future__ import annotations

import logging
import os
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, select_autoescape
from sqlalchemy.orm import Session

from app.api.findings import _Loaded, _alignment_view, _readiness, policy_view
from app.config import get_settings
from app.core.policy_loader import PolicyPack, get_policy
from app.core.visibility import hidden_verdicts, visible_verdict_keys
from app.models.enums import RecommendationStatus, Verdict, Wave
from app.models.scan import Scan

logger = logging.getLogger(__name__)

__all__ = [
    "ReportUnavailable",
    "WAVE_TITLES",
    "pdf_available",
    "render_html",
    "render_pdf",
    "report_context",
]

TEMPLATES = Path(__file__).resolve().parent / "templates"

WAVE_TITLES: dict[str, str] = {
    Wave.WAVE_0.value: "Wave 0 — broken today",
    Wave.WAVE_1.value: "Wave 1 — overdue, low effort",
    Wave.WAVE_2.value: "Wave 2 — overdue, high effort",
    Wave.WAVE_3.value: "Wave 3 — not yet overdue, or not harvestable",
    Wave.VERIFY.value: "Verify — confirm before planning",
}

WAVE_EXPLANATIONS: dict[str, str] = {
    Wave.WAVE_0.value: "Broken with today's computers. A now deadline, not a quantum one; Mosca's inequality is not consulted.",
    Wave.WAVE_1.value: "Quantum-vulnerable confidentiality primitives already overdue under (X + Y) − Z > 0, reachable by a configuration change or a library upgrade.",
    Wave.WAVE_2.value: "Overdue as wave 1, but the migration is a code change or a hardware swap. It starts now and finishes later; it needs budgeting, not deferring.",
    Wave.WAVE_3.value: "Quantum-vulnerable but not overdue at this data lifetime, or an authentication primitive: a signature cannot be harvested now and decrypted later, so X does not apply.",
    Wave.VERIFY.value: "Low-confidence observations and algorithms no policy entry classifies. The action is confirmation, not migration.",
}

VERDICT_TITLES: dict[str, str] = {
    Verdict.BROKEN_NOW.value: "Broken now",
    Verdict.QUANTUM_VULNERABLE.value: "Quantum-vulnerable",
    Verdict.QUANTUM_SAFE.value: "Quantum-safe",
    Verdict.HYGIENE.value: "Hygiene",
    Verdict.UNKNOWN.value: "Unknown",
}

STATUS_TITLES: dict[str, str] = {
    RecommendationStatus.RECOMMENDED.value: "Recommended",
    RecommendationStatus.BLOCKED.value: "Blocked",
    RecommendationStatus.NO_PATH.value: "No path",
    RecommendationStatus.UNKNOWN.value: "Unknown",
}


class ReportUnavailable(RuntimeError):
    """WeasyPrint's native libraries are not loadable here. The HTML report still is."""


# --------------------------------------------------------------------------- #
# Context
# --------------------------------------------------------------------------- #


def _describe(finding) -> str:
    base = finding.algorithm_family or finding.algorithm_name
    parts = [base]
    if finding.key_size:
        parts.append(f"{finding.key_size}-bit")
    if finding.mode:
        parts.append(finding.mode)
    if finding.protocol_version and str(base).upper().startswith(("TLS", "SSL")):
        parts.append(finding.protocol_version)
    return " ".join(parts)


def report_context(session: Session, scan: Scan, policy: PolicyPack | None = None) -> dict[str, Any]:
    """Everything the template renders, from the same queries the dashboard uses."""
    pack = policy or get_policy()
    loaded = _Loaded(session, scan)
    readiness = _readiness(loaded)
    alignment = _alignment_view(session, scan)

    rows: list[dict[str, Any]] = []
    hidden = hidden_verdicts()
    for finding in loaded.findings:
        verdict = loaded.verdicts.get(finding.id)
        if verdict is not None and verdict.verdict in hidden:
            continue
        score = loaded.scores.get(finding.id)
        recommendations = loaded.recommendations.get(finding.id, [])
        rows.append(
            {
                "finding": finding,
                "label": _describe(finding),
                "verdict": verdict,
                "verdict_title": VERDICT_TITLES.get(verdict.verdict.value, "") if verdict else "",
                "score": score,
                "recommendations": recommendations,
            }
        )

    waves: dict[str, list[dict[str, Any]]] = {wave.value: [] for wave in Wave}
    for row in rows:
        if row["score"] is not None:
            waves[row["score"].wave.value].append(row)
    for items in waves.values():
        items.sort(
            key=lambda row: (
                -(row["score"].urgency_years if row["score"].urgency_years is not None else -10**6),
                row["finding"].evidence_location or "",
            )
        )

    blocked = [
        {"row": row, "recommendation": rec}
        for row in rows
        for rec in row["recommendations"]
        if rec.status is RecommendationStatus.BLOCKED
    ]
    unknown_verdicts = [row for row in rows if row["verdict"] is not None and row["verdict"].verdict is Verdict.UNKNOWN]
    unknown_advice = [
        {"row": row, "recommendation": rec}
        for row in rows
        for rec in row["recommendations"]
        if rec.status is RecommendationStatus.UNKNOWN
    ]
    no_path = [
        {"row": row, "recommendation": rec}
        for row in rows
        for rec in row["recommendations"]
        if rec.status is RecommendationStatus.NO_PATH
    ]

    # Every standard the scan leaned on, with how often, for the methodology section.
    citations: Counter[str] = Counter()
    for verdict in loaded.verdicts.values():
        if verdict.rule_id and verdict.source_citation:
            citations[verdict.source_citation] += 1
    for recs in loaded.recommendations.values():
        for rec in recs:
            if rec.status is not RecommendationStatus.UNKNOWN and rec.source_citation:
                citations[rec.source_citation] += 1
    pack_citations = sorted({rule.source for rule in pack.algorithms} | {target.source for target in pack.pqc_targets})

    verdict_counts = {key: 0 for key in visible_verdict_keys()}
    for verdict in loaded.verdicts.values():
        if verdict.verdict.value in verdict_counts:
            verdict_counts[verdict.verdict.value] += 1
    wave_counts = {wave: len(items) for wave, items in waves.items()}
    status_counts = {s.value: 0 for s in RecommendationStatus}
    for recs in loaded.recommendations.values():
        for rec in recs:
            status_counts[rec.status.value] += 1

    return {
        "scan": scan,
        "generated_at": datetime.now(timezone.utc),
        "policy": policy_view(pack),
        "finding_count": len(loaded.all_findings),
        "hidden_count": len(loaded.all_findings) - len(rows),
        "readiness": readiness,
        "verdict_counts": verdict_counts,
        "verdict_titles": VERDICT_TITLES,
        "wave_counts": wave_counts,
        "wave_titles": WAVE_TITLES,
        "wave_explanations": WAVE_EXPLANATIONS,
        "waves": waves,
        "unscored": sum(1 for row in rows if row["score"] is None),
        "status_counts": status_counts,
        "status_titles": STATUS_TITLES,
        "alignment": alignment,
        "blocked": blocked,
        "no_path": no_path,
        "unknown_verdicts": unknown_verdicts,
        "unknown_advice": unknown_advice,
        "citations": citations.most_common(),
        "pack_citations": pack_citations,
        "z_years_used": loaded.z_years_used(),
        "y_years": pack.version.y_years_default,
    }


# --------------------------------------------------------------------------- #
# Rendering
# --------------------------------------------------------------------------- #


_environment: Environment | None = None


def _env() -> Environment:
    global _environment
    if _environment is None:
        _environment = Environment(
            loader=FileSystemLoader(str(TEMPLATES)),
            autoescape=select_autoescape(["html"]),
            trim_blocks=True,
            lstrip_blocks=True,
        )
    return _environment


def render_html(session: Session, scan: Scan, policy: PolicyPack | None = None) -> str:
    """The report as a self-contained HTML document. Inline CSS, no external assets (§1)."""
    return _env().get_template("report.html").render(**report_context(session, scan, policy))


def _import_weasyprint():
    settings = get_settings()
    if settings.weasyprint_dll_directories and "WEASYPRINT_DLL_DIRECTORIES" not in os.environ:
        os.environ["WEASYPRINT_DLL_DIRECTORIES"] = settings.weasyprint_dll_directories
    try:
        from weasyprint import HTML  # noqa: PLC0415 - deliberately lazy
    except OSError as exc:
        raise ReportUnavailable(
            "WeasyPrint could not load its native libraries (Pango, GObject, HarfBuzz). "
            "Install them for this platform, or point ECDAT_WEASYPRINT_DLL_DIRECTORIES at "
            "a directory holding them. The HTML report is available at report.html. "
            f"Detail: {exc}"
        ) from exc
    return HTML


def pdf_available() -> bool:
    try:
        _import_weasyprint()
    except ReportUnavailable:
        return False
    return True


def render_pdf(html: str) -> bytes:
    """Convert the HTML report to PDF. Raises :class:`ReportUnavailable` when it cannot."""
    HTML = _import_weasyprint()
    # base_url is a directory with nothing in it: the template references no
    # external resource, and a report generator that fetched one would be a
    # network call in the scan path (§1).
    return HTML(string=html, base_url=str(TEMPLATES)).write_pdf()
