"""The PDF report — SPEC.md §13.

The HTML is the report and the PDF is a rendering of it, so the content tests
run against the HTML on every platform. The PDF tests need WeasyPrint's native
libraries and skip, saying so, where they are not installed.
"""

from __future__ import annotations

import re
from html import unescape
from uuid import UUID

import pytest

from app.export.pdf import pdf_available, render_html, render_pdf
from app.models.enums import ScanMode, ScanStatus, SourceType
from app.models.scan import Scan

needs_weasyprint = pytest.mark.skipif(
    not pdf_available(), reason="WeasyPrint's native libraries (Pango, GObject) are not installed"
)


def text_of(html: str) -> str:
    """The rendered text: tags stripped, entities decoded (``&gt;`` is ``>`` on the page)."""
    return unescape(re.sub(r"<[^>]+>", " ", html))


@pytest.fixture
def empty_scan(db_session) -> Scan:
    scan = Scan(
        mode=ScanMode.FILES,
        source_type=SourceType.FOLDER,
        source_ref="/srv/nothing",
        data_lifetime_years=5,
        policy_version="2026.09",
        status=ScanStatus.COMPLETE,
    )
    db_session.add(scan)
    db_session.flush()
    db_session.commit()
    return scan


@pytest.fixture
def demo_report(client, demo_scan, db_session) -> str:
    scan = db_session.get(Scan, UUID(demo_scan["scan_id"]))
    return render_html(db_session, scan)


# --------------------------------------------------------------------------- #
# Content
# --------------------------------------------------------------------------- #


def test_a_report_generates_for_a_completed_demo_scan_with_every_section(demo_report) -> None:
    for heading in (
        "1. Scan and policy",
        "2. Executive summary",
        "3. Findings by wave",
        "4. Drift",
        "5. Blocked prerequisites",
        "6. Unknown findings",
        "7. Methodology and citations",
    ):
        assert heading in demo_report, heading
    text = text_of(demo_report)
    assert "Policy pack" in text and "2026.09" in text
    assert "PQC readiness" in text
    for status in ("Recommended", "Blocked", "No path", "Unknown"):
        assert status in text
    for wave in ("Wave 0", "Wave 1", "Wave 2", "Wave 3", "Verify"):
        assert wave in text


def test_the_report_contains_at_least_one_source_citation(demo_report) -> None:
    """§13's required test, and the point of the document."""
    assert "NIST SP 800-131A Rev.2" in demo_report
    assert "NIST IR 8547" in demo_report
    assert "Standards cited in this report" in demo_report


def test_every_classified_finding_row_shows_its_citation(demo_report) -> None:
    """A verdict badge is never printed without the standard beside it."""
    section = demo_report.split("<h2>3. Findings by wave</h2>", 1)[1].split("<h2>4.", 1)[0]
    cells = re.findall(r"<td class=\"verdict\">.*?</td>", section, re.S)
    assert len(cells) > 20
    for cell in cells:
        assert '<span class="badge' in cell, cell[:200]
        assert '<div class="small">' in cell, cell[:200]
        assert re.search(r"(NIST|RFC|OWASP|No entry in the policy pack)", cell), cell[:200]


def test_the_hard_parts_have_their_own_sections(demo_report) -> None:
    text = text_of(demo_report)
    # The demo has blocked key exchanges and unclassified findings; both are shown, not footnoted.
    assert "openssl>=3.5" in text
    assert "observed: nothing" in text
    assert "what the policy pack could not answer" in text
    assert "not checked" in text.lower()  # a files scan has no drift to compare


def test_a_scan_with_zero_findings_generates_a_valid_report(db_session, empty_scan) -> None:
    """§13's required test: empty is a state to render, not an error."""
    html = render_html(db_session, empty_scan)

    text = text_of(html)
    assert "no findings" in text
    assert "7. Methodology and citations" in html
    assert "No recommendation is blocked" in text
    assert "Every finding matched a policy entry" in text
    assert "—" in text  # readiness with nothing assessed is not 0%, it is undefined


def test_the_report_fetches_nothing_external(demo_report) -> None:
    """§1: a report generator is in the scan path too."""
    assert "http://" not in demo_report and "https://" not in demo_report
    assert "<link" not in demo_report and "<script" not in demo_report and "<img" not in demo_report


# --------------------------------------------------------------------------- #
# Endpoints
# --------------------------------------------------------------------------- #


def test_the_html_report_is_served(client, demo_scan) -> None:
    response = client.get(f"/api/scans/{demo_scan['scan_id']}/report.html")
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/html")
    assert "ECDAT cryptographic discovery report" in response.text


@needs_weasyprint
def test_a_demo_scan_produces_a_downloadable_pdf(client, demo_scan) -> None:
    """Build step 14's exit criterion."""
    response = client.get(f"/api/scans/{demo_scan['scan_id']}/report.pdf")

    assert response.status_code == 200, response.text[:300]
    assert response.headers["content-type"] == "application/pdf"
    assert "attachment" in response.headers["content-disposition"]
    assert response.content[:5] == b"%PDF-"
    assert len(response.content) > 10_000


@needs_weasyprint
def test_an_empty_scan_produces_a_valid_pdf(client, empty_scan) -> None:
    response = client.get(f"/api/scans/{empty_scan.id}/report.pdf")
    assert response.status_code == 200
    assert response.content[:5] == b"%PDF-"


@needs_weasyprint
def test_render_pdf_round_trips_the_html(db_session, empty_scan) -> None:
    pdf = render_pdf(render_html(db_session, empty_scan))
    assert pdf.startswith(b"%PDF-") and b"%%EOF" in pdf[-64:]


def test_when_weasyprint_is_unavailable_the_endpoint_says_so(client, demo_scan, monkeypatch) -> None:
    from app.export import pdf as pdf_module

    def unavailable(html: str) -> bytes:
        raise pdf_module.ReportUnavailable("Pango is not installed")

    monkeypatch.setattr(pdf_module, "render_pdf", unavailable)
    monkeypatch.setattr("app.api.scans.render_pdf", unavailable)

    response = client.get(f"/api/scans/{demo_scan['scan_id']}/report.pdf")

    assert response.status_code == 503
    assert "Pango" in response.json()["detail"]
    assert "report.html" in response.json()["detail"]
