"""The scan runner — SPEC.md §4 step 6, §7.

Two properties are the whole point of this module, and both are tested here
rather than in any collector:

* an unapproved path is never opened, by *any* collector, and
* a collector that raises costs its own findings and nothing else.

The second is why the run survives at all. The first is why a scan is something
a user can consent to.

A third follows from the second: ``partial`` has to say *what* degraded. The
diagnostics tests below hold the runner to that — which collector stopped and
why, which one was never called at all, and how many approved files of each
extension produced how many findings.
"""

from __future__ import annotations

import io
from pathlib import Path
from uuid import uuid4

import pytest

from app.collectors.base import Collector, CollectorTimeout, RawFinding, ScanContext
from app.models.enums import CollectorName, ScanMode, ScanStatus, SourceLayer
from app.runner import (
    FILE_COLLECTORS,
    PROBE_COLLECTORS,
    collectors_for,
    extension_coverage,
    run_collectors,
)


class ExplodingCollector(Collector):
    """Stands in for a collector meeting input its parser was not written for."""

    name = CollectorName.CODE

    def collect(self, ctx: ScanContext) -> list[RawFinding]:
        raise RuntimeError("semgrep died holding the door open")


class QuietCollector(Collector):
    name = CollectorName.BINARY

    def collect(self, ctx: ScanContext) -> list[RawFinding]:
        return [
            RawFinding(
                collector=self.name,
                algorithm_name="MD5",
                source_layer=SourceLayer.ARTIFACT,
                evidence_location="bin/app:0",
            )
        ]


# --------------------------------------------------------------------------- #
# Survivability
# --------------------------------------------------------------------------- #


def test_a_collector_that_raises_returns_nothing_and_marks_the_scan_partial(
    scan_context,
) -> None:
    ctx = scan_context({"app.py": "x = 1\n"})

    result = run_collectors(ctx, (ExplodingCollector(), QuietCollector()))

    failed = next(run for run in result.runs if run.name is CollectorName.CODE)
    assert failed.finding_count == 0
    assert failed.error == "RuntimeError: semgrep died holding the door open"
    assert result.status is ScanStatus.PARTIAL

    # And the other collector's work survives it, which is the reason for the rule.
    survivor = next(run for run in result.runs if run.name is CollectorName.BINARY)
    assert survivor.finding_count == 1
    assert [finding.algorithm_name for finding in result.findings] == ["MD5"]


def test_a_clean_run_is_complete(scan_context) -> None:
    result = run_collectors(scan_context({"app.py": "x = 1\n"}), (QuietCollector(),))

    assert result.status is ScanStatus.COMPLETE
    assert result.failures == ()


def test_a_collector_that_runs_out_of_budget_is_survivable_too(scan_context) -> None:
    """A timeout is a failure like any other: partial, named, and not fatal (§2)."""

    class SlowCollector(Collector):
        name = CollectorName.NETWORK

        def collect(self, ctx: ScanContext) -> list[RawFinding]:
            raise CollectorTimeout("exceeded the 120s per-collector budget")

    result = run_collectors(scan_context({}), (SlowCollector(), QuietCollector()))

    assert result.status is ScanStatus.PARTIAL
    assert "CollectorTimeout" in result.failures[0].error
    assert len(result.findings) == 1


def test_each_collector_gets_its_own_budget(scan_context) -> None:
    """One slow collector must not spend the next one's time."""
    starts: list[float] = []

    class Recorder(Collector):
        name = CollectorName.CERTS

        def collect(self, ctx: ScanContext) -> list[RawFinding]:
            starts.append(ctx.elapsed_seconds())
            return []

    ctx = scan_context({}, collector_timeout_seconds=120)
    run_collectors(ctx, (Recorder(), Recorder()))

    assert all(elapsed < 1.0 for elapsed in starts)


# --------------------------------------------------------------------------- #
# Scope — the approval gate
# --------------------------------------------------------------------------- #


def test_no_collector_ever_opens_an_unapproved_path(
    scan_context, weak_cert_pem, demo_dir, monkeypatch
) -> None:
    """The gate holds across every registered collector at once.

    ``io.open`` is where both ``open()`` and ``Path.open()`` end up, and crossplane
    reads the nginx file through it too — so this sees every read any collector
    makes, including the ones inside a third-party parser.
    """
    nginx = (demo_dir / "weak-nginx" / "nginx.conf").read_text(encoding="utf-8")
    ctx = scan_context(
        {
            "approved/server.crt": weak_cert_pem,
            "approved/nginx.conf": nginx,
            "secret/private.crt": weak_cert_pem,
            "secret/nginx.conf": nginx,
            "secret/id_rsa": "-----BEGIN RSA PRIVATE KEY-----\nnope\n",
        },
        approved=["approved/server.crt", "approved/nginx.conf"],
    )

    opened: list[str] = []
    real_open = io.open

    def _tracking_open(file, *args, **kwargs):
        opened.append(str(file))
        return real_open(file, *args, **kwargs)

    monkeypatch.setattr(io, "open", _tracking_open)
    monkeypatch.setattr("builtins.open", _tracking_open)

    result = run_collectors(ctx, FILE_COLLECTORS)

    assert result.findings, "the approved files were scanned"
    # Prove the instrumentation sees reads at all before trusting its silence —
    # an empty list would satisfy the assertion below for the wrong reason.
    assert any(path.endswith("approved/nginx.conf") for path in _posix(opened))
    assert any(path.endswith("approved/server.crt") for path in _posix(opened))
    assert not any("secret" in path for path in _posix(opened))


def _posix(paths: list[str]) -> list[str]:
    return [Path(path).as_posix() for path in paths]


def test_a_path_escaping_the_work_directory_is_refused(scan_context, tmp_path) -> None:
    """An approved path is relative to the work dir, and only reaches inside it."""
    outside = tmp_path / "outside.crt"
    outside.write_text("-----BEGIN CERTIFICATE-----\n", encoding="utf-8")
    ctx = scan_context({"inside.txt": "x\n"}, approved=["../outside.crt", "inside.txt"])

    assert [relative for relative, _ in ctx.iter_files()] == ["inside.txt"]


def test_a_missing_approved_path_is_skipped_rather_than_raising(scan_context) -> None:
    ctx = scan_context({"present.txt": "x\n"}, approved=["present.txt", "deleted.txt"])

    assert [relative for relative, _ in ctx.iter_files()] == ["present.txt"]


# --------------------------------------------------------------------------- #
# Registry
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("mode", "reads_files"),
    [
        (ScanMode.FILES, True),
        (ScanMode.FILES_AND_PROBE, True),
        # Steps 2-6 of the lifecycle are skipped entirely in probe_only (§4), so
        # there is no approved path list for a file collector to read.
        (ScanMode.PROBE_ONLY, False),
    ],
)
def test_the_registry_matches_the_mode(mode: ScanMode, reads_files: bool) -> None:
    collectors = collectors_for(mode)

    assert (set(FILE_COLLECTORS) <= set(collectors)) is reads_files


def test_the_context_carries_the_probe_target_allowlist() -> None:
    """§7.5's allowlist reaches the collector as data, not as a lookup it performs."""
    targets = ({"host": "localhost", "port": 8443},)
    ctx = ScanContext.build(scan_id=uuid4(), work_dir=Path("."), probe_targets=targets)

    assert ctx.probe_targets == targets


# --------------------------------------------------------------------------- #
# Diagnostics — why the result looks the way it does (§2)
# --------------------------------------------------------------------------- #


def test_a_failed_collector_reports_its_reason_without_the_exception_class(
    scan_context,
) -> None:
    """`error` is for a log; `reason` is what a person reads off a banner."""
    ctx = scan_context({"app.py": "x = 1\n"})

    result = run_collectors(ctx, (ExplodingCollector(), QuietCollector()))
    runs = {run.name: run for run in result.diagnostics.collectors}

    assert runs[CollectorName.CODE].reason == "semgrep died holding the door open"
    assert runs[CollectorName.CODE].error.startswith("RuntimeError: ")
    assert runs[CollectorName.BINARY].reason is None


def test_a_timed_out_collector_keeps_its_budget_message(scan_context) -> None:
    class SlowCollector(Collector):
        name = CollectorName.NETWORK

        def collect(self, ctx: ScanContext) -> list[RawFinding]:
            raise CollectorTimeout("exceeded the 120s per-collector budget while probing")

    result = run_collectors(scan_context({}), (SlowCollector(),))
    run = next(r for r in result.diagnostics.collectors if r.name is CollectorName.NETWORK)

    assert run.ran is True
    assert run.reason == "exceeded the 120s per-collector budget while probing"


def test_a_collector_the_mode_never_called_is_listed_as_not_run(scan_context) -> None:
    """"Found nothing" and "was not run" are different claims about the tree."""
    ctx = scan_context({"app.py": "x = 1\n"})

    result = run_collectors(ctx, (QuietCollector(),))
    runs = {run.name: run for run in result.diagnostics.collectors}

    assert set(runs) == {collector.name for collector in FILE_COLLECTORS + PROBE_COLLECTORS}
    assert runs[CollectorName.BINARY].ran is True
    for name in (CollectorName.CERTS, CollectorName.CONFIG, CollectorName.NETWORK):
        assert runs[name].ran is False
        assert runs[name].finding_count == 0
        assert runs[name].reason is None


def test_a_collector_records_how_many_files_it_was_handed(scan_context) -> None:
    ctx = scan_context({"a.py": "x = 1\n", "b.go": "package main\n", "c.txt": "x\n"})

    result = run_collectors(ctx, (QuietCollector(),))
    runs = {run.name: run for run in result.diagnostics.collectors}

    assert runs[CollectorName.BINARY].file_count == 3
    # A prober reads no files; claiming it was handed three would be a number
    # that says nothing about what it did.
    assert runs[CollectorName.NETWORK].file_count == 0


def test_the_extension_breakdown_pairs_approved_files_against_findings() -> None:
    """The pair is the point: 3 .go files and 0 findings, with no Go rules, is readable."""
    approved = ["a.py", "b.py", "x.go", "y.go", "z.go", "notes.txt"]
    findings = [
        RawFinding(
            collector=CollectorName.CODE,
            algorithm_name="hashlib.md5",
            source_layer=SourceLayer.SOURCE,
            evidence_location="a.py:3",
        ),
        RawFinding(
            collector=CollectorName.NETWORK,
            algorithm_name="TLSv1",
            source_layer=SourceLayer.LIVE,
            # A probe finding is host:port and belongs to no extension.
            evidence_location="localhost:8443",
        ),
    ]

    rows = {row.extension: row for row in extension_coverage(approved, findings)}

    assert (rows[".go"].approved_files, rows[".go"].finding_count) == (3, 0)
    assert (rows[".py"].approved_files, rows[".py"].finding_count) == (2, 1)
    assert rows[".txt"].approved_files == 1
    # Ordered by approved files descending — the biggest silence sorts first.
    assert [row.extension for row in extension_coverage(approved, findings)][0] == ".go"


def test_the_extension_breakdown_says_which_extensions_have_rules_behind_them() -> None:
    rows = {row.extension: row for row in extension_coverage(["a.go", "b.rs", "c.txt"], [])}

    assert (rows[".go"].code_scanned, rows[".go"].ruled) == (True, True)
    # Sent to semgrep, matched against nothing — the gap this makes visible.
    assert (rows[".rs"].code_scanned, rows[".rs"].ruled) == (True, False)
    assert (rows[".txt"].code_scanned, rows[".txt"].ruled) == (False, False)


def test_a_probe_finding_is_not_filed_under_a_port_shaped_extension() -> None:
    findings = [
        RawFinding(
            collector=CollectorName.NETWORK,
            algorithm_name="TLSv1",
            source_layer=SourceLayer.LIVE,
            evidence_location="demo.test:8443",
        )
    ]

    assert extension_coverage([], findings) == ()
