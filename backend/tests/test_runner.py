"""The scan runner — SPEC.md §4 step 6, §7.

Two properties are the whole point of this module, and both are tested here
rather than in any collector:

* an unapproved path is never opened, by *any* collector, and
* a collector that raises costs its own findings and nothing else.

The second is why the run survives at all. The first is why a scan is something
a user can consent to.
"""

from __future__ import annotations

import io
from pathlib import Path
from uuid import uuid4

import pytest

from app.collectors.base import Collector, CollectorTimeout, RawFinding, ScanContext
from app.models.enums import CollectorName, ScanMode, ScanStatus, SourceLayer
from app.runner import FILE_COLLECTORS, collectors_for, run_collectors


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
