"""Code collector — SPEC.md §7.1.

Real Semgrep over the committed demo sources, asserted against the
``ECDAT-EXPECT`` markers rather than hardcoded line numbers, so editing a demo
file cannot silently invalidate a test. The failure-mode tests stand a fake
runner in for the subprocess: what matters there is what the collector does
with Semgrep's answer, not Semgrep itself.
"""

from __future__ import annotations

import json
from pathlib import Path
from uuid import uuid4

import pytest

from app.collectors.base import CollectorPartial, CollectorTimeout, RawFinding, ScanContext
from app.collectors.code import (
    REDACTED,
    CodeCollector,
    SemgrepRun,
    is_code_file,
    parse_message,
    semgrep_command,
    shannon_entropy,
)
from app.config import get_settings
from app.models.enums import CollectorName, Confidence, Primitive, ScanStatus, SourceLayer
from app.runner import run_collectors

PYAPP = "pyapp/app.py"
JAVAAPP = "javaapp/HashDemo.java"
CBIN = "cbin/cryptodemo.c"

_COMMENT_STARTS = ("#", "//", "/*", "*")


def markers(text: str) -> dict[str, list[int]]:
    """``ECDAT-EXPECT: name`` → the line(s) a finding must anchor to.

    A marker on a code line anchors to that line. A marker on a comment line of
    its own anchors to the next line that is neither blank nor a comment —
    demo/README.md's convention.
    """
    lines = text.splitlines()
    found: dict[str, list[int]] = {}
    for index, line in enumerate(lines, start=1):
        if "ECDAT-EXPECT:" not in line:
            continue
        name = line.split("ECDAT-EXPECT:", 1)[1].strip().split()[0].rstrip("*/")
        stripped = line.strip()
        anchor = index
        if stripped.startswith(_COMMENT_STARTS):
            anchor = next(
                number
                for number in range(index + 1, len(lines) + 1)
                if lines[number - 1].strip()
                and not lines[number - 1].strip().startswith(_COMMENT_STARTS)
            )
        found.setdefault(name, []).append(anchor)
    return found


@pytest.fixture(scope="module")
def demo_findings(demo_dir: Path) -> list[RawFinding]:
    """One real Semgrep run over the three demo sources, shared by the module."""
    ctx = ScanContext.build(
        scan_id=uuid4(), work_dir=demo_dir, approved_paths=[PYAPP, JAVAAPP, CBIN]
    )
    return CodeCollector().collect(ctx)


@pytest.fixture(scope="module")
def demo_markers(demo_dir: Path) -> dict[str, dict[str, list[int]]]:
    return {
        path: markers((demo_dir / path).read_text(encoding="utf-8"))
        for path in (PYAPP, JAVAAPP, CBIN)
    }


def at(findings, path: str, line: int) -> list[RawFinding]:
    return [f for f in findings if f.evidence_location == f"{path}:{line}"]


def marker_line(demo_markers, path: str, name: str) -> int:
    lines = demo_markers[path][name]
    assert len(lines) == 1, (name, lines)
    return lines[0]


# --------------------------------------------------------------------------- #
# The demo Python service
# --------------------------------------------------------------------------- #


def test_the_demo_python_service_produces_md5_rsa_1024_and_ecb_at_the_marked_lines(
    demo_findings, demo_markers
) -> None:
    """§7.1's required test, against the markers in ``demo/pyapp/app.py``."""
    md5 = at(demo_findings, PYAPP, marker_line(demo_markers, PYAPP, "weak-hash-md5"))
    assert [f.algorithm_name for f in md5] == ["hashlib.md5"]
    assert md5[0].primitive is Primitive.HASH

    rsa = at(demo_findings, PYAPP, marker_line(demo_markers, PYAPP, "rsa-weak-key"))
    assert [(f.algorithm_name, f.key_size) for f in rsa] == [("RSA", 1024)]

    ecb = [
        f
        for f in at(demo_findings, PYAPP, marker_line(demo_markers, PYAPP, "aes-ecb"))
        if f.mode == "ECB"
    ]
    assert len(ecb) == 1
    assert ecb[0].algorithm_name == "algorithms.AES"
    assert ecb[0].primitive is Primitive.CIPHER


def test_every_finding_carries_the_code_layer(demo_findings) -> None:
    assert demo_findings
    for finding in demo_findings:
        assert finding.collector is CollectorName.CODE
        assert finding.source_layer is SourceLayer.SOURCE
        assert finding.evidence_raw["rule_id"].startswith("ecdat.")


def test_the_remaining_python_markers_are_found(demo_findings, demo_markers) -> None:
    sha1 = at(demo_findings, PYAPP, marker_line(demo_markers, PYAPP, "weak-hash-sha1"))
    assert [f.algorithm_name for f in sha1] == ["hashlib.sha1"]

    tdes = at(demo_findings, PYAPP, marker_line(demo_markers, PYAPP, "weak-cipher-3des"))
    assert "algorithms.TripleDES" in {f.algorithm_name for f in tdes}

    for line in demo_markers[PYAPP]["hardcoded-key"]:
        names = {f.algorithm_name for f in at(demo_findings, PYAPP, line)}
        assert "hardcoded-key-material" in names, line


def test_a_high_entropy_literal_is_reported_without_the_literal(
    demo_findings, demo_markers, demo_dir: Path
) -> None:
    """The finding says a credential-shaped string is there. It does not carry it."""
    line = marker_line(demo_markers, PYAPP, "high-entropy-literal")
    found = [
        f for f in at(demo_findings, PYAPP, line) if f.algorithm_name == "high-entropy-string-literal"
    ]
    assert len(found) == 1
    finding = found[0]
    assert finding.confidence is Confidence.MEDIUM
    assert finding.evidence_raw["shannon_entropy"] > 4.5
    assert finding.evidence_raw["literal_length"] > 20
    assert finding.evidence_raw["matched"] == REDACTED

    source_line = (demo_dir / PYAPP).read_text(encoding="utf-8").splitlines()[line - 1]
    literal = source_line.split('"')[1]
    assert literal not in json.dumps(finding.evidence_raw)

    # Byte literals are key material, and the hardcoded-key rules own them.
    for key_line in demo_markers[PYAPP]["hardcoded-key"]:
        assert not [
            f for f in at(demo_findings, PYAPP, key_line) if f.algorithm_name == "high-entropy-string-literal"
        ]
        for finding in at(demo_findings, PYAPP, key_line):
            assert finding.evidence_raw["matched"] == REDACTED


# --------------------------------------------------------------------------- #
# The demo Java service and the C source
# --------------------------------------------------------------------------- #


def test_the_demo_java_service_markers_are_found(demo_findings, demo_markers) -> None:
    md5 = at(demo_findings, JAVAAPP, marker_line(demo_markers, JAVAAPP, "weak-hash-md5"))
    assert [f.algorithm_name for f in md5] == ["MD5"]

    sha1 = at(demo_findings, JAVAAPP, marker_line(demo_markers, JAVAAPP, "weak-hash-sha1"))
    assert [f.algorithm_name for f in sha1] == ["SHA-1"]

    rsa = at(demo_findings, JAVAAPP, marker_line(demo_markers, JAVAAPP, "rsa-weak-key"))
    assert [(f.algorithm_name, f.key_size) for f in rsa] == [("RSA", 1024)]

    des = at(demo_findings, JAVAAPP, marker_line(demo_markers, JAVAAPP, "weak-cipher-des"))
    assert {(f.algorithm_name, f.mode) for f in des} == {("DES", "ECB")}
    assert all(f.evidence_raw["transformation"] == "DES/ECB/PKCS5Padding" for f in des)

    key = at(demo_findings, JAVAAPP, marker_line(demo_markers, JAVAAPP, "hardcoded-key"))
    assert "hardcoded-key-material" in {f.algorithm_name for f in key}


def test_the_demo_c_source_reaches_the_same_conclusions_as_the_binary(
    demo_findings, demo_markers
) -> None:
    """Target G's source, so the code and binary collectors can be compared."""
    md5 = at(demo_findings, CBIN, marker_line(demo_markers, CBIN, "symbol-md5"))
    assert [f.algorithm_name for f in md5] == ["MD5_Init"]

    rsa = at(demo_findings, CBIN, marker_line(demo_markers, CBIN, "symbol-rsa-keygen"))
    assert [(f.algorithm_name, f.key_size) for f in rsa] == [("RSA", 1024)]

    sha1 = at(demo_findings, CBIN, marker_line(demo_markers, CBIN, "symbol-sha1"))
    assert [f.algorithm_name for f in sha1] == ["EVP_sha1"]

    des = at(demo_findings, CBIN, marker_line(demo_markers, CBIN, "symbol-des-ecb"))
    assert [f.algorithm_name for f in des] == ["DES_ecb_encrypt"]


# --------------------------------------------------------------------------- #
# Scope
# --------------------------------------------------------------------------- #


def fake_runner(document: dict | None, exit_code: int = 0, stderr: str = ""):
    """A stand-in for the subprocess that records what it was asked to scan."""
    calls: list[list[str]] = []

    def _run(paths, work_dir, settings, timeout) -> SemgrepRun:
        calls.append(list(paths))
        return SemgrepRun(exit_code=exit_code, document=document, stderr=stderr, command=("semgrep",))

    _run.calls = calls  # type: ignore[attr-defined]
    return _run


def test_only_approved_source_files_are_handed_to_semgrep(scan_context) -> None:
    ctx = scan_context(
        {
            "src/app.py": "import hashlib\n",
            "src/notes.txt": "x\n",
            "certs/server.crt": "-----BEGIN CERTIFICATE-----\n",
            "src/secret.py": "import hashlib\n",
        },
        approved=["src/app.py", "src/notes.txt", "certs/server.crt"],
    )
    runner = fake_runner({"version": "test", "results": [], "errors": []})

    CodeCollector(runner).collect(ctx)

    assert runner.calls == [["src/app.py"]]


def test_nothing_to_scan_means_semgrep_is_never_started(scan_context) -> None:
    ctx = scan_context({"certs/server.crt": "x\n"})
    runner = fake_runner({"results": []})

    assert CodeCollector(runner).collect(ctx) == []
    assert runner.calls == []


def test_the_command_line_fetches_nothing_and_caps_memory() -> None:
    """§1's air-gap rule, spelled out on the command line."""
    settings = get_settings()
    command = semgrep_command(["a.py"], settings)

    assert "--metrics=off" in command
    assert "--disable-version-check" in command
    assert "--max-memory" in command
    assert command[command.index("--max-memory") + 1] == str(settings.semgrep_max_memory_mb)
    assert command[command.index("--config") + 1] == str(settings.semgrep_rules_path)
    assert not any(arg.startswith("p/") or arg.startswith("r/") for arg in command)
    assert command[-1] == "a.py"


# --------------------------------------------------------------------------- #
# Failure modes
# --------------------------------------------------------------------------- #


def _result(path: str, line: int, rule: str, message: str = "ecdat", **ecdat) -> dict:
    return {
        "check_id": f"backend.semgrep_rules.{rule}",
        "path": path,
        "start": {"line": line, "col": 1},
        "end": {"line": line, "col": 10},
        "extra": {"message": message, "metadata": {"ecdat": ecdat}, "severity": "WARNING"},
    }


def test_semgrep_exceeding_its_memory_limit_marks_the_scan_partial_and_keeps_findings(
    scan_context,
) -> None:
    """§7.1 / BUILD_PLAN: out of memory on one file costs that file, not the scan.

    Semgrep reports the file it gave up on in ``errors`` and finishes the rest.
    The collector keeps what it got and the runner marks the scan ``partial``
    naming the gap — never ``complete`` over a hole, never ``failed`` over one
    file.
    """
    ctx = scan_context({"a.py": "import hashlib\nhashlib.md5(b'x')\n", "big.py": "x = 1\n"})
    document = {
        "version": "test",
        "results": [
            _result("a.py", 2, "ecdat.python.weak-hash-md5", algorithm="hashlib.md5", primitive="hash", observation="hash_call")
        ],
        "errors": [
            {
                "code": 2,
                "level": "warn",
                "type": "Out of memory",
                "message": "Semgrep exceeded --max-memory 2000 MB while scanning big.py",
                "path": "big.py",
            }
        ],
    }
    collector = CodeCollector(fake_runner(document))

    with pytest.raises(CollectorPartial) as raised:
        collector.collect(ctx)
    assert [f.algorithm_name for f in raised.value.findings] == ["hashlib.md5"]
    assert "Out of memory" in str(raised.value) and "big.py" in str(raised.value)

    result = run_collectors(ctx, (collector,))

    assert result.status is ScanStatus.PARTIAL
    run = result.runs[0]
    assert run.finding_count == 1
    assert "Out of memory" in run.error
    assert [f.algorithm_name for f in result.findings] == ["hashlib.md5"]


def test_a_semgrep_that_produces_no_json_is_a_failed_collector(scan_context) -> None:
    ctx = scan_context({"a.py": "x = 1\n"})
    collector = CodeCollector(fake_runner(None, exit_code=2, stderr="boom"))

    result = run_collectors(ctx, (collector,))

    assert result.status is ScanStatus.PARTIAL
    assert "boom" in result.runs[0].error


def test_a_semgrep_that_hangs_is_a_timeout(scan_context) -> None:
    ctx = scan_context({"a.py": "x = 1\n"})

    def _hang(paths, work_dir, settings, timeout):
        raise CollectorTimeout("semgrep did not finish")

    result = run_collectors(ctx, (CodeCollector(_hang),))

    assert result.status is ScanStatus.PARTIAL
    assert "CollectorTimeout" in result.runs[0].error


# --------------------------------------------------------------------------- #
# Parsing
# --------------------------------------------------------------------------- #


def test_the_message_channel_carries_captured_values() -> None:
    assert parse_message("ecdat") == {}
    assert parse_message("ecdat|algorithm=AES|key_size=1024") == {"algorithm": "AES", "key_size": "1024"}
    assert parse_message('ecdat|algorithm="AES"') == {"algorithm": "AES"}
    # The literal is last and may contain the separator.
    assert parse_message("ecdat|literal=a|b=c") == {"literal": "a|b=c"}
    assert parse_message("something else") == {}


def test_shannon_entropy_separates_a_token_from_prose() -> None:
    assert shannon_entropy("hR7kQ2vX9pL4mN6bT8wZ3cY5dF1gJ0sA") > 4.5
    assert shannon_entropy("demo statement for the invoice") < 4.5
    assert shannon_entropy("") == 0.0


def test_code_file_detection_is_by_extension() -> None:
    assert is_code_file("src/app.py") and is_code_file("A.JAVA") and is_code_file("x/y.c")
    assert not is_code_file("certs/server.crt") and not is_code_file("bin/cryptodemo")
