"""Code collector — SPEC.md §7.1.

Real Semgrep over the committed demo sources, asserted against the
``ECDAT-EXPECT`` markers rather than hardcoded line numbers, so editing a demo
file cannot silently invalidate a test. The failure-mode tests stand a fake
runner in for the subprocess: what matters there is what the collector does
with Semgrep's answer, not Semgrep itself.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from uuid import uuid4

import pytest
import yaml

from app.collectors.base import CollectorPartial, CollectorTimeout, RawFinding, ScanContext
from app.collectors.code import (
    CODE_EXTENSIONS,
    REDACTED,
    CodeCollector,
    SemgrepRun,
    is_code_file,
    parse_message,
    rule_languages,
    ruled_extensions,
    semgrep_command,
    shannon_entropy,
    validate_rule_coverage,
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


# --------------------------------------------------------------------------- #
# Inventory, not judgement
# --------------------------------------------------------------------------- #


JAVA_STRONG = """
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.Signature;
import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.Mac;

public class Strong {
    static void run() throws Exception {
        MessageDigest sha = MessageDigest.getInstance("SHA-256");
        Mac mac = Mac.getInstance("HmacSHA256");
        Cipher aes = Cipher.getInstance("AES/GCM/NoPadding");
        Signature sig = Signature.getInstance("SHA256withRSA");
        KeyAgreement ka = KeyAgreement.getInstance("ECDH");
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
    }
}
"""

PYTHON_STRONG = """
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa, ec

def run(key, iv, data):
    digest = hashlib.sha256(data).hexdigest()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    signing = rsa.generate_private_key(public_exponent=65537, key_size=4096)
    agreement = ec.generate_private_key(ec.SECP256R1())
    return digest, cipher, signing, agreement
"""

ECB_ONLY = (
    "from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes\n"
    "def f(k):\n    return Cipher(algorithms.AES(k), modes.ECB())\n"
)


def test_strong_algorithms_are_inventoried_and_left_for_the_policy_engine(scan_context) -> None:
    """The rules record what they see. An RSA-2048 key is a quantum-vulnerable asset the
    roadmap needs even though nothing about it is broken today, and SHA-256 is a
    quantum-safe asset the readiness percentage needs as a numerator."""
    ctx = scan_context({"Strong.java": JAVA_STRONG, "strong.py": PYTHON_STRONG})

    findings = CodeCollector().collect(ctx)
    java = {f.algorithm_name: f for f in findings if f.evidence_location.startswith("Strong.java")}
    python = {f.algorithm_name: f for f in findings if f.evidence_location.startswith("strong.py")}

    assert java["SHA-256"].primitive is Primitive.HASH
    assert java["HmacSHA256"].primitive is Primitive.HASH
    assert (java["AES"].mode, java["AES"].primitive) == ("GCM", Primitive.CIPHER)
    assert java["AES"].evidence_raw["transformation"] == "AES/GCM/NoPadding"
    assert java["SHA256withRSA"].primitive is Primitive.SIGNATURE
    assert java["ECDH"].primitive is Primitive.KEY_EXCHANGE
    assert (java["RSA"].key_size, java["RSA"].primitive) == (2048, Primitive.UNKNOWN)

    assert python["hashlib.sha256"].primitive is Primitive.HASH
    assert (python["algorithms.AES"].mode, python["algorithms.AES"].primitive) == (None, Primitive.CIPHER)
    assert python["RSA"].key_size == 4096
    assert python["SECP256R1"].evidence_raw["observation"] == "ec_keygen"
    # Nothing here is a hardcoded key or an ECB use.
    assert not [f for f in findings if f.mode == "ECB"]
    assert not [f for f in findings if f.algorithm_name == "hardcoded-key-material"]


def test_an_ecb_use_is_recorded_once_with_its_mode(scan_context) -> None:
    """`Cipher(algorithms.AES(k), modes.ECB())` is one use: AES-ECB, not AES beside AES-ECB."""
    ctx = scan_context({"ecb.py": ECB_ONLY})

    findings = [f for f in CodeCollector().collect(ctx) if f.algorithm_name == "algorithms.AES"]

    assert [(f.mode, f.evidence_raw["observation"]) for f in findings] == [("ECB", "ecb_mode")]


# --------------------------------------------------------------------------- #
# Language coverage — what is scanned against what is ruled on
#
# The gap is deliberate (CODE_EXTENSIONS is wider than the rule file) and the
# check is a warning rather than a failure. What these assert is that the gap is
# *named*: a language whose rules are dropped must not go quiet.
# --------------------------------------------------------------------------- #


def test_the_shipped_rules_cover_the_five_languages_they_claim_to() -> None:
    assert rule_languages(get_settings().semgrep_rules_path) >= {
        "python",
        "java",
        "c",
        "go",
        "js",
        "ts",
    }
    assert ruled_extensions() >= {".py", ".java", ".c", ".h", ".go", ".js", ".jsx", ".ts", ".tsx"}


def test_an_extension_with_no_rule_behind_it_is_named_in_a_warning(caplog) -> None:
    """§7.1: the wider list is the design, so this warns and never raises."""
    with caplog.at_level(logging.WARNING, logger="app.collectors.code"):
        uncovered = validate_rule_coverage()

    assert set(uncovered) <= CODE_EXTENSIONS
    assert ".rs" in uncovered and ".rb" in uncovered  # nothing rules on these yet
    assert ".go" not in uncovered and ".ts" not in uncovered
    message = "\n".join(record.getMessage() for record in caplog.records)
    for extension in uncovered:
        assert extension in message


def test_dropping_a_language_from_the_rules_widens_the_reported_gap(tmp_path: Path) -> None:
    """The check reads the rule file, so removing Go's rules re-opens .go visibly."""
    document = yaml.safe_load(get_settings().semgrep_rules_path.read_text(encoding="utf-8"))
    document["rules"] = [rule for rule in document["rules"] if "go" not in rule["languages"]]
    trimmed = tmp_path / "trimmed.yaml"
    trimmed.write_text(yaml.safe_dump(document, sort_keys=False), encoding="utf-8")

    assert ".go" not in ruled_extensions(trimmed)
    assert ".go" in validate_rule_coverage(trimmed)


def test_a_language_key_the_map_does_not_know_is_reported_rather_than_ignored(
    tmp_path: Path, caplog
) -> None:
    """It covers nothing as far as the check can tell, which is worth saying once."""
    path = tmp_path / "rules.yaml"
    path.write_text(
        yaml.safe_dump({"rules": [{"id": "x", "languages": ["ocaml"], "pattern": "x"}]}),
        encoding="utf-8",
    )

    with caplog.at_level(logging.WARNING, logger="app.collectors.code"):
        validate_rule_coverage(path)

    assert "ocaml" in "\n".join(record.getMessage() for record in caplog.records)


def test_an_unreadable_rule_file_does_not_stop_the_check(tmp_path: Path) -> None:
    assert rule_languages(tmp_path / "missing.yaml") == set()


# --------------------------------------------------------------------------- #
# Go
#
# Each block is a fixture that must match beside a near-miss that must not. The
# near-misses are the point: a rule that fires on `tls.VersionTLS12` in a version
# comparison reports a floor the server never declared.
# --------------------------------------------------------------------------- #

GO_WEAK = """
package main

import (
\t"crypto/des"
\t"crypto/dsa"
\t"crypto/ecdsa"
\t"crypto/ed25519"
\t"crypto/elliptic"
\t"crypto/md5"
\t"crypto/rand"
\t"crypto/rc4"
\t"crypto/rsa"
\t"crypto/sha1"
\t"crypto/tls"
)

func weak(data []byte, key []byte) {
\th := md5.New()
\ts := sha1.Sum(data)
\tb, _ := des.NewCipher(key)
\tt, _ := des.NewTripleDESCipher(key)
\tr, _ := rc4.NewCipher(key)
\trk, _ := rsa.GenerateKey(rand.Reader, 1024)
\tek, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
\tpub, priv, _ := ed25519.GenerateKey(rand.Reader)
\tvar params dsa.Parameters
\tdsa.GenerateParameters(&params, rand.Reader, dsa.L1024N160)
\tcfg := &tls.Config{
\t\tMinVersion: tls.VersionTLS10,
\t\tCipherSuites: []uint16{
\t\t\ttls.TLS_RSA_WITH_AES_128_CBC_SHA,
\t\t},
\t}
\t_ = h; _ = s; _ = b; _ = t; _ = r; _ = rk; _ = ek; _ = pub; _ = priv; _ = cfg
}
"""

GO_NEAR_MISS = """
package main

import (
\t"crypto/tls"
\t"fmt"
)

type md5 struct{ n int }

func (m md5) New() int { return m.n }

func nearMiss(state *tls.ConnectionState) {
\tlocal := md5{n: 1}
\t_ = local.New()
\tif state.Version < tls.VersionTLS12 {
\t\tfmt.Println("old", tls.TLS_RSA_WITH_AES_128_CBC_SHA)
\t}
}
"""


@pytest.fixture(scope="module")
def go_findings(tmp_path_factory) -> dict[str, list[RawFinding]]:
    root = tmp_path_factory.mktemp("go")
    (root / "weak.go").write_text(GO_WEAK, encoding="utf-8", newline="\n")
    (root / "near.go").write_text(GO_NEAR_MISS, encoding="utf-8", newline="\n")
    ctx = ScanContext.build(
        scan_id=uuid4(), work_dir=root, approved_paths=["weak.go", "near.go"]
    )
    found = CodeCollector().collect(ctx)
    return {
        "weak": [f for f in found if f.evidence_location.startswith("weak.go")],
        "near": [f for f in found if f.evidence_location.startswith("near.go")],
    }


def test_the_go_standard_library_is_inventoried_by_import_path(go_findings) -> None:
    """The package is the identity; the constructor is already in the evidence."""
    names = {f.algorithm_name for f in go_findings["weak"]}

    assert {
        "crypto/md5",
        "crypto/sha1",
        "crypto/des",
        "crypto/des.NewTripleDESCipher",
        "crypto/rc4",
        "crypto/rsa",
        "crypto/ecdsa",
        "crypto/ed25519",
        "crypto/dsa",
    } <= names


def test_go_records_primitives_key_sizes_and_curves(go_findings) -> None:
    by_algorithm = {f.algorithm_name: f for f in go_findings["weak"]}

    assert by_algorithm["crypto/md5"].primitive is Primitive.HASH
    assert by_algorithm["crypto/des"].primitive is Primitive.CIPHER
    # Triple DES shares crypto/des with single DES, so it is recorded apart —
    # reporting it as DES would name the wrong algorithm.
    assert by_algorithm["crypto/des.NewTripleDESCipher"].primitive is Primitive.CIPHER
    assert by_algorithm["crypto/rsa"].key_size == 1024
    assert by_algorithm["P256"].evidence_raw["observation"] == "curve_selected"
    # RSA is generated by its own rule; the generic one must not double-count it.
    assert len([f for f in go_findings["weak"] if f.algorithm_name == "crypto/rsa"]) == 1


def test_a_go_tls_config_declares_its_floor_and_its_suites(go_findings) -> None:
    floor = [f for f in go_findings["weak"] if f.algorithm_name == "VersionTLS10"]
    assert len(floor) == 1
    assert floor[0].primitive is Primitive.PROTOCOL
    assert floor[0].evidence_raw["observation"] == "protocol_floor"

    suites = [f for f in go_findings["weak"] if f.algorithm_name.startswith("TLS_")]
    assert [f.algorithm_name for f in suites] == ["TLS_RSA_WITH_AES_128_CBC_SHA"]
    assert suites[0].primitive is Primitive.CIPHER


def test_go_near_misses_are_not_reported(go_findings) -> None:
    """A local type called md5, a version *comparison*, a suite named in a log line."""
    assert go_findings["near"] == []


# --------------------------------------------------------------------------- #
# JavaScript and TypeScript
# --------------------------------------------------------------------------- #

JS_WEAK = """
const crypto = require("crypto");
const https = require("https");

function weak(key, iv) {
  const h = crypto.createHash("md5");
  const c = crypto.createCipheriv("des-ede3-cbc", key, iv);
  crypto.generateKeyPair("rsa", { modulusLength: 1024 }, () => {});
  const kp = crypto.generateKeyPairSync("ed25519");
  const agent = new https.Agent({
    secureProtocol: "TLSv1_method",
    ciphers: "DEFAULT@SECLEVEL=1",
  });
  return [h, c, kp, agent];
}
module.exports = { weak };
"""

TS_WEAK = """
import * as crypto from "crypto";

export function weak(key: Buffer, iv: Buffer): void {
  const h: crypto.Hash = crypto.createHash("sha1");
  const c = crypto.createCipheriv("rc4", key, iv);
  console.log(h, c);
}
"""

JS_NEAR_MISS = """
const crypto = require("crypto");

function nearMiss(algorithm, options) {
  // The algorithm is a variable, so nothing was observed to record.
  const h = crypto.createHash(algorithm);
  const c = crypto.createCipheriv(options.algorithm, options.key, options.iv);
  const opts = { secureProtocol: options.protocol, ciphers: options.ciphers };
  return [h, c, opts];
}
module.exports = { nearMiss };
"""


@pytest.fixture(scope="module")
def js_findings(tmp_path_factory) -> dict[str, list[RawFinding]]:
    root = tmp_path_factory.mktemp("js")
    for name, source in (("weak.js", JS_WEAK), ("weak.ts", TS_WEAK), ("near.js", JS_NEAR_MISS)):
        (root / name).write_text(source, encoding="utf-8", newline="\n")
    ctx = ScanContext.build(
        scan_id=uuid4(), work_dir=root, approved_paths=["weak.js", "weak.ts", "near.js"]
    )
    found = CodeCollector().collect(ctx)
    return {
        stem: [f for f in found if f.evidence_location.startswith(stem)]
        for stem in ("weak.js", "weak.ts", "near.js")
    }


def test_node_crypto_is_recorded_with_the_algorithm_string_it_was_handed(js_findings) -> None:
    by_algorithm = {f.algorithm_name: f for f in js_findings["weak.js"]}

    assert by_algorithm["md5"].primitive is Primitive.HASH
    assert by_algorithm["des-ede3-cbc"].primitive is Primitive.CIPHER
    assert by_algorithm["rsa"].key_size == 1024
    # A generator with no modulusLength is still an asset; it just has no size.
    assert by_algorithm["ed25519"].key_size is None
    assert len([f for f in js_findings["weak.js"] if f.algorithm_name == "rsa"]) == 1


def test_node_tls_options_declare_a_protocol_and_a_cipher_string(js_findings) -> None:
    protocol = [f for f in js_findings["weak.js"] if f.algorithm_name == "TLSv1_method"]
    assert len(protocol) == 1
    assert protocol[0].primitive is Primitive.PROTOCOL

    # The declaration is the finding and the string is evidence, exactly as §7.4
    # treats a CipherString that names no concrete suite.
    ciphers = [f for f in js_findings["weak.js"] if f.algorithm_name == "ciphers"]
    assert len(ciphers) == 1
    assert ciphers[0].evidence_raw["declared"] == "DEFAULT@SECLEVEL=1"
    assert ciphers[0].evidence_raw["observation"] == "cipher_selection_declared"


def test_the_same_rules_apply_to_typescript(js_findings) -> None:
    """A `js` rule is not applied to a `.ts` file; every rule lists both."""
    assert {f.algorithm_name for f in js_findings["weak.ts"]} == {"sha1", "rc4"}


def test_a_javascript_algorithm_held_in_a_variable_is_not_invented(js_findings) -> None:
    assert js_findings["near.js"] == []


# --------------------------------------------------------------------------- #
# Python — key exchange and signature, beyond hashes and ciphers
# --------------------------------------------------------------------------- #

PYTHON_ASYMMETRIC = """
import hmac
import hashlib
import ssl
from cryptography.hazmat.primitives.asymmetric import dh, ec, padding, rsa
from Crypto.Cipher import ARC4, Blowfish, DES
from Crypto.PublicKey import RSA

def run(key, data, peer):
    signing = rsa.generate_private_key(public_exponent=65537, key_size=1024)
    agreement = ec.generate_private_key(ec.SECP256R1())
    shared = agreement.exchange(ec.ECDH(), peer)
    params = dh.generate_parameters(generator=2, key_size=2048)
    pad = padding.PKCS1v15()
    legacy = DES.new(key, DES.MODE_ECB)
    stream = ARC4.new(key)
    block = Blowfish.new(key, Blowfish.MODE_CBC)
    imported = RSA.generate(1024)
    context = ssl.SSLContext(ssl.PROTOCOL_TLSv1)
    context.set_ciphers("DEFAULT@SECLEVEL=1")
    mac = hmac.new(key, data, hashlib.sha1)
    named = hmac.new(key, data, digestmod="md5")
    return signing, shared, params, pad, legacy, stream, block, imported, context, mac, named
"""

PYTHON_NEAR_MISS = """
import ssl

class DES:
    @staticmethod
    def new(*args):
        return None

def run(context, chosen):
    # Not pycryptodome: no `from Crypto.Cipher import DES` anywhere in the file.
    local = DES.new(b"x")
    # A cipher string held in a variable declares nothing this rule can read.
    context.set_ciphers(chosen)
    return local, ssl.CERT_REQUIRED
"""


@pytest.fixture(scope="module")
def python_asymmetric_findings(tmp_path_factory) -> dict[str, list[RawFinding]]:
    root = tmp_path_factory.mktemp("pyasym")
    (root / "asym.py").write_text(PYTHON_ASYMMETRIC, encoding="utf-8", newline="\n")
    (root / "near.py").write_text(PYTHON_NEAR_MISS, encoding="utf-8", newline="\n")
    ctx = ScanContext.build(
        scan_id=uuid4(), work_dir=root, approved_paths=["asym.py", "near.py"]
    )
    found = CodeCollector().collect(ctx)
    return {
        stem: [f for f in found if f.evidence_location.startswith(stem)]
        for stem in ("asym.py", "near.py")
    }


def test_python_key_exchange_and_signature_are_recorded(python_asymmetric_findings) -> None:
    by_algorithm = {f.algorithm_name: f for f in python_asymmetric_findings["asym.py"]}

    assert by_algorithm["RSA"].key_size in (1024,)
    assert by_algorithm["SECP256R1"].evidence_raw["observation"] == "ec_keygen"
    assert by_algorithm["ECDH"].primitive is Primitive.KEY_EXCHANGE
    assert (by_algorithm["DH"].primitive, by_algorithm["DH"].key_size) == (
        Primitive.KEY_EXCHANGE,
        2048,
    )
    assert by_algorithm["padding.PKCS1v15"].evidence_raw["observation"] == "rsa_padding"


def test_pycryptodome_ciphers_are_recorded_under_their_module(
    python_asymmetric_findings,
) -> None:
    names = {f.algorithm_name for f in python_asymmetric_findings["asym.py"]}

    assert {"Crypto.Cipher.DES", "Crypto.Cipher.ARC4", "Crypto.Cipher.Blowfish"} <= names


def test_python_ssl_declarations_and_hmac_digests_are_recorded(
    python_asymmetric_findings,
) -> None:
    by_algorithm = {f.algorithm_name: f for f in python_asymmetric_findings["asym.py"]}

    assert by_algorithm["PROTOCOL_TLSv1"].primitive is Primitive.PROTOCOL
    assert by_algorithm["set_ciphers"].evidence_raw["declared"] == "DEFAULT@SECLEVEL=1"
    assert by_algorithm["hashlib.sha1"].evidence_raw["observation"] in ("hash_call", "mac_call")
    assert by_algorithm["md5"].evidence_raw["observation"] == "mac_call"


def test_a_local_class_named_des_is_not_pycryptodome(python_asymmetric_findings) -> None:
    """The import is required rather than assumed — `DES.new` is just a name."""
    names = {f.algorithm_name for f in python_asymmetric_findings["near.py"]}

    assert "Crypto.Cipher.DES" not in names
    assert "set_ciphers" not in names


# --------------------------------------------------------------------------- #
# Java and C — key exchange, signature, and the TLS knobs
# --------------------------------------------------------------------------- #

JAVA_TLS = """
import java.security.KeyPairGenerator;
import java.security.Signature;
import javax.crypto.KeyAgreement;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;

public class Tls {
    static void run(SSLSocket socket) throws Exception {
        KeyPairGenerator sized = KeyPairGenerator.getInstance("RSA");
        sized.initialize(1024);
        KeyPairGenerator unsized = KeyPairGenerator.getInstance("DSA");
        KeyAgreement agreement = KeyAgreement.getInstance("DH");
        Signature signature = Signature.getInstance("SHA1withRSA");
        SSLContext context = SSLContext.getInstance("TLSv1");
        socket.setEnabledProtocols(new String[] {"TLSv1", "TLSv1.2"});
        socket.setEnabledCipherSuites(new String[] {"TLS_RSA_WITH_3DES_EDE_CBC_SHA"});
    }
}
"""

C_TLS = """
#include <openssl/dh.h>
#include <openssl/ec.h>
#include <openssl/objects.h>
#include <openssl/ssl.h>

void run(SSL_CTX *ctx) {
    DH *dh = DH_new();
    EC_KEY *key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    SSL_CTX_set_cipher_list(ctx, "HIGH:!aNULL:!MD5");
    SSL_CTX_set_min_proto_version(ctx, TLS1_VERSION);
    DES_cblock block;
    DES_key_schedule schedule;
    DES_set_key(&block, &schedule);
}
"""


@pytest.fixture(scope="module")
def tls_api_findings(tmp_path_factory) -> dict[str, list[RawFinding]]:
    root = tmp_path_factory.mktemp("tlsapi")
    (root / "Tls.java").write_text(JAVA_TLS, encoding="utf-8", newline="\n")
    (root / "tls.c").write_text(C_TLS, encoding="utf-8", newline="\n")
    ctx = ScanContext.build(
        scan_id=uuid4(), work_dir=root, approved_paths=["Tls.java", "tls.c"]
    )
    found = CodeCollector().collect(ctx)
    return {
        stem: [f for f in found if f.evidence_location.startswith(stem)]
        for stem in ("Tls.java", "tls.c")
    }


def test_a_sized_java_generator_is_recorded_once_with_its_size(tls_api_findings) -> None:
    """Two rules cover KeyPairGenerator; a sized one must not land in both."""
    rsa = [f for f in tls_api_findings["Tls.java"] if f.algorithm_name == "RSA"]

    assert [(f.key_size, f.evidence_raw["observation"]) for f in rsa] == [
        (1024, "keypair_generation")
    ]
    # And a generator left at the provider default is still an asset.
    dsa = [f for f in tls_api_findings["Tls.java"] if f.algorithm_name == "DSA"]
    assert [(f.key_size, f.evidence_raw["observation"]) for f in dsa] == [
        (None, "keypair_generation")
    ]


def test_a_java_signature_spelling_is_recorded_whole(tls_api_findings) -> None:
    """"SHA1withRSA" names a broken hash and a vulnerable signature in one string.

    The rule records the spelling; splitting it is §8's job, and the pack's
    `sha1-with-rsa` entry is what resolves it to SHA-1 with RSA as a component.
    """
    signature = [f for f in tls_api_findings["Tls.java"] if f.algorithm_name == "SHA1withRSA"]

    assert len(signature) == 1
    assert signature[0].primitive is Primitive.SIGNATURE


def test_java_tls_knobs_are_enumerated_per_declared_value(tls_api_findings) -> None:
    java = tls_api_findings["Tls.java"]
    protocols = [f for f in java if f.evidence_raw["observation"] == "protocol_version_declared"]

    assert {f.algorithm_name for f in protocols} == {"TLSv1", "TLSv1.2"}
    assert all(f.primitive is Primitive.PROTOCOL for f in protocols)
    assert [f.algorithm_name for f in java if f.algorithm_name.startswith("TLS_")] == [
        "TLS_RSA_WITH_3DES_EDE_CBC_SHA"
    ]
    context = [f for f in java if f.evidence_raw["observation"] == "protocol_declared"]
    assert [f.algorithm_name for f in context] == ["TLSv1"]
    assert {f.algorithm_name for f in java} >= {"DH"}


def test_the_openssl_c_api_records_key_exchange_curves_and_tls_knobs(tls_api_findings) -> None:
    by_algorithm = {f.algorithm_name: f for f in tls_api_findings["tls.c"]}

    assert by_algorithm["DH"].primitive is Primitive.KEY_EXCHANGE
    assert by_algorithm["NID_X9_62_prime256v1"].evidence_raw["observation"] == "curve_selected"
    assert by_algorithm["SSL_CTX_set_cipher_list"].evidence_raw["declared"] == "HIGH:!aNULL:!MD5"
    assert by_algorithm["TLS1_VERSION"].primitive is Primitive.PROTOCOL
    assert by_algorithm["DES_set_key"].primitive is Primitive.CIPHER


# --------------------------------------------------------------------------- #
# Every new spelling resolves — a rule producing a name nothing resolves moves a
# finding from absent to unknown, which is not progress (§8).
# --------------------------------------------------------------------------- #


def test_every_spelling_a_rule_declares_resolves_to_a_family() -> None:
    """The guard against moving findings from absent to unknown (§8).

    Read off the rule file rather than off a fixture. The fixture version of this
    test passed while ``ecdat.python.pycryptodome-cipher`` was emitting
    ``Crypto.Cipher.ChaCha20_Poly1305``, ``Crypto.Cipher.Salsa20`` and four more
    invented families on a real repository, because the fixture only exercised
    the three modules it happened to import. A rule that declares what it can
    produce can be checked against the alias table exhaustively, and that is the
    only version of this check worth having.
    """
    from app.core.normalizer import get_alias_index, identity_key
    from app.core.policy_loader import get_policy

    aliases = get_alias_index(get_policy())
    document = yaml.safe_load(get_settings().semgrep_rules_path.read_text(encoding="utf-8"))

    unresolved: dict[str, list[str]] = {}
    declared = 0
    for rule in document["rules"]:
        meta = (rule.get("metadata") or {}).get("ecdat") or {}
        allowed = meta.get("algorithm_in")
        if not allowed:
            continue
        prefix = meta.get("algorithm_prefix", "")
        declared += 1
        missing = [
            f"{prefix}{name}"
            for name in allowed
            if identity_key(f"{prefix}{name}") not in aliases.by_name
        ]
        if missing:
            unresolved[rule["id"]] = missing

    assert declared, "no rule declares algorithm_in; this test would pass vacuously"
    assert unresolved == {}


def test_a_capture_outside_a_rules_declared_spellings_is_dropped(scan_context) -> None:
    """An aliased import binds the local name, and the message carries that name.

    ``from Crypto.Cipher import PKCS1_v1_5 as PKCS`` makes Semgrep interpolate
    ``PKCS`` into the message even though the metavariable matched the real module
    — so a metavariable-regex does not bound what reaches the collector. The
    finding is dropped rather than recorded as ``Crypto.Cipher.PKCS``, which
    would resolve to nothing and be counted as its own family.
    """
    ctx = scan_context(
        {
            "aliased.py": (
                "from Crypto.Cipher import PKCS1_v1_5 as PKCS\n"
                "from Crypto.Cipher import AES\n"
                "\n"
                "def run(key):\n"
                "    return PKCS.new(key), AES.new(key, AES.MODE_GCM)\n"
            )
        }
    )

    findings = CodeCollector().collect(ctx)

    assert [f.algorithm_name for f in findings] == ["Crypto.Cipher.AES"]
    assert not [f for f in findings if "PKCS" in f.algorithm_name]


def test_every_spelling_the_new_rules_produce_resolves_to_a_family(
    go_findings, js_findings, python_asymmetric_findings, tls_api_findings
) -> None:
    from app.core.normalizer import get_alias_index, identity_key
    from app.core.policy_loader import get_policy

    aliases = get_alias_index(get_policy())
    # Declaration markers are deliberately absent from the alias table: the knob
    # is not an algorithm, and the declared string is evidence. See the header of
    # policy/algorithm_aliases.yaml.
    markers = {"set_ciphers", "ciphers", "SSL_CTX_set_cipher_list"}

    produced = [
        *go_findings["weak"],
        *js_findings["weak.js"],
        *js_findings["weak.ts"],
        *python_asymmetric_findings["asym.py"],
        *tls_api_findings["Tls.java"],
        *tls_api_findings["tls.c"],
    ]
    unresolved = sorted(
        {
            finding.algorithm_name
            for finding in produced
            if finding.algorithm_name not in markers
            and identity_key(finding.algorithm_name) not in aliases.by_name
        }
    )

    assert unresolved == []


def test_a_partial_parse_reason_is_a_sentence_not_a_json_dump(scan_context) -> None:
    """The reason reaches a banner and a PDF, so it has to be readable.

    Semgrep reports `type` as a plain string for most errors but as
    ``["PartialParsing", [ ...every offending range... ]]`` for a parse failure.
    Stringifying that put a screenful of JSON where the dashboard shows one line.
    """
    ctx = scan_context({"a.py": "x = 1\n"})
    document = {
        "version": "test",
        "results": [],
        "errors": [
            {
                "type": [
                    "PartialParsing",
                    [{"path": "src/ARC4.c", "start": {"line": 38, "col": 12}}],
                ],
                "message": "Syntax error at line src/ARC4.c:38:\nlong detail follows",
                "path": "src/ARC4.c",
            }
        ],
    }

    with pytest.raises(CollectorPartial) as raised:
        CodeCollector(fake_runner(document)).collect(ctx)

    reason = str(raised.value)
    assert reason.startswith("semgrep reported PartialParsing at src/ARC4.c")
    assert "Syntax error at line src/ARC4.c:38:" in reason
    # The offending-range list is what made this unreadable.
    assert "'start'" not in reason and "col" not in reason
    assert len(reason) < 200
