"""CBOM import and export — SPEC.md §7.6 and §13.

Two boundaries, one format. The import tests read the demo's sample document
the way a CBOMkit run would hand it over; the export tests hold the generated
document to the 1.6 schema and then feed it straight back through the importer,
because a format that only this tool can read is not a wire format.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from uuid import UUID, uuid4

import pytest
import sqlalchemy as sa

from app.collectors.binary import BinaryCollector
from app.collectors.cbom_import import (
    CbomImportError,
    findings_from_bom,
    import_cbom,
    parse_cbom,
    primitive_of,
)
from app.core.alignment import align
from app.core.normalizer import normalize
from app.export.cyclonedx import MEDIA_TYPE, build_cbom, export_cbom, validate_cbom
from app.models.analysis import VerdictRow
from app.models.enums import (
    CollectorName,
    Confidence,
    Primitive,
    ScanMode,
    ScanStatus,
    SourceLayer,
    SourceType,
)
from app.models.finding import Finding, ProvenanceBlob
from app.models.scan import Scan
from app.runner import analyse
from tests.conftest import DEMO_DIR, TEST_DATA_DIR


@pytest.fixture(scope="session")
def sample_bytes() -> bytes:
    return (DEMO_DIR / "sample_cbom.json").read_bytes()


@pytest.fixture
def scan_factory(db_session):
    def _factory(mode: ScanMode = ScanMode.FILES, data_lifetime_years: int = 20) -> Scan:
        scan = Scan(
            mode=mode,
            source_type=SourceType.FOLDER if mode is not ScanMode.PROBE_ONLY else SourceType.NONE,
            source_ref="/tmp/whatever" if mode is not ScanMode.PROBE_ONLY else None,
            data_lifetime_years=data_lifetime_years,
            policy_version="2026.09",
            status=ScanStatus.COMPLETE,
        )
        db_session.add(scan)
        db_session.flush()
        return scan

    return _factory


def by_family(findings) -> dict[str, list[Finding]]:
    grouped: dict[str, list[Finding]] = {}
    for finding in findings:
        grouped.setdefault(finding.algorithm_family, []).append(finding)
    return grouped


def minimal_cbom(*components: dict) -> bytes:
    """A valid 1.6 document with exactly these components."""
    return json.dumps(
        {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "version": 1,
            "metadata": {"tools": {"components": [{"type": "application", "name": "unit-test", "version": "0"}]}},
            "components": list(components),
        }
    ).encode("utf-8")


def algorithm(name: str, primitive: str, functions: list[str], oid: str | None = None, **props) -> dict:
    component = {
        "type": "cryptographic-asset",
        "bom-ref": f"crypto/algorithm/{name.lower()}",
        "name": name,
        "cryptoProperties": {
            "assetType": "algorithm",
            "algorithmProperties": {"primitive": primitive, "cryptoFunctions": functions, **props},
        },
    }
    if oid:
        component["cryptoProperties"]["oid"] = oid
    return component


# --------------------------------------------------------------------------- #
# Import — the demo sample
# --------------------------------------------------------------------------- #


def test_the_sample_cbom_imports_and_produces_findings(db_session, scan_factory, sample_bytes) -> None:
    """§7.6's required test: every cryptographic-asset becomes findings, one per occurrence."""
    scan = scan_factory()

    result = import_cbom(db_session, scan, sample_bytes, filename="sample_cbom.json")

    assert result.component_count == 10
    assert result.tool == "cbomkit 1.4.0"
    assert result.skipped == ()
    families = by_family(result.findings)
    for expected in ("MD5", "SHA-1", "RSA", "AES", "ECDH", "ML-KEM", "TLS"):
        assert expected in families, sorted(families)

    for finding in result.findings:
        assert finding.collector is CollectorName.CBOM_IMPORT
        assert finding.source_layer is SourceLayer.SOURCE
        assert finding.confidence is Confidence.MEDIUM
        assert finding.evidence_raw["provenance_id"] == str(result.blob.id)
        assert finding.evidence_raw["tool"] == "cbomkit 1.4.0"

    # One row per occurrence (§5), located where the source tool said.
    md5 = families["MD5"]
    assert {f.evidence_location for f in md5} == {"pyapp/app.py:49", "javaapp/HashDemo.java:29"}
    assert all(f.primitive is Primitive.HASH for f in md5)
    assert md5[0].algorithm_oid == "1.2.840.113549.2.5"


def test_pke_is_resolved_by_what_the_key_does(db_session, scan_factory, sample_bytes) -> None:
    """RSA-1024 is filed under ``pke`` with sign and verify: a signature, and 1024 bits."""
    scan = scan_factory()
    findings = import_cbom(db_session, scan, sample_bytes).findings

    rsa = [f for f in by_family(findings)["RSA"] if f.evidence_raw["observation"] == "cbom_algorithm"]
    assert rsa and all(f.primitive is Primitive.SIGNATURE and f.key_size == 1024 for f in rsa)
    assert {f.evidence_location for f in rsa} == {"pyapp/app.py:64", "cbin/cryptodemo.c:67"}


def test_modes_key_sizes_and_the_pqc_asset_come_through(db_session, scan_factory, sample_bytes) -> None:
    scan = scan_factory()
    families = by_family(import_cbom(db_session, scan, sample_bytes).findings)

    aes = families["AES"]
    assert [(f.key_size, f.mode) for f in aes] == [(128, "ECB")]
    assert aes[0].evidence_location == "pyapp/app.py:77"

    mlkem = families["ML-KEM"]
    assert [f.primitive for f in mlkem] == [Primitive.KEY_EXCHANGE]
    assert mlkem[0].algorithm_oid == "2.16.840.1.101.3.4.4.2"

    x25519 = families["ECDH"]
    assert x25519[0].algorithm_name == "X25519"
    assert x25519[0].primitive is Primitive.KEY_EXCHANGE


def test_the_certificate_and_protocol_components_become_findings(db_session, scan_factory, sample_bytes) -> None:
    scan = scan_factory()
    findings = import_cbom(db_session, scan, sample_bytes).findings
    observations = {f.evidence_raw["observation"]: f for f in findings}

    signature = observations["certificate_signature_algorithm"]
    assert signature.algorithm_family == "SHA-1" and signature.primitive is Primitive.SIGNATURE
    assert signature.evidence_location == "certs/weak.crt"
    assert signature.evidence_raw["certificate"]["subject"].endswith("CN=legacy.ecdat.demo")

    public_key = observations["certificate_public_key"]
    assert public_key.algorithm_family == "RSA" and public_key.key_size == 1024
    assert public_key.evidence_raw["material_type"] == "public-key"
    # The public key was consumed through the certificate: no second row for it.
    assert sum(1 for f in findings if f.evidence_raw.get("material_ref") == "crypto/related-crypto-material/legacy-rsa-1024-public") == 1

    protocol = observations["cbom_protocol"]
    assert protocol.algorithm_family == "TLS" and protocol.protocol_version == "1.0"
    assert protocol.primitive is Primitive.PROTOCOL
    assert protocol.evidence_location == "legacy.ecdat.demo:8443"

    suites = [f for f in findings if f.evidence_raw["observation"] == "cbom_protocol_cipher_suite"]
    assert {f.algorithm_name for f in suites} == {"TLS_RSA_WITH_AES_128_CBC_SHA", "TLS_RSA_WITH_3DES_EDE_CBC_SHA"}
    assert all(f.protocol_version == "1.0" and f.primitive is Primitive.CIPHER for f in suites)


def test_an_imported_protocol_observation_never_feeds_the_alignment_check(
    db_session, scan_factory, sample_bytes
) -> None:
    """demo/README.md §I: a third party's report of a handshake is not our observation of one."""
    scan = scan_factory(ScanMode.FILES_AND_PROBE)
    import_cbom(db_session, scan, sample_bytes)

    result = align(db_session, scan)

    assert result.skipped
    assert result.notes == ()


def test_the_imported_findings_get_verdicts_waves_and_advice(db_session, scan_factory, sample_bytes) -> None:
    """Imported means treated like everything else: MD5 broken, ML-KEM safe, X25519 overdue at X=20."""
    scan = scan_factory(data_lifetime_years=20)
    import_cbom(db_session, scan, sample_bytes)

    analysis = analyse(db_session, scan)

    verdicts = {}
    for row in analysis.verdicts:
        finding = db_session.get(Finding, row.finding_id)
        verdicts.setdefault(finding.algorithm_family, set()).add(row.verdict.value)
    assert verdicts["MD5"] == {"broken_now"}
    assert verdicts["ML-KEM"] == {"quantum_safe"}
    assert verdicts["ECDH"] == {"quantum_vulnerable"}
    assert verdicts["AES"] == {"broken_now"}  # ECB, by mode not key size
    assert "wave_1" in {row.wave.value for row in analysis.risk_scores}
    assert analysis.recommendations


# --------------------------------------------------------------------------- #
# Provenance
# --------------------------------------------------------------------------- #


def test_the_raw_document_is_stored_byte_identical(db_session, scan_factory, sample_bytes) -> None:
    """§7.6's required test. The bytes, not a re-serialisation of them."""
    scan = scan_factory()
    result = import_cbom(db_session, scan, sample_bytes, filename="sample_cbom.json")
    db_session.flush()
    db_session.expire_all()

    stored = db_session.scalars(sa.select(ProvenanceBlob).where(ProvenanceBlob.scan_id == scan.id)).all()
    assert len(stored) == 1 and stored[0].id == result.blob.id
    document = stored[0].raw_document
    assert document["document"].encode("utf-8") == sample_bytes
    assert document["sha256"] == hashlib.sha256(sample_bytes).hexdigest()
    assert document["byte_length"] == len(sample_bytes)
    assert document["filename"] == "sample_cbom.json"


def test_a_rejected_upload_stores_no_provenance(db_session, scan_factory) -> None:
    scan = scan_factory()
    with pytest.raises(CbomImportError):
        import_cbom(db_session, scan, b'{"bomFormat": "SPDX"}')
    assert db_session.scalars(sa.select(ProvenanceBlob).where(ProvenanceBlob.scan_id == scan.id)).all() == []


@pytest.mark.parametrize(
    ("raw", "match"),
    [
        (b"\xff\xfe not text", "not UTF-8"),
        (b"{not json", "not JSON"),
        (b'{"spdxVersion": "SPDX-2.3"}', "not a CycloneDX document"),
        (b'{"bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1}', "only 1.6 is accepted"),
        (b'{"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1, "components": [{"type": "cryptographic-asset"}]}', "does not validate"),
    ],
)
def test_documents_that_are_not_a_valid_1_6_cbom_are_refused(raw: bytes, match: str) -> None:
    with pytest.raises(CbomImportError, match=match):
        parse_cbom(raw)


# --------------------------------------------------------------------------- #
# Mapping rules on minimal documents
# --------------------------------------------------------------------------- #


def test_pke_ambiguity_is_unknown_rather_than_guessed() -> None:
    bom, _ = parse_cbom(
        minimal_cbom(
            algorithm("RSA-sign", "pke", ["sign", "verify"]),
            algorithm("RSA-transport", "pke", ["encrypt", "decrypt"]),
            algorithm("RSA-both", "pke", ["sign", "encrypt"]),
            algorithm("RSA-keygen", "pke", ["keygen"]),
        )
    )
    findings, _ = findings_from_bom(bom)
    primitives = {f.algorithm_name: f.primitive for f in findings}

    assert primitives == {
        "RSA-sign": Primitive.SIGNATURE,
        "RSA-transport": Primitive.KEY_EXCHANGE,
        "RSA-both": Primitive.UNKNOWN,
        "RSA-keygen": Primitive.UNKNOWN,
    }
    assert primitive_of(None) is Primitive.UNKNOWN


def test_declared_confidence_and_layer_are_honoured_and_defaults_apply(db_session, scan_factory) -> None:
    """§7.6: inherit from the source if declared, else medium and source."""
    declared = algorithm("MD5", "hash", ["digest"], oid="1.2.840.113549.2.5")
    declared["properties"] = [
        {"name": "ecdat:confidence", "value": "high"},
        {"name": "ecdat:source_layer", "value": "artifact"},
    ]
    plain = algorithm("SHA-1", "hash", ["digest"], oid="1.3.14.3.2.26")
    scan = scan_factory()

    findings = import_cbom(db_session, scan, minimal_cbom(declared, plain)).findings

    by_name = {f.algorithm_name: f for f in findings}
    assert by_name["MD5"].confidence is Confidence.HIGH
    assert by_name["MD5"].source_layer is SourceLayer.ARTIFACT
    assert by_name["SHA-1"].confidence is Confidence.MEDIUM
    assert by_name["SHA-1"].source_layer is SourceLayer.SOURCE


def test_private_key_material_in_the_document_is_never_copied_into_a_finding(db_session, scan_factory) -> None:
    secret = "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcw\n-----END PRIVATE KEY-----"
    component = {
        "type": "cryptographic-asset",
        "bom-ref": "crypto/related-crypto-material/leaked",
        "name": "leaked key",
        "cryptoProperties": {
            "assetType": "related-crypto-material",
            "relatedCryptoMaterialProperties": {"type": "private-key", "size": 2048, "value": secret},
        },
        "evidence": {"occurrences": [{"location": "config/app.key"}]},
    }
    scan = scan_factory()

    findings = import_cbom(db_session, scan, minimal_cbom(component)).findings

    assert len(findings) == 1
    finding = findings[0]
    assert finding.algorithm_name == "private-key-file"
    assert finding.key_size == 2048
    assert finding.evidence_location == "config/app.key"
    assert "BEGIN" not in json.dumps(finding.evidence_raw)
    assert secret not in json.dumps(finding.evidence_raw)


def test_a_component_that_yields_nothing_is_reported_rather_than_dropped() -> None:
    dangling = {
        "type": "cryptographic-asset",
        "bom-ref": "crypto/certificate/orphan",
        "name": "orphan",
        "cryptoProperties": {
            "assetType": "certificate",
            "certificateProperties": {"signatureAlgorithmRef": "crypto/algorithm/not-in-this-document"},
        },
    }
    bom, _ = parse_cbom(minimal_cbom(dangling))
    findings, skipped = findings_from_bom(bom)

    assert findings == []
    assert len(skipped) == 1 and "crypto/certificate/orphan" in skipped[0]


# --------------------------------------------------------------------------- #
# Through the API
# --------------------------------------------------------------------------- #


def test_uploading_a_cbom_to_a_scan_reruns_the_analysis(client, demo_scan, db_session, sample_bytes) -> None:
    scan_id = demo_scan["scan_id"]

    response = client.post(
        f"/api/scans/{scan_id}/cbom",
        content=sample_bytes,
        headers={"content-type": "application/json", "x-filename": "sample_cbom.json"},
    )

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["tool"] == "cbomkit 1.4.0"
    assert body["component_count"] == 10
    assert body["finding_count"] > 10
    assert body["skipped"] == []
    assert "quantum_safe" not in body["verdict_counts"]  # hidden from every output by default
    assert set(body["recommendation_counts"]) == {"recommended", "blocked", "no_path", "unknown"}
    assert body["alignment"]["status"] == "skipped"

    stored = db_session.scalars(sa.select(ProvenanceBlob).where(ProvenanceBlob.scan_id == UUID(scan_id))).all()
    assert len(stored) == 1
    # The imported ML-KEM asset is what gives quantum_safe a post-quantum member.
    rows = db_session.execute(
        sa.select(Finding, VerdictRow).join(VerdictRow, VerdictRow.finding_id == Finding.id)
        .where(Finding.scan_id == UUID(scan_id), Finding.algorithm_family == "ML-KEM")
    ).all()
    assert rows and all(v.verdict.value == "quantum_safe" for _, v in rows)


def test_a_bad_upload_is_a_400_and_an_unknown_scan_a_404(client, demo_scan, sample_bytes) -> None:
    bad = client.post(f"/api/scans/{demo_scan['scan_id']}/cbom", content=b'{"bomFormat": "SPDX"}')
    assert bad.status_code == 400
    assert "not a CycloneDX document" in bad.json()["detail"]

    empty = client.post(f"/api/scans/{demo_scan['scan_id']}/cbom", content=b"   ")
    assert empty.status_code == 400

    missing = client.post(f"/api/scans/{uuid4()}/cbom", content=sample_bytes)
    assert missing.status_code == 404


# --------------------------------------------------------------------------- #
# Export
# --------------------------------------------------------------------------- #


def test_the_exported_cbom_validates_against_the_1_6_schema(client, demo_scan) -> None:
    """§16's required test."""
    response = client.get(f"/api/scans/{demo_scan['scan_id']}/cbom")

    assert response.status_code == 200, response.text
    assert response.headers["content-type"].startswith(MEDIA_TYPE)
    assert validate_cbom(response.text) is None

    document = response.json()
    assert document["bomFormat"] == "CycloneDX" and document["specVersion"] == "1.6"
    assets = [c for c in document["components"] if c["type"] == "cryptographic-asset"]
    assert assets
    assert all("cryptoProperties" in c for c in assets)
    properties = {p["name"]: p["value"] for p in document["metadata"]["component"]["properties"]}
    assert properties["ecdat:scan_id"] == demo_scan["scan_id"]
    assert properties["ecdat:policy_version"] == "2026.09"
    assert properties["ecdat:excluded_observations"] != "none"


def test_the_export_carries_the_analysis_as_properties(client, demo_scan) -> None:
    document = client.get(f"/api/scans/{demo_scan['scan_id']}/cbom").json()
    by_name = {}
    for component in document["components"]:
        by_name.setdefault(component["name"], []).append(component)

    md5 = next(c for c in by_name["MD5"] if c["cryptoProperties"]["algorithmProperties"]["primitive"] == "hash")
    props = {p["name"]: p["value"] for p in md5["properties"]}
    assert props["ecdat:verdict"] == "broken_now"
    assert props["ecdat:wave"] == "wave_0"
    assert props["ecdat:source_citation"]
    assert md5["cryptoProperties"]["oid"] == "1.2.840.113549.2.5"
    # One component, many occurrences: MD5 is used in Python, Java, C and sshd.
    assert len(md5["evidence"]["occurrences"]) >= 3
    assert any(o.get("line") for o in md5["evidence"]["occurrences"])


def test_the_export_contains_no_key_material(client, demo_scan) -> None:
    text = client.get(f"/api/scans/{demo_scan['scan_id']}/cbom").text
    assert "BEGIN" not in text
    document = json.loads(text)
    keys = [c for c in document["components"] if c["name"] == "private-key-file"]
    if keys:  # demo/certs is generated; present on a machine that ran the lab
        material = keys[0]["cryptoProperties"]["relatedCryptoMaterialProperties"]
        assert material["type"] == "private-key" and "value" not in material


def test_linked_libraries_and_protocols_are_exported_in_their_own_shapes(db_session, scan_factory, scan_context) -> None:
    elf = TEST_DATA_DIR / "cryptodemo-openssl1.1.elf"
    scan = scan_factory()
    ctx = scan_context({"bin/cryptodemo": elf.read_bytes()})
    normalize(db_session, scan.id, BinaryCollector().collect(ctx))
    analyse(db_session, scan)

    document = json.loads(export_cbom(db_session, scan))

    libraries = [c for c in document["components"] if c["type"] == "library"]
    assert {(c["name"], c.get("version")) for c in libraries} == {("openssl", "1.1"), ("openssl", "1.1.1f")}
    protocols = [
        c for c in document["components"]
        if c.get("cryptoProperties", {}).get("assetType") == "protocol"
    ]
    names = {s["name"] for c in protocols for s in c["cryptoProperties"]["protocolProperties"].get("cipherSuites", [])}
    # Suite names read out of .rodata carry no protocol version, so they hang
    # off a protocol component whose version is undeclared — and the one the
    # alias table does not know is still an asset, not a marker.
    assert {"TLS_RSA_WITH_3DES_EDE_CBC_SHA", "TLS_RSA_WITH_RC4_128_MD5"} <= names
    assert all(c["cryptoProperties"]["protocolProperties"].get("version") is None for c in protocols)
    # The dependency graph is complete: the scan depends on everything it found.
    root = document["metadata"]["component"]["bom-ref"]
    depends = next(d for d in document["dependencies"] if d["ref"] == root)["dependsOn"]
    assert set(depends) == {c["bom-ref"] for c in document["components"]}


def test_a_round_trip_preserves_algorithm_identities(client, demo_scan, db_session, scan_factory) -> None:
    """§7.6 / §13's required test: export, then import into a fresh scan, and compare identities."""
    original_id = UUID(demo_scan["scan_id"])
    exported = client.get(f"/api/scans/{original_id}/cbom").text

    fresh = scan_factory()
    result = import_cbom(db_session, fresh, exported.encode("utf-8"), filename="round-trip.cdx.json")

    def is_algorithm(f: Finding) -> bool:
        return (
            f.primitive not in (Primitive.UNKNOWN, Primitive.PROTOCOL)
            and not (f.algorithm_family or "").startswith(("TLS_", "SSL_"))
            and f.algorithm_name != "private-key-file"
        )

    def identities(findings):
        return {
            (f.algorithm_family, f.primitive.value, f.key_size, (f.mode or "").upper() or None)
            for f in findings
            if is_algorithm(f)
        }

    from app.models.analysis import VerdictRow as _Verdict

    safe_ids = {
        row.finding_id
        for row in db_session.scalars(sa.select(_Verdict).where(_Verdict.verdict == "quantum_safe"))
    }
    originals = [
        f for f in db_session.scalars(sa.select(Finding).where(Finding.scan_id == original_id))
        if f.id not in safe_ids  # hidden from the export by default, so not round-tripped
    ]
    before = identities(originals)
    after = identities(result.findings)

    assert before, "the demo scan has algorithm findings to round-trip"
    assert before == after, {"lost": before - after, "invented": after - before}
    assert result.skipped == ()

    # Every OID the scan recorded came back on the same family. The importer
    # may *add* one — resolving `DH` to its OID is identity resolution doing
    # its job — but it may never lose or change one.
    oids_before = {(f.algorithm_family, f.algorithm_oid) for f in originals if is_algorithm(f) and f.algorithm_oid}
    oids_after = {(f.algorithm_family, f.algorithm_oid) for f in result.findings if is_algorithm(f) and f.algorithm_oid}
    assert oids_before <= oids_after, {"lost": oids_before - oids_after}
    # And the round trip kept the observed layer and the collector's own confidence.
    assert {f.source_layer for f in result.findings} >= {SourceLayer.SOURCE}


def test_build_cbom_needs_no_analysis_rows(db_session, scan_factory) -> None:
    """An export of a scan that has findings but was never analysed still validates."""
    scan = scan_factory()
    db_session.add(
        Finding(
            scan_id=scan.id,
            collector=CollectorName.CODE,
            algorithm_name="hashlib.md5",
            algorithm_family="MD5",
            primitive=Primitive.HASH,
            evidence_location="app.py:1",
            evidence_raw={"observation": "hash_call", "normalization": {"identity_resolved": True}},
            confidence=Confidence.HIGH,
            source_layer=SourceLayer.SOURCE,
        )
    )
    db_session.flush()

    text = export_cbom(db_session, scan)

    assert validate_cbom(text) is None
    bom = build_cbom(db_session, scan)
    assert len(bom.components) == 1
