"""Certificate collector — SPEC.md §7.3.

The first two tests are the ones that matter. Everything else in this file
checks that the collector reports certificates correctly; those two check that it
never reads a private key, which is the hard rule from §1 and the only property
here that cannot be fixed after the fact.
"""

from __future__ import annotations

import datetime
import os
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from app.collectors import certs
from app.collectors.certs import CertificateCollector
from app.models.enums import CollectorName, Confidence, Primitive, SourceLayer

SHA1_WITH_RSA_OID = "1.2.840.113549.1.1.5"

#: A key file the collector must never open. The body is deliberately not a key:
#: if anything ever tried to parse it the test would fail loudly rather than
#: quietly succeeding on well-formed material.
FAKE_PRIVATE_KEY = (
    "-----BEGIN RSA PRIVATE KEY-----\n"
    "this is not key material and nothing in ECDAT may ever try to read it\n"
    "-----END RSA PRIVATE KEY-----\n"
)


def collect(ctx) -> list:
    return CertificateCollector().collect(ctx)


def by_name(findings, name: str) -> list:
    return [finding for finding in findings if finding.algorithm_name == name]


# --------------------------------------------------------------------------- #
# The hard rule: private key material (§1, §7.3)
# --------------------------------------------------------------------------- #


def test_private_key_produces_metadata_only_and_is_never_parsed(scan_context, monkeypatch) -> None:
    """Path, size and permissions. No parser is called on it — asserted, not assumed."""
    parsed: list[str] = []

    def _record_pem(data, *args, **kwargs):
        parsed.append("pem")
        raise AssertionError("the PEM certificate loader ran on a private key file")

    def _record_der(data, *args, **kwargs):
        parsed.append("der")
        raise AssertionError("the DER certificate loader ran on a private key file")

    monkeypatch.setattr(certs.x509, "load_pem_x509_certificate", _record_pem)
    monkeypatch.setattr(certs.x509, "load_der_x509_certificate", _record_der)

    ctx = scan_context({"etc/tls/server.key": FAKE_PRIVATE_KEY})
    findings = collect(ctx)

    assert parsed == []
    metadata = by_name(findings, certs.OBS_PRIVATE_KEY_FILE)
    assert len(metadata) == 1
    evidence = metadata[0].evidence_raw
    assert evidence["parsed"] is False
    assert evidence["size_bytes"] == len(FAKE_PRIVATE_KEY)
    assert evidence["container"] == "-----BEGIN RSA PRIVATE KEY-----"
    assert metadata[0].evidence_location == "etc/tls/server.key"
    # Nothing about the key itself: no algorithm identity, no size in bits.
    assert metadata[0].key_size is None
    assert metadata[0].primitive is Primitive.UNKNOWN


def test_a_bundle_stops_reading_at_the_key_header(scan_context, weak_cert_pem) -> None:
    """A cert followed by its key yields the cert, and the key's bytes stay unread.

    This is why the collector streams instead of slurping: the certificate above
    the key is genuinely useful, and reading the file to find it must not mean
    reading past the ``BEGIN ... PRIVATE KEY`` line to get there.
    """
    sentinel = "SENTINEL-BYTES-THAT-MUST-NEVER-BE-READ"
    bundle = weak_cert_pem.decode("ascii") + (
        "-----BEGIN PRIVATE KEY-----\n" + sentinel + "\n-----END PRIVATE KEY-----\n"
    )
    ctx = scan_context({"bundle.pem": bundle})

    findings = collect(ctx)

    assert by_name(findings, "RSA"), "the certificate above the key was still reported"
    key_findings = by_name(findings, certs.OBS_PRIVATE_KEY_FILE)
    assert len(key_findings) == 1
    assert key_findings[0].evidence_raw["certificates_read_before_key"] == 1
    # The sentinel sits after the key header, so it must appear nowhere.
    assert sentinel not in repr([finding.evidence_raw for finding in findings])


def test_pkcs12_is_treated_as_key_material_not_as_a_certificate(scan_context, monkeypatch) -> None:
    """``.p12`` is on §7.3's extension list *and* holds a key. §1 wins."""
    ctx = scan_context({"certs/bundle.p12": b"\x30\x82\x00\x00 not really a pkcs12"})

    opened: list[str] = []
    real_open = Path.open

    def _tracking_open(self, *args, **kwargs):
        opened.append(self.name)
        return real_open(self, *args, **kwargs)

    # Patched after the tree is written, so only the collector's reads are counted.
    monkeypatch.setattr(Path, "open", _tracking_open)
    findings = collect(ctx)

    assert "bundle.p12" not in opened, "the container was opened despite holding a key"
    assert by_name(findings, certs.OBS_PRIVATE_KEY_FILE)
    assert findings[0].evidence_raw["container"].startswith("PKCS#12")


@pytest.mark.skipif(os.name == "nt", reason="NTFS carries no POSIX mode to report")
def test_a_world_readable_key_adds_a_hygiene_finding(scan_context) -> None:
    ctx = scan_context({"server.key": FAKE_PRIVATE_KEY})
    (ctx.work_dir / "server.key").chmod(0o644)

    findings = collect(ctx)

    assert by_name(findings, certs.OBS_PRIVATE_KEY_WORLD_READABLE)

    (ctx.work_dir / "server.key").chmod(0o600)
    assert not by_name(collect(ctx), certs.OBS_PRIVATE_KEY_WORLD_READABLE)


# --------------------------------------------------------------------------- #
# The demo's RSA-1024 / SHA-1 certificate (§14 target E)
# --------------------------------------------------------------------------- #


def test_the_demo_weak_certificate_produces_the_expected_findings(
    scan_context, weak_cert_pem
) -> None:
    """RSA-1024, SHA-1 signature, self-signed — three independent observations.

    Two of them live in one file, and the collector has to report both rather
    than stopping at the first thing it notices (``demo/gen_certs.sh`` says so in
    as many words).
    """
    ctx = scan_context({"etc/nginx/certs/weak.crt": weak_cert_pem})

    findings = collect(ctx)

    public_key = by_name(findings, "RSA")
    assert len(public_key) == 1
    assert public_key[0].key_size == 1024
    assert public_key[0].collector is CollectorName.CERTS
    assert public_key[0].source_layer is SourceLayer.ARTIFACT
    assert public_key[0].confidence is Confidence.HIGH
    # A certificate key is an identity key; §12's primitive gate depends on it.
    assert public_key[0].primitive is Primitive.SIGNATURE

    signature = by_name(findings, "sha1WithRSAEncryption")
    assert len(signature) == 1
    assert signature[0].algorithm_oid == SHA1_WITH_RSA_OID
    assert signature[0].primitive is Primitive.SIGNATURE
    assert signature[0].evidence_raw["signature_hash"] == "sha1"

    assert by_name(findings, certs.OBS_CERTIFICATE_SELF_SIGNED)

    # The collector does not judge. No verdict field exists on a RawFinding, and
    # "RSA-1024 is broken" is a policy lookup against a citation (§10).
    assert not any(hasattr(finding, "verdict") for finding in findings)

    location = public_key[0].evidence_location
    assert location.startswith("etc/nginx/certs/weak.crt:")
    evidence = public_key[0].evidence_raw
    assert evidence["self_signed"] is True
    assert "legacy.ecdat.demo" in evidence["subject"]
    assert "localhost" in evidence["subject_alternative_names"]


def test_a_certificate_embedded_in_another_file_is_found_by_sniffing(
    scan_context, weak_cert_pem
) -> None:
    """§7.3: configs embed PEM blocks, so the extension list is not the whole answer."""
    embedded = "upstream_tls_pin = |\n" + weak_cert_pem.decode("ascii")
    ctx = scan_context({"conf/embedded-cert.conf": embedded})

    findings = collect(ctx)

    assert by_name(findings, "RSA")
    assert by_name(findings, "sha1WithRSAEncryption")[0].evidence_location == (
        "conf/embedded-cert.conf:2"
    )


def test_a_der_certificate_is_parsed(scan_context, weak_cert_pem) -> None:
    der = x509.load_pem_x509_certificate(weak_cert_pem).public_bytes(
        serialization.Encoding.DER
    )
    ctx = scan_context({"pki/server.der": der})

    findings = collect(ctx)

    assert by_name(findings, "RSA")[0].evidence_raw["encoding"] == "der"


# --------------------------------------------------------------------------- #
# Validity and self-signed
# --------------------------------------------------------------------------- #


def _self_signed(common_name: str, *, days_valid: int, key_size: int = 2048) -> bytes:
    key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    now = datetime.datetime.now(datetime.timezone.utc)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=days_valid))
        .sign(key, hashes.SHA256())
    )
    return certificate.public_bytes(serialization.Encoding.PEM)


def test_a_certificate_expiring_inside_the_window_is_reported(scan_context) -> None:
    ctx = scan_context({"pki/soon.pem": _self_signed("soon.example", days_valid=45)})

    findings = collect(ctx)

    expiring = by_name(findings, certs.OBS_CERTIFICATE_EXPIRING)
    assert len(expiring) == 1
    assert 0 < expiring[0].evidence_raw["days_remaining"] <= certs.EXPIRY_WARNING_DAYS
    assert not by_name(findings, certs.OBS_CERTIFICATE_EXPIRED)


def test_a_long_lived_certificate_reports_no_expiry_finding(scan_context) -> None:
    ctx = scan_context({"pki/fine.pem": _self_signed("fine.example", days_valid=800)})

    findings = collect(ctx)

    assert not by_name(findings, certs.OBS_CERTIFICATE_EXPIRING)
    assert not by_name(findings, certs.OBS_CERTIFICATE_EXPIRED)


def test_self_signed_under_a_dev_path_is_not_reported(scan_context) -> None:
    """§7.3 asks for self-signed *in a non-dev path*. A cert under ``tests/`` is furniture."""
    pem = _self_signed("local.example", days_valid=800)
    ctx = scan_context({"tests/fixtures/local.pem": pem, "pki/live.pem": pem})

    findings = collect(ctx)

    locations = {
        finding.evidence_location.split(":")[0]
        for finding in by_name(findings, certs.OBS_CERTIFICATE_SELF_SIGNED)
    }
    assert locations == {"pki/live.pem"}


# --------------------------------------------------------------------------- #
# Scope
# --------------------------------------------------------------------------- #


def test_only_approved_files_are_read(scan_context, weak_cert_pem) -> None:
    ctx = scan_context(
        {"approved.crt": weak_cert_pem, "unapproved.crt": weak_cert_pem},
        approved=["approved.crt"],
    )

    findings = collect(ctx)

    assert {finding.evidence_location.split(":")[0] for finding in findings} == {
        "approved.crt"
    }


def test_a_file_that_is_not_a_certificate_produces_nothing(scan_context) -> None:
    ctx = scan_context({"app/main.py": "x = 1\n", "notes.txt": "no crypto here\n"})

    assert collect(ctx) == []
