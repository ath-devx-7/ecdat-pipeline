"""Normalizer — SPEC.md §8.

Two properties are tested here, and both of them are about *counting*.

Identity resolution is what stops one algorithm appearing as four rows because
four tools spell it four ways. The failure mode is not an exception — it is a
dashboard where the biggest number belongs to the algorithm with the most
spellings, which nobody notices until they act on it.

Source layer tagging is what makes §9 possible at all. A config finding that
arrives tagged ``artifact`` is not a wrong label, it is a drift check that
compares a claim against a claim and reports nothing.
"""

from __future__ import annotations

from pathlib import Path
from uuid import UUID, uuid4

import pytest
import sqlalchemy as sa

from app.collectors.base import RawFinding
from app.collectors.certs import CertificateCollector
from app.collectors.config import ConfigCollector
from app.core.normalizer import (
    AliasError,
    LAYER_PRECEDENCE,
    build_alias_index,
    layer_rank,
    normalize,
    resolve,
)
from app.core.policy_loader import load_policy
from app.models.enums import (
    CollectorName,
    Confidence,
    Primitive,
    ScanMode,
    ScanStatus,
    SourceLayer,
    SourceType,
)
from app.models.finding import Finding
from app.models.scan import Scan

SHA1_OID = "1.3.14.3.2.26"
SHA1_WITH_RSA_OID = "1.2.840.113549.1.1.5"


@pytest.fixture
def alias_index(shipped_policy_dir: Path):
    """The index built from the pack as it ships. Nothing here uses a toy table."""
    return build_alias_index(load_policy(shipped_policy_dir).aliases)


@pytest.fixture
def stored_scan(db_session):
    """A ``scans`` row for findings to hang off."""
    scan = Scan(
        mode=ScanMode.FILES,
        source_type=SourceType.FOLDER,
        source_ref="/tmp/whatever",
        data_lifetime_years=20,
        policy_version="2026.09",
        status=ScanStatus.RUNNING,
    )
    db_session.add(scan)
    db_session.flush()
    return scan


def observed(name: str, **kwargs) -> RawFinding:
    """A raw finding with the fields a test is not talking about left alone."""
    kwargs.setdefault("collector", CollectorName.CERTS)
    kwargs.setdefault("source_layer", SourceLayer.ARTIFACT)
    return RawFinding(algorithm_name=name, **kwargs)


def findings_of(session, scan_id) -> list[Finding]:
    query = sa.select(Finding).where(Finding.scan_id == scan_id).order_by(Finding.id)
    return list(session.scalars(query))


# --------------------------------------------------------------------------- #
# Identity resolution
# --------------------------------------------------------------------------- #


def test_sha1_spellings_and_the_sha1_oid_resolve_to_one_identity(alias_index) -> None:
    """The §8 example, and the reason this module exists."""
    by_name = resolve(observed("SHA-1"), alias_index)
    by_lowercase = resolve(observed("sha1"), alias_index)
    # What the certificate collector emits when the library has no short name for
    # an OID: the dotted string lands in `algorithm_name` as well.
    by_oid = resolve(observed(SHA1_OID, algorithm_oid=SHA1_OID), alias_index)

    families = {by_name.family, by_lowercase.family, by_oid.family}
    oids = {by_name.oid, by_lowercase.oid, by_oid.oid}

    assert families == {"SHA-1"}
    assert oids == {SHA1_OID}
    assert {by_name.entry.id, by_lowercase.entry.id, by_oid.entry.id} == {"sha-1"}


def test_a_composite_signature_collapses_to_its_hash_and_keeps_its_own_oid(
    alias_index,
) -> None:
    """``SHA1withRSA`` is one identity with SHA-1 — but it is not the SHA-1 OID.

    The family is what the dashboard counts, so it collapses. The OID is what a
    disputed finding is traced by, so it stays exactly as the certificate wrote
    it; rewriting it into the bare hash OID would make the trace point at
    something the artefact never said.
    """
    identity = resolve(
        observed("sha1WithRSAEncryption", algorithm_oid=SHA1_WITH_RSA_OID), alias_index
    )

    assert identity.family == "SHA-1"
    assert identity.oid == SHA1_WITH_RSA_OID
    # The RSA half is not lost, it is recorded rather than counted as a use.
    assert identity.entry.components == ("RSA",)

    # …and the spelling with no OID at all resolves to the same family.
    assert resolve(observed("SHA1withRSA"), alias_index).family == "SHA-1"


def test_md5_in_python_and_in_java_land_on_one_family(alias_index) -> None:
    """demo/README.md §D's cross-language check, stated as a test."""
    python_side = resolve(
        observed("hashlib.md5", collector=CollectorName.CODE, source_layer=SourceLayer.SOURCE),
        alias_index,
    )
    java_side = resolve(
        observed("MD5", collector=CollectorName.CODE, source_layer=SourceLayer.SOURCE),
        alias_index,
    )

    assert python_side.family == java_side.family == "MD5"
    assert python_side.oid == java_side.oid == "1.2.840.113549.2.5"


def test_the_two_spellings_of_one_cipher_suite_collapse(alias_index) -> None:
    """nginx writes ``DES-CBC3-SHA``; sslyze reports the IANA name for the same suite.

    They are one declaration and one observation of one suite, and the drift
    check in step 8 can only compare them if they carry one identity.
    """
    from_config = resolve(
        observed(
            "DES-CBC3-SHA",
            collector=CollectorName.CONFIG,
            source_layer=SourceLayer.CONFIG,
            primitive=Primitive.CIPHER,
        ),
        alias_index,
    )
    from_probe = resolve(
        observed(
            "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
            collector=CollectorName.NETWORK,
            source_layer=SourceLayer.LIVE,
            primitive=Primitive.CIPHER,
        ),
        alias_index,
    )

    assert from_config.family == from_probe.family == "TLS_RSA_WITH_3DES_EDE_CBC_SHA"


def test_a_name_the_table_does_not_carry_is_kept_as_observed(alias_index) -> None:
    """No guessing. The gap is recorded as a gap, and the row stays countable.

    The policy engine answers ``unknown`` for it (§10), which is the honest
    outcome — an identity invented here would be laundered into a verdict there.
    """
    identity = resolve(observed("SuperCipher-9000"), alias_index)

    assert identity.resolved is False
    assert identity.entry is None
    assert identity.family == "SuperCipher-9000"

    row = _row_for(observed("SuperCipher-9000"), alias_index)
    assert row.evidence_raw["normalization"] == {
        "identity_resolved": False,
        "alias_id": None,
        "observed_name": "SuperCipher-9000",
    }


def test_the_hygiene_markers_the_collectors_emit_still_get_a_family(alias_index) -> None:
    """``private-key-file`` is not an algorithm, and it is still a row worth counting."""
    identity = resolve(observed("private-key-file"), alias_index)

    assert identity.resolved is False
    assert identity.family == "private-key-file"


def test_the_table_fills_gaps_the_observation_left(alias_index) -> None:
    """``aes128-ctr`` names a size and a mode; an sshd_config line does not repeat them."""
    identity = resolve(
        observed(
            "aes128-ctr", collector=CollectorName.CONFIG, source_layer=SourceLayer.CONFIG
        ),
        alias_index,
    )

    assert identity.family == "AES"
    assert identity.key_size == 128
    assert identity.mode == "CTR"


def test_an_observed_primitive_beats_the_table(alias_index) -> None:
    """The certificate case, and it decides a verdict.

    The alias entry calls SHA-1 a hash, because that is what the name usually
    means. The certificate collector saw it signing a certificate. Keeping the
    observation is what lets ``sha1-signature`` fire here while a bare
    ``hashlib.sha1()`` call resolves to ``unknown`` — which is the distinction
    demo/README.md's policy-gap table is built on.
    """
    signing = resolve(observed("SHA-1", primitive=Primitive.SIGNATURE), alias_index)
    hashing = resolve(observed("SHA-1"), alias_index)

    assert signing.primitive is Primitive.SIGNATURE
    assert hashing.primitive is Primitive.HASH
    assert signing.family == hashing.family == "SHA-1"


def test_protocol_versions_are_canonicalised_for_the_policy_comparison(alias_index) -> None:
    """``algorithms.yaml`` compares ``protocol_version_lt: "1.2"``.

    So ``TLSv1`` has to arrive as ``1.0``, not as the four spellings nginx,
    OpenSSL, sslyze and the JDK each use for it.
    """
    weak = resolve(
        observed("TLSv1", primitive=Primitive.PROTOCOL, protocol_version="TLSv1"), alias_index
    )
    floor = resolve(
        observed("TLSv1.2", primitive=Primitive.PROTOCOL, protocol_version="TLSv1.2"),
        alias_index,
    )

    assert (weak.family, weak.protocol_version) == ("TLS", "1.0")
    assert (floor.family, floor.protocol_version) == ("TLS", "1.2")

    # SSL is its own family: "3.0" is not less than "1.2", so filing it under TLS
    # would let the oldest protocol in the file pass a numeric comparison.
    sslv3 = resolve(observed("SSLv3", primitive=Primitive.PROTOCOL), alias_index)
    assert (sslv3.family, sslv3.protocol_version) == ("SSL", "3.0")

    # A version nobody has written a rule for is kept verbatim rather than parsed
    # into a number that would sort by accident.
    unknown = resolve(observed("TLSv9.9", protocol_version="TLSv9.9"), alias_index)
    assert unknown.protocol_version == "TLSv9.9"


def test_a_suite_carries_the_protocol_version_it_was_observed_at(alias_index) -> None:
    """The suite name says nothing about the version; the handshake that offered it does."""
    identity = resolve(
        observed(
            "AES128-SHA",
            collector=CollectorName.NETWORK,
            source_layer=SourceLayer.LIVE,
            primitive=Primitive.CIPHER,
            protocol_version="TLSv1.0",
        ),
        alias_index,
    )

    assert identity.family == "TLS_RSA_WITH_AES_128_CBC_SHA"
    assert identity.protocol_version == "1.0"


# --------------------------------------------------------------------------- #
# Confidence (§7's per-collector guidance)
# --------------------------------------------------------------------------- #


def test_confidence_falls_back_to_the_collectors_own_default(alias_index) -> None:
    """§7.2 rates a ``.rodata`` string below a linked symbol; the default is the weaker."""
    from_binary = resolve(
        observed("MD5", collector=CollectorName.BINARY, confidence=None), alias_index
    )
    from_certs = resolve(observed("RSA", confidence=None), alias_index)
    stated = resolve(
        observed("MD5", collector=CollectorName.NETWORK, confidence=Confidence.LOW),
        alias_index,
    )

    assert from_binary.confidence is Confidence.MEDIUM
    assert from_certs.confidence is Confidence.HIGH
    # A collector that says "this one is weaker than my usual" is believed.
    assert stated.confidence is Confidence.LOW


# --------------------------------------------------------------------------- #
# Source layer tagging
# --------------------------------------------------------------------------- #


def test_a_certificate_finding_is_tagged_artifact(
    db_session, stored_scan, scan_context, weak_cert_pem
) -> None:
    ctx = scan_context({"etc/ssl/weak.crt": weak_cert_pem})

    rows = normalize(db_session, stored_scan.id, CertificateCollector().collect(ctx))

    assert rows, "the committed weak certificate must produce findings"
    assert {row.source_layer for row in rows} == {SourceLayer.ARTIFACT}
    # And the certificate's own signature resolved, rather than being stored raw.
    signatures = [row for row in rows if row.algorithm_oid == SHA1_WITH_RSA_OID]
    assert [row.algorithm_family for row in signatures] == ["SHA-1"]


def test_an_openssl_cnf_finding_is_tagged_config(
    db_session, stored_scan, scan_context, demo_dir: Path
) -> None:
    """A declaration, not an observation — the tag §9 compares against ``live``."""
    text = (demo_dir / "weak-nginx" / "openssl.cnf").read_text(encoding="utf-8")
    ctx = scan_context({"etc/ssl/openssl.cnf": text})

    rows = normalize(db_session, stored_scan.id, ConfigCollector().collect(ctx))

    assert {row.source_layer for row in rows} == {SourceLayer.CONFIG}
    floors = [row for row in rows if row.evidence_raw["observation"] == "protocol_floor"]
    assert len(floors) == 1
    assert (floors[0].algorithm_family, floors[0].protocol_version) == ("TLS", "1.2")


def test_the_layer_ordering_is_the_precedence_rule() -> None:
    """§8's ordering, which step 8 resolves live-versus-config disagreements with."""
    assert LAYER_PRECEDENCE == (
        SourceLayer.LIVE,
        SourceLayer.ARTIFACT,
        SourceLayer.CONFIG,
        SourceLayer.SOURCE,
    )
    assert layer_rank(SourceLayer.LIVE) < layer_rank(SourceLayer.CONFIG)
    assert layer_rank(SourceLayer.CONFIG) < layer_rank(SourceLayer.SOURCE)


# --------------------------------------------------------------------------- #
# Storing
# --------------------------------------------------------------------------- #


def test_every_observation_becomes_exactly_one_row(db_session, stored_scan) -> None:
    """The normalizer renames things. It does not merge them and it does not drop them.

    A user who was told the scan produced eleven findings must find eleven rows;
    a silent merge would make the two numbers disagree with no way to tell which
    one lied.
    """
    raws = [
        observed("SHA-1"),
        observed("sha1"),
        observed("SHA-1"),
        observed("SuperCipher-9000"),
    ]

    rows = normalize(db_session, stored_scan.id, raws)

    assert len(rows) == len(raws)
    assert len(findings_of(db_session, stored_scan.id)) == len(raws)
    # Three spellings of one algorithm are still three uses of it.
    assert sum(row.algorithm_family == "SHA-1" for row in rows) == 3


def test_the_observed_spelling_survives_on_the_row(db_session, stored_scan) -> None:
    """``algorithm_name`` is what the artefact said; the family is what we filed it under."""
    rows = normalize(db_session, stored_scan.id, [observed("sha1WithRSAEncryption")])

    assert rows[0].algorithm_name == "sha1WithRSAEncryption"
    assert rows[0].algorithm_family == "SHA-1"
    assert rows[0].evidence_raw["normalization"]["alias_id"] == "sha1-with-rsa"
    assert rows[0].evidence_raw["normalization"]["alias_source"]


def test_the_evidence_the_collector_gathered_is_not_overwritten(
    db_session, stored_scan
) -> None:
    rows = normalize(
        db_session,
        stored_scan.id,
        [observed("RSA", key_size=1024, evidence_raw={"file": "weak.crt", "curve": None})],
    )

    assert rows[0].evidence_raw["file"] == "weak.crt"
    assert rows[0].evidence_raw["normalization"]["identity_resolved"] is True


def test_a_demo_scan_lands_in_findings_with_a_family_on_every_row(
    demo_scan, db_session
) -> None:
    """The build step 5 exit test, run through the API exactly as a user would.

    ``algorithm_family`` is not nullable in practice even though the column
    allows it: an unresolved name keeps its own spelling, so a null here would
    mean a row went through the normalizer without being looked at.
    """
    rows = findings_of(db_session, UUID(demo_scan["scan_id"]))

    assert len(rows) == demo_scan["finding_count"] > 0
    assert all(row.algorithm_family for row in rows)
    assert all(row.evidence_raw["normalization"]["observed_name"] for row in rows)

    # The committed half of the demo tree guarantees these: two nginx.conf and
    # two openssl.cnf declare TLS versions, and every one of them is a claim.
    tls = [row for row in rows if row.algorithm_family == "TLS"]
    assert tls, "the demo's nginx and openssl configs declare TLS versions"
    assert {row.protocol_version for row in tls} <= {"1.0", "1.1", "1.2", "1.3"}
    assert {row.source_layer for row in tls} == {SourceLayer.CONFIG}


# --------------------------------------------------------------------------- #
# The table itself
# --------------------------------------------------------------------------- #


def test_the_shipped_table_covers_the_algorithms_the_build_plan_names() -> None:
    """Build step 5's minimum list. A family missing here splits into duplicate rows."""
    index = build_alias_index(load_policy(Path(__file__).parent.parent / "policy").aliases)
    families = {entry.family for entry in index.entries}

    required = {
        "MD5", "SHA-1", "SHA-256", "SHA-384", "SHA-512",
        "RSA", "DSA", "ECDSA", "ECDH", "EdDSA", "DH",
        "AES", "DES", "3DES", "RC4", "TLS",
    }
    assert required <= families, f"missing from the alias table: {sorted(required - families)}"

    for version in ("TLSv1", "TLSv1.1", "TLSv1.2", "TLSv1.3"):
        assert index.by_spelling(version) is not None, version


def test_every_alias_entry_carries_a_citation(alias_index) -> None:
    for entry in alias_index.entries:
        assert entry.source.strip(), f"alias entry {entry.id!r} has no citation"


def test_an_alias_entry_without_a_citation_is_refused() -> None:
    """Same rule as ``algorithms.yaml`` (§6): an uncited mapping is not traceable."""
    with pytest.raises(AliasError) as caught:
        build_alias_index({"sha-1": {"family": "SHA-1", "names": ["SHA-1"]}})

    assert "sha-1" in str(caught.value)
    assert "source" in str(caught.value)


def test_two_entries_cannot_claim_one_spelling() -> None:
    """Otherwise which identity a name resolves to depends on dict order."""
    with pytest.raises(AliasError) as caught:
        build_alias_index(
            {
                "sha-1": {"family": "SHA-1", "source": "RFC 3279", "names": ["SHA-1"]},
                "sha-one": {"family": "SHA1", "source": "RFC 3279", "names": ["sha1"]},
            }
        )

    assert "sha-1" in str(caught.value) and "sha-one" in str(caught.value)


def test_two_entries_cannot_claim_one_oid() -> None:
    with pytest.raises(AliasError) as caught:
        build_alias_index(
            {
                "a": {"family": "SHA-1", "source": "RFC 3279", "oid": SHA1_OID},
                "b": {"family": "SHA-2", "source": "RFC 3279", "oid": SHA1_OID},
            }
        )

    assert SHA1_OID in str(caught.value)


def test_a_mistyped_field_name_is_refused() -> None:
    """A typo'd key is otherwise silent, and shows up days later as a dashboard oddity."""
    with pytest.raises(AliasError) as caught:
        build_alias_index(
            {"aes": {"family": "AES", "source": "FIPS 197", "keysize": 128}}
        )

    assert "keysize" in str(caught.value)


def _row_for(raw: RawFinding, index) -> Finding:
    """A finding built without a session, for assertions about the row's contents."""
    from app.core.normalizer import to_finding

    return to_finding(uuid4(), raw, index)
