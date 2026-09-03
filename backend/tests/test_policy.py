"""Policy engine — SPEC.md §10.

These are the tests a cryptographer would check first, and most of them are
guarding against one specific wrong answer rather than exercising a code path.
A tool that calls AES quantum-vulnerable is wrong in a way that is spotted in
thirty seconds and remembered for years, and the reason it would be wrong is not
a bug in the lookup — it is someone deciding that "vulnerable" and "broken" sit
on one scale and sorting by it.

The other half of the file is about the pack rather than the engine: a condition
key the engine does not implement does not fail, it *widens*, and a rule that
quietly matches everything of its family is far worse than one that crashes.
"""

from __future__ import annotations

from pathlib import Path
from uuid import UUID

import pytest
import sqlalchemy as sa

from app.core.policy import (
    NO_RULE_CITATION,
    VERDICT_PRECEDENCE,
    apply_policy,
    classify,
    validate_rules,
)
from app.core.policy_loader import PolicyValidationError, load_policy
from app.models.analysis import VerdictRow
from app.models.enums import (
    CollectorName,
    Primitive,
    ScanMode,
    ScanStatus,
    SourceLayer,
    SourceType,
    Verdict,
)
from app.models.finding import Finding
from app.models.scan import Scan

MD5_OID = "1.2.840.113549.2.5"


@pytest.fixture
def pack(shipped_policy_dir: Path):
    """The pack as it ships. Every assertion below is about the real policy."""
    return load_policy(shipped_policy_dir)


@pytest.fixture
def stored_scan(db_session):
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


def finding(family: str | None = None, **kwargs) -> Finding:
    """A findings row shaped the way the normalizer would have written it."""
    kwargs.setdefault("collector", CollectorName.CODE)
    kwargs.setdefault("algorithm_name", family or "unnamed")
    kwargs.setdefault("source_layer", SourceLayer.SOURCE)
    kwargs.setdefault("primitive", Primitive.UNKNOWN)
    return Finding(algorithm_family=family, **kwargs)


def verdicts_for(session, scan_id) -> list[VerdictRow]:
    query = (
        sa.select(VerdictRow)
        .join(Finding, Finding.id == VerdictRow.finding_id)
        .where(Finding.scan_id == scan_id)
    )
    return list(session.scalars(query))


# --------------------------------------------------------------------------- #
# The answers a cryptographer checks
# --------------------------------------------------------------------------- #


def test_aes_256_is_quantum_safe_and_never_quantum_vulnerable(pack) -> None:
    """Grover weakens symmetric crypto; it does not break it (§6).

    This is the assertion the spec singles out, so it is written as a positive
    *and* a negative: getting `quantum_safe` by luck while some other rule also
    fires `quantum_vulnerable` would pass the happy half on its own.
    """
    decision = classify(finding("AES", key_size=256, primitive=Primitive.CIPHER), pack)

    assert decision.verdict is Verdict.QUANTUM_SAFE
    assert decision.rule.id == "aes-safe"
    assert Verdict.QUANTUM_VULNERABLE not in {
        Verdict(rule.verdict) for rule in decision.matches
    }


def test_sha_256_is_quantum_safe(pack) -> None:
    decision = classify(finding("SHA-256", primitive=Primitive.HASH), pack)

    assert decision.verdict is Verdict.QUANTUM_SAFE
    assert decision.source_citation


def test_rsa_4096_is_quantum_vulnerable_and_not_broken_now(pack) -> None:
    """The distinction the whole verdict vocabulary exists to make.

    RSA-4096 is perfectly secure today. A tool that reports it as broken teaches
    its users to ignore the word.
    """
    decision = classify(finding("RSA", key_size=4096, primitive=Primitive.SIGNATURE), pack)

    assert decision.verdict is Verdict.QUANTUM_VULNERABLE
    assert decision.rule.id == "rsa-quantum"
    assert Verdict.BROKEN_NOW not in {Verdict(rule.verdict) for rule in decision.matches}


def test_rsa_1024_is_broken_now(pack) -> None:
    """Both rules fire honestly; the reported one is the one that says "not today".

    RSA-1024 really is quantum-vulnerable as well, and `rsa-quantum` stays on the
    decision where it can be seen. What it must not do is outrank a key that is
    too small to use this afternoon.
    """
    decision = classify(finding("RSA", key_size=1024, primitive=Primitive.SIGNATURE), pack)

    assert decision.verdict is Verdict.BROKEN_NOW
    assert decision.rule.id == "rsa-weak-key"
    assert [rule.id for rule in decision.also_matched] == ["rsa-quantum"]


def test_aes_in_ecb_mode_is_broken_now_regardless_of_key_size(pack) -> None:
    """A 256-bit key in ECB is a 256-bit key that leaks the plaintext's structure."""
    for key_size in (128, 256, None):
        decision = classify(
            finding("AES", key_size=key_size, mode="ECB", primitive=Primitive.CIPHER), pack
        )

        assert decision.verdict is Verdict.BROKEN_NOW, key_size
        assert decision.rule.id == "aes-ecb"


def test_an_algorithm_with_no_matching_rule_is_unknown(pack) -> None:
    """Never guess, never assume safe (§10)."""
    decision = classify(finding("SuperCipher-9000", primitive=Primitive.CIPHER), pack)

    assert decision.verdict is Verdict.UNKNOWN
    assert decision.rule is None
    assert decision.rule_id is None
    # Still traceable: the row says why no standard is cited, which is not the
    # same thing as a row where the citation went missing.
    assert decision.source_citation == NO_RULE_CITATION


def test_every_verdict_row_carries_a_source_citation(db_session, stored_scan) -> None:
    """Including the ``unknown`` ones. An untraceable verdict is not evidence."""
    db_session.add_all(
        [
            finding(
                "RSA",
                scan_id=stored_scan.id,
                key_size=1024,
                primitive=Primitive.SIGNATURE,
            ),
            finding("AES", scan_id=stored_scan.id, key_size=256, primitive=Primitive.CIPHER),
            finding("SuperCipher-9000", scan_id=stored_scan.id, primitive=Primitive.CIPHER),
        ]
    )
    db_session.flush()

    rows = apply_policy(db_session, stored_scan.id)

    assert len(rows) == 3
    assert all(row.source_citation and row.source_citation.strip() for row in rows)
    assert all(row.policy_version == "2026.09" for row in rows)


# --------------------------------------------------------------------------- #
# Matching
# --------------------------------------------------------------------------- #


def test_family_and_oid_are_two_names_for_one_algorithm(pack) -> None:
    """``md5-hash`` gives both. A finding carrying either is a finding about MD5."""
    by_family = classify(finding("MD5", primitive=Primitive.HASH), pack)
    by_oid = classify(
        finding(None, algorithm_oid=MD5_OID, primitive=Primitive.HASH), pack
    )

    assert by_family.verdict is by_oid.verdict is Verdict.BROKEN_NOW
    assert by_family.rule.id == by_oid.rule.id == "md5-hash"


def test_a_stated_primitive_must_be_observed_not_assumed(pack) -> None:
    """The Mosca gate, guarded two steps early.

    ``rsa-quantum`` is written for RSA doing key exchange or signing. A finding
    that never recorded which is not evidence of either, and treating `unknown`
    as "whichever makes the rule fire" would put a signature into a
    confidentiality wave in step 9 on the strength of a shrug.
    """
    observed = classify(finding("RSA", key_size=4096, primitive=Primitive.SIGNATURE), pack)
    unobserved = classify(finding("RSA", key_size=4096, primitive=Primitive.UNKNOWN), pack)

    assert observed.verdict is Verdict.QUANTUM_VULNERABLE
    assert unobserved.verdict is Verdict.UNKNOWN
    assert unobserved.primitive is Primitive.UNKNOWN


def test_a_hash_use_of_sha1_hits_nothing_while_a_signature_use_is_broken(pack) -> None:
    """demo/README.md's gap table, stated as a test.

    ``sha1-signature`` is scoped to signatures, so a bare ``hashlib.sha1()`` is
    ``unknown`` — an honest gap in the pack, closable with a cited entry, and
    visibly different from "assessed and fine".
    """
    signing = classify(finding("SHA-1", primitive=Primitive.SIGNATURE), pack)
    hashing = classify(finding("SHA-1", primitive=Primitive.HASH), pack)

    assert signing.verdict is Verdict.BROKEN_NOW
    assert hashing.verdict is Verdict.UNKNOWN


def test_an_unmeasured_key_size_satisfies_no_size_condition(pack) -> None:
    """A missing size is not a small one and not a large one.

    Both directions have to fail. Matching ``key_size_lt`` would invent a broken
    key; matching ``key_size_gte`` would invent a safe one, which is worse.
    """
    rsa = classify(finding("RSA", key_size=None, primitive=Primitive.SIGNATURE), pack)
    aes = classify(finding("AES", key_size=None, primitive=Primitive.CIPHER), pack)

    assert [rule.id for rule in rsa.matches] == ["rsa-quantum"]
    assert aes.verdict is Verdict.UNKNOWN


def test_legacy_tls_versions_are_broken_and_current_ones_are_not(pack) -> None:
    """``protocol_version_lt`` compares the canonical form the normalizer emits (§8)."""
    assert classify(_tls("1.0"), pack).verdict is Verdict.BROKEN_NOW
    assert classify(_tls("1.1"), pack).verdict is Verdict.BROKEN_NOW
    assert classify(_tls("1.2"), pack).verdict is Verdict.UNKNOWN
    assert classify(_tls("1.3"), pack).verdict is Verdict.UNKNOWN

    # A version the normalizer could not canonicalise fails the comparison rather
    # than being parsed into a number that would sort by accident.
    assert classify(_tls("TLSv1"), pack).verdict is Verdict.UNKNOWN


def _tls(version: str) -> Finding:
    return finding(
        "TLS",
        algorithm_name=f"TLS {version}",
        primitive=Primitive.PROTOCOL,
        protocol_version=version,
    )


def test_the_reported_verdict_is_a_reporting_order_not_a_severity_number(pack) -> None:
    """§10: the two classifications stay independent.

    Precedence picks which row is written; it does not rank the outcomes against
    each other for any other purpose, and everything that matched stays visible.
    """
    assert VERDICT_PRECEDENCE == (
        Verdict.BROKEN_NOW,
        Verdict.QUANTUM_VULNERABLE,
        Verdict.HYGIENE,
        Verdict.QUANTUM_SAFE,
    )
    assert Verdict.UNKNOWN not in VERDICT_PRECEDENCE

    decision = classify(finding("RSA", key_size=1024, primitive=Primitive.KEY_EXCHANGE), pack)
    assert {rule.id for rule in decision.matches} == {"rsa-weak-key", "rsa-quantum"}


# --------------------------------------------------------------------------- #
# The pack has to be applicable, not just loadable
# --------------------------------------------------------------------------- #


def test_the_shipped_pack_validates(pack) -> None:
    validate_rules(pack)


def test_a_condition_the_engine_does_not_implement_is_refused(
    policy_dir_factory,
) -> None:
    """The important one. A typo'd condition key does not fail — it widens.

    ``keysize_lt`` silently drops the size constraint from ``rsa-weak-key``,
    which then reports every RSA key in the estate as broken today. That has to
    stop the process, not produce a confident wrong answer for a week.
    """

    def mutate(document):
        entry = next(e for e in document["entries"] if e["id"] == "rsa-weak-key")
        entry["condition"] = {"keysize_lt": 2048}

    directory = policy_dir_factory("algorithms.yaml", mutate)

    with pytest.raises(PolicyValidationError) as caught:
        validate_rules(load_policy(directory))

    assert "rsa-weak-key" in str(caught.value)
    assert "keysize_lt" in str(caught.value)


def test_a_non_integer_key_size_condition_is_refused(policy_dir_factory) -> None:
    def mutate(document):
        entry = next(e for e in document["entries"] if e["id"] == "rsa-weak-key")
        entry["condition"] = {"key_size_lt": "2048"}

    with pytest.raises(PolicyValidationError):
        validate_rules(load_policy(policy_dir_factory("algorithms.yaml", mutate)))


def test_an_entry_cannot_assert_unknown(policy_dir_factory) -> None:
    """``unknown`` is the answer when nothing matched. An entry matching is not that."""

    def mutate(document):
        entry = next(e for e in document["entries"] if e["id"] == "aes-safe")
        entry["verdict"] = "unknown"

    with pytest.raises(PolicyValidationError) as caught:
        validate_rules(load_policy(policy_dir_factory("algorithms.yaml", mutate)))

    assert "aes-safe" in str(caught.value)


def test_a_misspelled_verdict_is_refused(policy_dir_factory) -> None:
    def mutate(document):
        entry = next(e for e in document["entries"] if e["id"] == "aes-safe")
        entry["verdict"] = "quantum-safe"  # hyphen, not underscore

    with pytest.raises(PolicyValidationError):
        validate_rules(load_policy(policy_dir_factory("algorithms.yaml", mutate)))


def test_a_misspelled_primitive_is_refused(policy_dir_factory) -> None:
    def mutate(document):
        entry = next(e for e in document["entries"] if e["id"] == "sha1-signature")
        entry["primitive"] = "signatures"

    with pytest.raises(PolicyValidationError) as caught:
        validate_rules(load_policy(policy_dir_factory("algorithms.yaml", mutate)))

    assert "signatures" in str(caught.value)


# --------------------------------------------------------------------------- #
# Through the pipeline
# --------------------------------------------------------------------------- #


def test_reclassifying_replaces_a_scans_verdicts_rather_than_adding_to_them(
    db_session, stored_scan
) -> None:
    """Rerunning under a newer pack is legitimate; two verdicts on one row is not."""
    db_session.add(
        finding("AES", scan_id=stored_scan.id, key_size=256, primitive=Primitive.CIPHER)
    )
    db_session.flush()

    apply_policy(db_session, stored_scan.id)
    apply_policy(db_session, stored_scan.id)

    assert len(verdicts_for(db_session, stored_scan.id)) == 1


def test_a_demo_scan_gives_every_finding_a_verdict_with_a_citation(
    demo_scan, db_session
) -> None:
    """The build step 6 exit test, run through the API exactly as a user would."""
    scan_id = UUID(demo_scan["scan_id"])
    rows = verdicts_for(db_session, scan_id)

    assert len(rows) == demo_scan["finding_count"] > 0
    assert all(row.source_citation and row.source_citation.strip() for row in rows)
    assert all(row.policy_version for row in rows)
    # A rule fired or it did not, and the two are distinguishable from the row.
    for row in rows:
        if row.rule_id is None:
            assert row.verdict is Verdict.UNKNOWN
            assert row.source_citation == NO_RULE_CITATION
        else:
            assert row.verdict is not Verdict.UNKNOWN

    assert demo_scan["verdict_counts"] == {
        row.verdict.value: sum(1 for other in rows if other.verdict is row.verdict)
        for row in rows
    }


def test_the_demo_scan_produces_the_verdicts_its_readme_promises(
    demo_scan, db_session
) -> None:
    """demo/README.md is the expectations document; this is it as assertions.

    Only the committed half of the tree is asserted — ``demo/certs/`` is
    generated — so this is the config layer: the weak host declares TLS 1.0 and
    1.1, and the strong host's TLS 1.3 declaration hits no rule at all, which is
    correct rather than an omission.
    """
    by_family: dict[str, set[Verdict]] = {}
    query = (
        sa.select(Finding, VerdictRow)
        .join(VerdictRow, VerdictRow.finding_id == Finding.id)
        .where(Finding.scan_id == UUID(demo_scan["scan_id"]))
    )
    for finding_row, verdict_row in db_session.execute(query):
        by_family.setdefault(finding_row.algorithm_family, set()).add(verdict_row.verdict)

    # TLS < 1.2 is broken_now; TLS 1.2 and 1.3 hit no rule, so the family carries
    # both answers across the two demo hosts.
    assert by_family["TLS"] == {Verdict.BROKEN_NOW, Verdict.UNKNOWN}
    # sshd_config declares hmac-md5, which is MD5 used as a hash.
    assert by_family["MD5"] == {Verdict.BROKEN_NOW}
    # …and 3DES has no entry in the pack. demo/README.md lists that as a known
    # gap, closable with a citation. `unknown` is the honest output until then.
    assert by_family["3DES"] == {Verdict.UNKNOWN}
