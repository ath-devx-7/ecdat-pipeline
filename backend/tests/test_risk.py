"""Risk scorer — SPEC.md §12.

The primitive gate is what these tests exist for. Mosca's inequality is a
statement about harvest-now-decrypt-later, and applying it to a signature is the
single most common way to get this component wrong: it ranks a certificate's
signing key as urgently as the key exchange protecting the traffic, and quietly
reorders somebody's migration budget.

So the first test is a signature and a key exchange sitting side by side under
identical inputs, ending up in different waves for a reason that can be read off
the row.
"""

from __future__ import annotations

from pathlib import Path
from uuid import UUID

import pytest
import sqlalchemy as sa

from app.core.policy_loader import load_policy
from app.core.risk import (
    CONFIDENTIALITY_PRIMITIVES,
    score_finding,
    score_scan,
)
from app.models.analysis import RiskScore, VerdictRow
from app.models.enums import (
    CollectorName,
    Confidence,
    Primitive,
    ScanMode,
    ScanStatus,
    SourceLayer,
    SourceType,
    Verdict,
    Wave,
)
from app.models.finding import Finding
from app.models.scan import Scan


@pytest.fixture
def pack(shipped_policy_dir: Path):
    """The pack as it ships: Z = 12, Y = 1."""
    return load_policy(shipped_policy_dir)


@pytest.fixture
def scan_factory(db_session):
    def _factory(data_lifetime_years: int | None = 20) -> Scan:
        scan = Scan(
            mode=ScanMode.FILES,
            source_type=SourceType.FOLDER,
            source_ref="/tmp/whatever",
            data_lifetime_years=data_lifetime_years,
            policy_version="2026.09",
            status=ScanStatus.RUNNING,
        )
        db_session.add(scan)
        db_session.flush()
        return scan

    return _factory


def finding(family: str, primitive: Primitive, **kwargs) -> Finding:
    kwargs.setdefault("collector", CollectorName.NETWORK)
    kwargs.setdefault("algorithm_name", family)
    kwargs.setdefault("source_layer", SourceLayer.LIVE)
    kwargs.setdefault("confidence", Confidence.HIGH)
    return Finding(algorithm_family=family, primitive=primitive, **kwargs)


def score(family, primitive, verdict, pack, *, x=20, z=None, **kwargs):
    return score_finding(
        finding(family, primitive, **kwargs),
        verdict,
        data_lifetime_years=x,
        policy=pack,
        z_years=z,
    )


# --------------------------------------------------------------------------- #
# The primitive gate
# --------------------------------------------------------------------------- #


def test_a_signature_finding_gets_no_urgency_and_lands_in_wave_3(pack) -> None:
    """§12's required test, and the distinction the component exists to make.

    Forging a signature in 2035 does not retroactively forge a 2026 transaction.
    There is no harvest step, so the data's lifetime is irrelevant — X could be a
    century and the answer would not move.
    """
    decision = score("ECDSA", Primitive.SIGNATURE, Verdict.QUANTUM_VULNERABLE, pack, x=20)

    assert decision.urgency_years is None
    assert decision.wave is Wave.WAVE_3
    assert decision.rationale["hndl_applicable"] is False
    assert "harvest" in decision.rationale["because"]

    # A century of data lifetime does not move it, which is the point.
    a_century = score("ECDSA", Primitive.SIGNATURE, Verdict.QUANTUM_VULNERABLE, pack, x=100)
    assert a_century.wave is Wave.WAVE_3


def test_a_key_exchange_finding_with_a_long_lifetime_is_overdue(pack) -> None:
    """§12's required test. (20 + 1) − 12 = 9 years overdue."""
    decision = score("ECDH", Primitive.KEY_EXCHANGE, Verdict.QUANTUM_VULNERABLE, pack, x=20)

    assert decision.urgency_years == 9
    assert decision.wave in (Wave.WAVE_1, Wave.WAVE_2)
    assert decision.rationale["hndl_applicable"] is True


def test_the_same_finding_with_a_short_lifetime_is_not(pack) -> None:
    """§12's required test, and the clearest demonstration that this is not a sort.

    Identical algorithm, identical verdict, identical everything except how long
    the data has to stay secret — and it moves out of the migration waves
    entirely. A severity ranking cannot express that.
    """
    decision = score("ECDH", Primitive.KEY_EXCHANGE, Verdict.QUANTUM_VULNERABLE, pack, x=1)

    assert decision.urgency_years == -10
    assert decision.wave is Wave.WAVE_3


def test_a_cipher_is_a_confidentiality_primitive_too(pack) -> None:
    """§12 names two, not one. Traffic under a recorded cipher is harvestable."""
    assert CONFIDENTIALITY_PRIMITIVES == {Primitive.KEY_EXCHANGE, Primitive.CIPHER}

    decision = score("3DES", Primitive.CIPHER, Verdict.QUANTUM_VULNERABLE, pack, x=20)

    assert decision.rationale["hndl_applicable"] is True
    assert decision.urgency_years == 9


@pytest.mark.parametrize("primitive", [Primitive.HASH, Primitive.PROTOCOL, Primitive.UNKNOWN])
def test_mosca_does_not_apply_to_anything_that_is_not_confidentiality(
    pack, primitive
) -> None:
    """Nothing recorded now becomes readable later, so X does not enter the sum.

    §12 singles out signatures because that is the tempting mistake, but the
    reasoning is about confidentiality rather than about signatures: a hash has
    no harvest step either.
    """
    decision = score("SHA-1", primitive, Verdict.QUANTUM_VULNERABLE, pack, x=20)

    assert decision.urgency_years is None
    assert decision.wave is Wave.WAVE_3
    assert decision.rationale["hndl_applicable"] is False


# --------------------------------------------------------------------------- #
# Waves
# --------------------------------------------------------------------------- #


def test_a_broken_now_finding_lands_in_wave_0_regardless_of_primitive(pack) -> None:
    """§12's required test. This is a today deadline, not a quantum one."""
    for primitive in Primitive:
        decision = score("MD5", primitive, Verdict.BROKEN_NOW, pack, x=1)

        assert decision.wave is Wave.WAVE_0, primitive
        # Mosca is not consulted at all: a short data lifetime does not make a
        # broken algorithm less broken.
        assert decision.urgency_years is None
        assert decision.rationale["hndl_applicable"] is False


def test_a_low_confidence_finding_lands_in_verify(pack) -> None:
    """§12's required test, and it outranks every other branch.

    The action a shaky observation needs is confirmation. Filing it as wave_0
    would send somebody after an algorithm that may not be there.
    """
    decision = score(
        "MD5", Primitive.HASH, Verdict.BROKEN_NOW, pack, confidence=Confidence.LOW
    )

    assert decision.wave is Wave.VERIFY
    assert "low confidence" in decision.rationale["because"]


def test_an_unknown_verdict_lands_in_verify(pack) -> None:
    """"Not assessed" is not "safe", and the wave says which one it is."""
    decision = score("3DES", Primitive.CIPHER, Verdict.UNKNOWN, pack)

    assert decision.wave is Wave.VERIFY
    assert "unknown" in decision.rationale["because"]


def test_high_effort_migrations_get_their_own_wave(pack) -> None:
    """§12: wave_2 is separated because high effort is *why* it needs budgeting now.

    The shipped pack does not currently produce this combination — every
    quantum-vulnerable confidentiality family in it maps to `kex-to-mlkem`, whose
    action class is `config` — so the verdict is supplied directly to exercise
    the branch rather than waiting for a pack that has one.
    """
    decision = score("3DES", Primitive.CIPHER, Verdict.QUANTUM_VULNERABLE, pack, x=20)

    assert decision.wave is Wave.WAVE_2
    assert decision.rationale["action_class"] == "code_change"
    assert decision.rationale["action_class_rule"] == "cipher-upgrade"


def test_an_overdue_finding_of_unknown_effort_is_budgeted_rather_than_assumed_cheap(
    pack,
) -> None:
    """No ``pqc_targets`` rule names the effort, so the cheap wave is not assumed.

    Filing it with the config changes would let it slip a planning cycle on an
    assumption nothing supports. The rationale records that no rule matched, so
    the choice is visible rather than looking like a measurement.
    """
    decision = score("ExoticKEX", Primitive.KEY_EXCHANGE, Verdict.QUANTUM_VULNERABLE, pack)

    assert decision.wave is Wave.WAVE_2
    assert decision.rationale["action_class"] is None
    assert decision.rationale["matched_pqc_targets"] == []
    assert "no pqc_targets rule" in decision.rationale["because"]


def test_a_low_effort_migration_lands_in_wave_1(pack) -> None:
    decision = score("RSA", Primitive.KEY_EXCHANGE, Verdict.QUANTUM_VULNERABLE, pack, x=20)

    assert decision.wave is Wave.WAVE_1
    assert decision.rationale["action_class"] == "config"
    assert decision.rationale["action_class_rule"] == "kex-to-mlkem"


# --------------------------------------------------------------------------- #
# What gets no wave at all
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("verdict", [Verdict.QUANTUM_SAFE, Verdict.HYGIENE])
def test_a_finding_that_needs_no_migration_gets_no_wave(pack, verdict) -> None:
    """§12's table covers neither, and inventing a wave would put them on a roadmap.

    demo/README.md records this as a wave of "—". A risk score says *when this
    must be migrated*; AES-256 does not have to be.
    """
    assert score("AES", Primitive.CIPHER, verdict, pack, x=20) is None


# --------------------------------------------------------------------------- #
# The arithmetic, and its audit trail
# --------------------------------------------------------------------------- #


def test_the_formula_is_x_plus_y_minus_z(pack) -> None:
    """No weighting, no curve, no model. (X + Y) − Z, and positive means overdue."""
    for x, expected in ((0, -11), (11, 0), (12, 1), (20, 9)):
        decision = score("ECDH", Primitive.KEY_EXCHANGE, Verdict.QUANTUM_VULNERABLE, pack, x=x)
        assert decision.urgency_years == (x + 1) - 12 == expected


def test_the_rationale_carries_all_three_mosca_inputs(pack) -> None:
    """§12's required test. An auditor must reconstruct the wave from the row."""
    decision = score("ECDH", Primitive.KEY_EXCHANGE, Verdict.QUANTUM_VULNERABLE, pack, x=20)

    assert decision.rationale["x_years"] == 20
    assert decision.rationale["y_years"] == 1
    assert decision.rationale["z_years"] == 12
    # …and every other factor that produced the wave, per §12's example object.
    expected = (
        "verdict", "primitive", "hndl_applicable", "urgency_years", "confidence", "wave",
    )
    for key in expected:
        assert key in decision.rationale, key
    assert (
        decision.rationale["x_years"] + decision.rationale["y_years"]
        - decision.rationale["z_years"]
        == decision.rationale["urgency_years"]
    )


def test_the_inputs_are_stored_even_when_mosca_did_not_apply(pack) -> None:
    """§12: store all three inputs on every row, not just the ones that were used.

    ``urgency_years = null`` beside a populated X is what tells an auditor the
    gate fired, rather than the arithmetic having been skipped by accident.
    """
    decision = score("ECDSA", Primitive.SIGNATURE, Verdict.QUANTUM_VULNERABLE, pack, x=20)

    assert (decision.x_years, decision.y_years, decision.z_years) == (20, 1, 12)
    assert decision.urgency_years is None


def test_a_missing_data_lifetime_is_not_treated_as_not_urgent(pack) -> None:
    """X is the one input the user supplies, and there is no safe default for it.

    Assuming a short lifetime would quietly file every harvestable finding as not
    overdue — assuming safety, which §10's philosophy rules out everywhere else.
    """
    decision = score("ECDH", Primitive.KEY_EXCHANGE, Verdict.QUANTUM_VULNERABLE, pack, x=None)

    assert decision.wave is Wave.VERIFY
    assert decision.urgency_years is None
    assert "data_lifetime_years was not supplied" in decision.rationale["because"]


def test_z_can_be_overridden_so_the_slider_changes_the_answer(pack) -> None:
    """§12 exposes Z as a UI slider: it is an assumption, not a measurement.

    Letting a user test their plan against a sooner arrival is more honest than
    hardcoding one date, and the row records the Z that was actually used.
    """
    default = score("ECDH", Primitive.KEY_EXCHANGE, Verdict.QUANTUM_VULNERABLE, pack, x=5)
    sooner = score("ECDH", Primitive.KEY_EXCHANGE, Verdict.QUANTUM_VULNERABLE, pack, x=5, z=3)

    assert default.wave is Wave.WAVE_3 and default.urgency_years == -6
    assert sooner.wave is Wave.WAVE_1 and sooner.urgency_years == 3
    assert sooner.z_years == 3


# --------------------------------------------------------------------------- #
# Storing
# --------------------------------------------------------------------------- #


def stored_scores(session, scan) -> list[RiskScore]:
    query = (
        sa.select(RiskScore)
        .join(Finding, Finding.id == RiskScore.finding_id)
        .where(Finding.scan_id == scan.id)
    )
    return list(session.scalars(query))


def with_verdict(session, scan, family, primitive, verdict, **kwargs) -> Finding:
    row = finding(family, primitive, scan_id=scan.id, **kwargs)
    session.add(row)
    session.flush()
    session.add(
        VerdictRow(
            finding_id=row.id,
            verdict=verdict,
            rule_id="test-rule",
            source_citation="test",
            policy_version="2026.09",
        )
    )
    session.flush()
    return row


def test_scoring_a_scan_writes_a_row_only_for_what_needs_migrating(
    db_session, scan_factory
) -> None:
    scan = scan_factory(20)
    with_verdict(db_session, scan, "ECDH", Primitive.KEY_EXCHANGE, Verdict.QUANTUM_VULNERABLE)
    with_verdict(db_session, scan, "ECDSA", Primitive.SIGNATURE, Verdict.QUANTUM_VULNERABLE)
    with_verdict(db_session, scan, "AES", Primitive.CIPHER, Verdict.QUANTUM_SAFE)

    scores = score_scan(db_session, scan)

    assert len(scores) == 2
    assert {row.wave for row in scores} == {Wave.WAVE_1, Wave.WAVE_3}
    assert len(stored_scores(db_session, scan)) == 2


def test_rescoring_replaces_the_rows_rather_than_adding_to_them(
    db_session, scan_factory
) -> None:
    """What makes the Z slider work: the same scan, re-scored under a new assumption."""
    scan = scan_factory(5)
    with_verdict(db_session, scan, "ECDH", Primitive.KEY_EXCHANGE, Verdict.QUANTUM_VULNERABLE)

    score_scan(db_session, scan)
    rescored = score_scan(db_session, scan, z_years=3)

    assert len(stored_scores(db_session, scan)) == 1
    assert rescored[0].wave is Wave.WAVE_1
    assert rescored[0].z_years == 3


# --------------------------------------------------------------------------- #
# Through the pipeline
# --------------------------------------------------------------------------- #


def test_the_demo_puts_signatures_and_key_exchanges_in_different_waves(
    demo_scan, db_session
) -> None:
    """demo/README.md §B: the best illustration of the gate in the whole demo.

    One clean host, two findings, identical inputs — and they are in different
    waves because one is harvestable and the other is not.
    """
    rows = db_session.execute(
        sa.select(Finding, RiskScore)
        .join(RiskScore, RiskScore.finding_id == Finding.id)
        .where(Finding.scan_id == UUID(demo_scan["scan_id"]))
    ).all()

    by_primitive: dict[str, set[str]] = {}
    for finding_row, score_row in rows:
        by_primitive.setdefault(finding_row.primitive.value, set()).add(score_row.wave.value)

    assert by_primitive["key_exchange"] == {"wave_1"}
    assert by_primitive["signature"] <= {"wave_0", "wave_3"}
    # Every signature that reached a migration wave did so with no urgency at all.
    for finding_row, score_row in rows:
        if finding_row.primitive is Primitive.SIGNATURE:
            assert score_row.urgency_years is None


def test_shortening_the_data_lifetime_moves_findings_out_of_the_migration_waves(
    client, demo_dir: Path, approve_all_files, db_session
) -> None:
    """demo/README.md's headline demonstration, run twice.

    Re-running at X=1 and watching findings move to wave_3 is the clearest
    argument that the scorer is not a severity sort — nothing about the
    algorithms changed, only how long their traffic has to stay secret.
    """
    waves_by_lifetime = {}
    for lifetime in (20, 1):
        created = client.post(
            "/api/scans",
            json={
                "mode": "files",
                "source_type": "folder",
                "source_ref": str(demo_dir),
                "data_lifetime_years": lifetime,
            },
        )
        waves_by_lifetime[lifetime] = approve_all_files(created.json()["id"])["wave_counts"]

    assert waves_by_lifetime[20].get("wave_1", 0) > 0
    assert waves_by_lifetime[1].get("wave_1", 0) == 0
    # They did not vanish — they moved.
    assert waves_by_lifetime[1]["wave_3"] > waves_by_lifetime[20]["wave_3"]
    # And what is broken today is unmoved by any of it.
    assert waves_by_lifetime[1]["wave_0"] == waves_by_lifetime[20]["wave_0"]
