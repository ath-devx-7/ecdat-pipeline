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
from app.models.scan import Scan, ScanFile


@pytest.fixture
def pack(shipped_policy_dir: Path):
    """The pack as it ships: Z = 12, and Y read from the finding's action class.

    ``y_years_by_action_class`` maps config to 1, library_upgrade to 2,
    code_change to 3 and hardware to 5; ``y_years_default`` (1) is what a
    finding no ``pqc_targets`` rule matches falls back to.
    """
    return load_policy(shipped_policy_dir)


@pytest.fixture
def scan_factory(db_session):
    def _factory(
        data_lifetime_years: int | None = 20, lifetimes: dict[str, int] | None = None
    ) -> Scan:
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
        # The approval screen writes these onto scan_files; the scorer reads
        # them back from there, so the fixture has to go through the same table.
        for path, years in (lifetimes or {}).items():
            db_session.add(
                ScanFile(scan_id=scan.id, path=path, approved=True, data_lifetime_years=years)
            )
        db_session.flush()
        return scan

    return _factory


def finding(family: str, primitive: Primitive, **kwargs) -> Finding:
    kwargs.setdefault("collector", CollectorName.NETWORK)
    kwargs.setdefault("algorithm_name", family)
    kwargs.setdefault("source_layer", SourceLayer.LIVE)
    kwargs.setdefault("confidence", Confidence.HIGH)
    return Finding(algorithm_family=family, primitive=primitive, **kwargs)


def score(family, primitive, verdict, pack, *, x=20, z=None, lifetimes=None, **kwargs):
    return score_finding(
        finding(family, primitive, **kwargs),
        verdict,
        data_lifetime_years=x,
        policy=pack,
        z_years=z,
        file_lifetimes=lifetimes,
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
    # Y is the cipher's own migration effort, not a pack-wide constant: the
    # cheapest route the pack names for 3DES is `cipher-upgrade`, a code_change,
    # which the pack costs at 3 years. (20 + 3) - 12 = 11.
    assert decision.rationale["y_source"] == "action_class:code_change"
    assert decision.urgency_years == 11


@pytest.mark.parametrize("primitive", [Primitive.HASH, Primitive.PROTOCOL])
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


def test_an_unobserved_primitive_goes_to_verify_rather_than_to_a_wave(pack) -> None:
    """An RSA key from a generator: vulnerable, but is it harvestable?

    Nothing recorded what the key is used for. wave_3 would assume "not
    harvestable" and wave_1 would assume the opposite; both are guesses about
    the one input the gate turns on. The action is to find out.
    """
    decision = score("RSA", Primitive.UNKNOWN, Verdict.QUANTUM_VULNERABLE, pack, x=20, key_size=2048)

    assert decision.wave is Wave.VERIFY
    assert decision.urgency_years is None
    assert "primitive was not observed" in decision.rationale["because"]
    # A broken key of unknown use is still broken today, not a thing to verify.
    assert score("RSA", Primitive.UNKNOWN, Verdict.BROKEN_NOW, pack, x=20).wave is Wave.WAVE_0


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

    # Y is resolved for a signature too. Mosca never reaches it — urgency stays
    # null — but the migration effort is no less real for being undated, and a
    # row that dropped Y would look like the arithmetic had been skipped.
    assert (decision.x_years, decision.y_years, decision.z_years) == (20, 2, 12)
    assert decision.rationale["action_class"] == "library_upgrade"
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


# --------------------------------------------------------------------------- #
# Y — the migration effort, read from the finding's own action class
# --------------------------------------------------------------------------- #


def test_two_key_exchanges_at_the_same_x_and_z_get_different_y(pack) -> None:
    """The point of the whole feature: identical inputs, different effort, different Y.

    Both are ECDH, both quantum-vulnerable, both scored at X = 20 and Z = 12.
    The only difference is where they were observed, and that changes the
    cheapest route the pack names — a deployed service is a `KexAlgorithms`-shaped
    config change, a call site in source needs a library that provides ML-KEM
    first. A single pack-wide Y would report those as the same piece of work.
    """
    deployed = score(
        "ECDH", Primitive.KEY_EXCHANGE, Verdict.QUANTUM_VULNERABLE, pack,
        x=20, source_layer=SourceLayer.LIVE,
    )
    in_source = score(
        "ECDH", Primitive.KEY_EXCHANGE, Verdict.QUANTUM_VULNERABLE, pack,
        x=20, source_layer=SourceLayer.SOURCE,
    )

    assert (deployed.y_years, deployed.rationale["action_class"]) == (1, "config")
    assert (in_source.y_years, in_source.rationale["action_class"]) == (2, "library_upgrade")
    assert deployed.rationale["y_source"] == "action_class:config"
    assert in_source.rationale["y_source"] == "action_class:library_upgrade"

    # …and the urgency moves with it, which is what makes the ranking informative.
    assert deployed.urgency_years == 9
    assert in_source.urgency_years == 10


def test_y_can_decide_the_wave_where_the_inequality_crosses_zero(pack) -> None:
    """Same X, same Z, and the effort alone is what makes one of them overdue.

    At X = 11 and Z = 12 a one-year config change lands exactly on the line —
    (11 + 1) − 12 = 0, not overdue — while the same algorithm in source needs a
    two-year library upgrade and is a year late. Before Y varied, both were 0
    and the wave chart could not tell them apart.
    """
    deployed = score(
        "ECDH", Primitive.KEY_EXCHANGE, Verdict.QUANTUM_VULNERABLE, pack,
        x=11, source_layer=SourceLayer.LIVE,
    )
    in_source = score(
        "ECDH", Primitive.KEY_EXCHANGE, Verdict.QUANTUM_VULNERABLE, pack,
        x=11, source_layer=SourceLayer.SOURCE,
    )

    assert (deployed.urgency_years, deployed.wave) == (0, Wave.WAVE_3)
    assert (in_source.urgency_years, in_source.wave) == (1, Wave.WAVE_1)


def test_an_unmatched_finding_falls_back_to_the_default_y_and_says_so(pack) -> None:
    """No ``pqc_targets`` rule names this algorithm, so there is no effort to read.

    The fallback is the pack default, and ``y_source`` records that it was a
    fallback — a Y nobody can trace back to a stated assumption is
    indistinguishable from a Y nobody chose.
    """
    decision = score("ExoticKEX", Primitive.KEY_EXCHANGE, Verdict.QUANTUM_VULNERABLE, pack)

    assert decision.y_years == pack.version.y_years_default == 1
    assert decision.rationale["y_source"] == "policy_default (no pqc_targets rule matched)"
    assert decision.rationale["action_class"] is None
    assert decision.rationale["matched_pqc_targets"] == []


def test_the_action_class_is_recorded_on_rows_mosca_never_reached(pack) -> None:
    """§12 stores every input on every row, and the effort is an input.

    A signature gets no urgency, but it still has a migration cost, and a
    roadmap that shows the wave without the effort cannot be budgeted from.
    """
    decision = score("ECDSA", Primitive.SIGNATURE, Verdict.QUANTUM_VULNERABLE, pack, x=20)

    assert decision.wave is Wave.WAVE_3 and decision.urgency_years is None
    assert decision.rationale["action_class"] == "library_upgrade"
    assert decision.rationale["action_class_rule"] == "sig-to-mldsa"
    assert "sig-longlived-root" in decision.rationale["matched_pqc_targets"]


def test_a_row_that_exits_before_the_action_class_still_carries_a_y(pack) -> None:
    """Uncertainty is resolved first, so a verify row never reaches the lookup."""
    decision = score(
        "MD5", Primitive.HASH, Verdict.BROKEN_NOW, pack, confidence=Confidence.LOW
    )

    assert decision.wave is Wave.VERIFY
    assert decision.y_years == pack.version.y_years_default
    assert decision.rationale["y_source"] == "policy_default (action class not resolved)"


# --------------------------------------------------------------------------- #
# X — per file, set on the approval screen
# --------------------------------------------------------------------------- #


def test_a_files_own_lifetime_wins_over_the_scan_wide_one(pack) -> None:
    """The user set this file's lifetime on the approval screen; it is used."""
    decision = score(
        "ECDH", Primitive.KEY_EXCHANGE, Verdict.QUANTUM_VULNERABLE, pack,
        x=5, lifetimes={"etc/openssl.cnf": 25}, evidence_location="etc/openssl.cnf",
    )

    assert decision.x_years == 25
    assert decision.rationale["x_source"] == "file: etc/openssl.cnf"
    assert decision.urgency_years == (25 + 1) - 12


def test_the_line_number_does_not_have_to_match(pack) -> None:
    """A lifetime belongs to the file, not to line 14 of it.

    Findings carry ``path:line``; the approval screen only ever showed a path.
    Requiring the line would mean every lifetime broke the moment somebody
    edited the file above it.
    """
    decision = score(
        "ECDH", Primitive.KEY_EXCHANGE, Verdict.QUANTUM_VULNERABLE, pack,
        x=5, lifetimes={"etc/openssl.cnf": 30}, evidence_location="etc/openssl.cnf:14",
        source_layer=SourceLayer.CONFIG,
    )

    assert decision.x_years == 30
    assert decision.rationale["x_source"] == "file: etc/openssl.cnf"


def test_a_file_with_no_lifetime_of_its_own_uses_the_scan_default(pack) -> None:
    """The ordinary case: one number covers the estate, a few files differ."""
    decision = score(
        "ECDH", Primitive.KEY_EXCHANGE, Verdict.QUANTUM_VULNERABLE, pack,
        x=20, lifetimes={"srv/vault/keys.pem": 50}, evidence_location="etc/nginx/nginx.conf:12",
    )

    assert decision.x_years == 20
    assert decision.rationale["x_source"] == "scan default"
    assert decision.urgency_years == 9


def test_a_probed_host_has_no_file_and_takes_the_scan_default(pack) -> None:
    """``host:port`` is not a path, and no approval row ever named it."""
    decision = score(
        "ECDH", Primitive.KEY_EXCHANGE, Verdict.QUANTUM_VULNERABLE, pack,
        x=20, lifetimes={"etc/openssl.cnf": 30}, evidence_location="localhost:8443",
    )

    assert (decision.x_years, decision.rationale["x_source"]) == (20, "scan default")


def test_a_finding_with_no_location_takes_the_scan_default(pack) -> None:
    decision = score(
        "ECDH", Primitive.KEY_EXCHANGE, Verdict.QUANTUM_VULNERABLE, pack,
        x=20, lifetimes={"etc/openssl.cnf": 30}, evidence_location=None,
    )

    assert (decision.x_years, decision.rationale["x_source"]) == (20, "scan default")


def test_a_file_lifetime_of_zero_is_a_value_not_a_missing_one(pack) -> None:
    """"This data is worthless tomorrow" is a real answer, and it is not null.

    Treating 0 as absent would quietly score a throwaway cache at the estate's
    20-year default — the opposite of what the user said on the screen.
    """
    decision = score(
        "ECDH", Primitive.KEY_EXCHANGE, Verdict.QUANTUM_VULNERABLE, pack,
        x=20, lifetimes={"var/cache/tmp.py": 0}, evidence_location="var/cache/tmp.py:3",
    )

    assert decision.x_years == 0
    assert decision.rationale["x_source"] == "file: var/cache/tmp.py"
    assert decision.wave is Wave.WAVE_3


def test_a_missing_x_still_routes_to_verify_whatever_the_overrides_say(pack) -> None:
    """§12's invariant: a missing X is never defaulted."""
    decision = score(
        "ECDH", Primitive.KEY_EXCHANGE, Verdict.QUANTUM_VULNERABLE, pack,
        x=None, lifetimes={"srv/other.pem": 50}, evidence_location="etc/nginx.conf",
    )

    assert decision.wave is Wave.VERIFY
    assert decision.x_years is None
    assert decision.rationale["x_source"] == "not supplied"


# --------------------------------------------------------------------------- #
# X and Y together, over a whole scan
# --------------------------------------------------------------------------- #


def test_two_findings_in_one_scan_can_have_different_x(db_session, scan_factory) -> None:
    """One scan, one Z, and two files with genuinely different horizons."""
    scan = scan_factory(5, lifetimes={"etc/records.cnf": 25})
    with_verdict(
        db_session, scan, "ECDH", Primitive.KEY_EXCHANGE, Verdict.QUANTUM_VULNERABLE,
        evidence_location="etc/records.cnf:3",
    )
    with_verdict(
        db_session, scan, "ECDH", Primitive.KEY_EXCHANGE, Verdict.QUANTUM_VULNERABLE,
        evidence_location="etc/monitoring.cnf:3",
    )

    by_source = {row.rationale["x_source"]: row for row in score_scan(db_session, scan)}

    assert by_source["file: etc/records.cnf"].x_years == 25
    assert by_source["file: etc/records.cnf"].urgency_years == 14
    assert by_source["scan default"].x_years == 5
    assert by_source["scan default"].urgency_years == -6
    assert {row.wave for row in by_source.values()} == {Wave.WAVE_1, Wave.WAVE_3}


def test_rescoring_at_a_new_z_keeps_each_files_own_x(db_session, scan_factory) -> None:
    """The lifetimes live on scan_files, so the Z slider re-reads rather than loses them."""
    scan = scan_factory(5, lifetimes={"etc/records.cnf": 25})
    with_verdict(
        db_session, scan, "ECDH", Primitive.KEY_EXCHANGE, Verdict.QUANTUM_VULNERABLE,
        evidence_location="etc/records.cnf:3",
    )

    score_scan(db_session, scan)
    rescored = score_scan(db_session, scan, z_years=30)

    assert len(stored_scores(db_session, scan)) == 1
    assert rescored[0].x_years == 25
    assert rescored[0].rationale["x_source"] == "file: etc/records.cnf"
    assert rescored[0].urgency_years == (25 + 1) - 30
    assert rescored[0].wave is Wave.WAVE_3


def test_a_scan_with_no_overrides_produces_the_waves_it_always_did(
    db_session, scan_factory
) -> None:
    """Regression guard. Per-file X is opt-in, and opting out changes nothing.

    Five findings spanning every wave, scored at one scan-wide X with no file
    carrying an override — the shape of every scan that ran before this existed.
    """
    scan = scan_factory(20)
    rows = {
        "broken": with_verdict(
            db_session, scan, "MD5", Primitive.HASH, Verdict.BROKEN_NOW
        ),
        "overdue_cheap": with_verdict(
            db_session, scan, "ECDH", Primitive.KEY_EXCHANGE, Verdict.QUANTUM_VULNERABLE
        ),
        "overdue_costly": with_verdict(
            db_session, scan, "3DES", Primitive.CIPHER, Verdict.QUANTUM_VULNERABLE
        ),
        "signature": with_verdict(
            db_session, scan, "ECDSA", Primitive.SIGNATURE, Verdict.QUANTUM_VULNERABLE
        ),
        "shaky": with_verdict(
            db_session, scan, "RSA", Primitive.KEY_EXCHANGE, Verdict.QUANTUM_VULNERABLE,
            confidence=Confidence.LOW,
        ),
    }

    waves = {row.finding_id: row for row in score_scan(db_session, scan)}

    assert waves[rows["broken"].id].wave is Wave.WAVE_0
    assert waves[rows["overdue_cheap"].id].wave is Wave.WAVE_1
    assert waves[rows["overdue_costly"].id].wave is Wave.WAVE_2
    assert waves[rows["signature"].id].wave is Wave.WAVE_3
    assert waves[rows["shaky"].id].wave is Wave.VERIFY

    # Every row took X from the scan, and every row says so.
    assert {row.x_years for row in waves.values()} == {20}
    assert {row.rationale["x_source"] for row in waves.values()} == {"scan default"}
