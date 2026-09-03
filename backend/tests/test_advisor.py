"""Advisor — SPEC.md §11.

The first test is the one §11 says the advisor gets wrong half the time if it
matches on the algorithm name: RSA doing key exchange and RSA signing, same
family, different targets. The rest are about restraint — a blocker chain
instead of a wish, no target rather than a generic one, and a hybrid preference
read from the pack rather than assumed.
"""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from uuid import UUID

import pytest
import sqlalchemy as sa

from app.collectors.base import ScanContext
from app.collectors.network import NetworkCollector
from app.core.advisor import (
    OBS_LINKED_LIBRARY,
    OBS_LIBRARY_VERSION,
    ScanObservations,
    advise_finding,
    advise_scan,
    asset_of,
    recommendation_counts,
    select_parameter_set,
    validate_targets,
)
from app.core.normalizer import normalize
from app.core.policy import apply_policy
from app.core.policy_loader import PolicyValidationError, load_policy
from app.models.analysis import Recommendation
from app.models.enums import (
    ActionClass,
    CollectorName,
    Confidence,
    Primitive,
    RecommendationStatus,
    ScanMode,
    ScanStatus,
    SourceLayer,
    SourceType,
    Verdict,
)
from app.models.finding import Finding
from app.models.scan import Scan
from tests.conftest import reachable

DEMO_UP = reachable("localhost", 8443)
needs_demo = pytest.mark.skipif(
    not DEMO_UP, reason="demo lab not running: docker compose -f demo/docker-compose.yml up"
)

HOST, PORT = "localhost", 8443


@pytest.fixture
def pack(shipped_policy_dir: Path):
    """The pack as it ships: prefer_hybrid on, the long-lived line at 10 years."""
    return load_policy(shipped_policy_dir)


@pytest.fixture
def pure(pack):
    """The same pack with the hybrid preference off — a policy choice, not a code path."""
    return replace(pack, prefer_hybrid=False)


@pytest.fixture
def scan_factory(db_session):
    def _factory(data_lifetime_years: int | None = 20) -> Scan:
        scan = Scan(
            mode=ScanMode.FILES_AND_PROBE,
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
    kwargs.setdefault("evidence_location", f"{HOST}:{PORT}")
    kwargs.setdefault("evidence_raw", {"host": HOST, "port": PORT, "observation": "negotiated_group"})
    return Finding(algorithm_family=family, primitive=primitive, **kwargs)


def protocol(version: str, *, accepted: bool = True, host: str = HOST, port: int = PORT) -> Finding:
    """A live protocol observation, in the two shapes the prober emits."""
    observation = "protocol_version_accepted" if accepted else "protocol_version_not_offered"
    return Finding(
        collector=CollectorName.NETWORK,
        algorithm_name=f"TLS {version}" if accepted else "tls-version-not-offered",
        algorithm_family="TLS" if accepted else "tls-version-not-offered",
        primitive=Primitive.PROTOCOL if accepted else Primitive.UNKNOWN,
        protocol_version=version,
        evidence_location=f"{host}:{port}",
        evidence_raw={"observation": observation, "host": host, "port": port},
        confidence=Confidence.HIGH,
        source_layer=SourceLayer.LIVE,
    )


def library(version: str, *, location: str = "cbin/build/cryptodemo", soname: bool = False) -> Finding:
    """What the binary collector (§7.2) reports for a linked OpenSSL."""
    return Finding(
        collector=CollectorName.BINARY,
        algorithm_name=f"libcrypto.so.{version}" if soname else "OpenSSL",
        algorithm_family="OpenSSL",
        primitive=Primitive.UNKNOWN,
        evidence_location=location,
        evidence_raw={
            "observation": OBS_LINKED_LIBRARY if soname else OBS_LIBRARY_VERSION,
            "library": "openssl",
            "version": version,
        },
        confidence=Confidence.HIGH if soname else Confidence.MEDIUM,
        source_layer=SourceLayer.ARTIFACT,
    )


def advise(target: Finding, verdict, pack, *, x=None, context=()):
    """Advice for one finding, with ``context`` findings supplying the observations."""
    observations = ScanObservations([target, *context])
    return advise_finding(
        target, verdict, data_lifetime_years=x, policy=pack, observations=observations
    )


def one(advice):
    assert len(advice) == 1, [item.rationale for item in advice]
    return advice[0]


# --------------------------------------------------------------------------- #
# Step 1 — primitive plus family
# --------------------------------------------------------------------------- #


def test_rsa_key_exchange_recommends_ml_kem_and_rsa_signature_recommends_ml_dsa(pure) -> None:
    """§11's required test, and the one a name-based match gets wrong half the time.

    Same family, same key size, same verdict — different primitive, different
    target. Run against the pack with the hybrid preference off so the pure
    target is visible; the hybrid half has its own test below.
    """
    kex = one(advise(finding("RSA", Primitive.KEY_EXCHANGE, key_size=2048), Verdict.QUANTUM_VULNERABLE, pure))
    sig = one(advise(finding("RSA", Primitive.SIGNATURE, key_size=2048), Verdict.QUANTUM_VULNERABLE, pure))

    assert kex.target == "ML-KEM-768" and kex.rule_id == "kex-to-mlkem"
    assert sig.target == "ML-DSA-65" and sig.rule_id == "sig-to-mldsa"
    assert kex.source_citation == "NIST FIPS 203"
    assert sig.source_citation == "NIST FIPS 204"


def test_an_unknown_primitive_matches_nothing(pure) -> None:
    """RSA with no observed use is not key exchange and not a signature. No guess."""
    advice = one(advise(finding("RSA", Primitive.UNKNOWN), Verdict.QUANTUM_VULNERABLE, pure))

    assert advice.status is RecommendationStatus.UNKNOWN
    assert advice.target is None


# --------------------------------------------------------------------------- #
# Step 3 — the blocker chain
# --------------------------------------------------------------------------- #


def test_a_finding_on_the_openssl_1_1_1_host_is_blocked_with_a_prerequisite_chain(pack) -> None:
    """§11's required test, and the highest-value output in the system.

    The demo's target F: a host that tops out at TLS 1.2 and links OpenSSL
    1.1.1f. Both halves of the chain come from observations — the ceiling from
    the probe, the library from the binary collector — and the chain is ordered
    with the procurement item first.
    """
    context = [
        protocol("1.0"), protocol("1.1"), protocol("1.2"), protocol("1.3", accepted=False),
        library("1.1.1f"),
    ]
    advice = one(advise(finding("RSA", Primitive.KEY_EXCHANGE), Verdict.QUANTUM_VULNERABLE, pack, x=5, context=context))

    assert advice.status is RecommendationStatus.BLOCKED
    assert advice.target == "X25519MLKEM768"
    chain = [item.as_dict() for item in advice.prerequisites]
    assert [(item["unmet"], item["observed"]) for item in chain] == [
        ("openssl>=3.5", "openssl 1.1.1f"),
        ("TLS 1.3", "TLS 1.2"),
    ]
    assert chain[0]["observed_at"] == "cbin/build/cryptodemo"
    assert chain[1]["observed_at"] == f"{HOST}:{PORT}"


def test_prerequisites_met_on_the_asset_produce_a_recommendation(pack) -> None:
    context = [
        protocol("1.2"), protocol("1.3"),
        library("3.5.1", location=f"{HOST}:{PORT}"),
    ]
    advice = one(advise(finding("ECDH", Primitive.KEY_EXCHANGE), Verdict.QUANTUM_VULNERABLE, pack, x=5, context=context))

    assert advice.status is RecommendationStatus.RECOMMENDED
    assert advice.prerequisites == ()
    assert advice.action_class is ActionClass.CONFIG


def test_an_unobserved_prerequisite_is_not_presumed_met(pack) -> None:
    """Nothing in the scan says which OpenSSL the host runs, so it is not confirmed.

    The row stays ``blocked`` with ``observed: null`` and the work item is to
    check. Rounding "unobserved" to "presumably fine" is the optimistic
    direction demo/README.md rules out.
    """
    context = [protocol("1.3")]
    advice = one(advise(finding("ECDH", Primitive.KEY_EXCHANGE), Verdict.QUANTUM_VULNERABLE, pack, x=5, context=context))

    assert advice.status is RecommendationStatus.BLOCKED
    chain = [item.as_dict() for item in advice.prerequisites]
    assert len(chain) == 1
    assert chain[0]["unmet"] == "openssl>=3.5"
    assert chain[0]["observed"] is None
    assert "confirm" in chain[0]["note"]


def test_a_soname_cannot_confirm_a_minor_version(pack) -> None:
    """``libcrypto.so.3`` says OpenSSL 3 and nothing more — it neither meets nor fails ``>=3.5``."""
    context = [protocol("1.3"), library("3", location=f"{HOST}:{PORT}", soname=True)]
    advice = one(advise(finding("ECDH", Primitive.KEY_EXCHANGE), Verdict.QUANTUM_VULNERABLE, pack, x=5, context=context))

    assert advice.status is RecommendationStatus.BLOCKED
    entry = advice.prerequisites[0].as_dict()
    assert entry["observed"] == "openssl 3"
    assert "major version" in entry["note"]


def test_a_precise_version_string_beside_the_soname_settles_it(pack) -> None:
    """The ``.rodata`` version string is what a soname lacks (demo/README.md §G)."""
    context = [
        protocol("1.3"),
        library("3", location=f"{HOST}:{PORT}", soname=True),
        library("3.5.0", location=f"{HOST}:{PORT}"),
    ]
    advice = one(advise(finding("ECDH", Primitive.KEY_EXCHANGE), Verdict.QUANTUM_VULNERABLE, pack, x=5, context=context))

    assert advice.status is RecommendationStatus.RECOMMENDED


def test_a_library_seen_elsewhere_in_the_scan_can_block_but_is_named(pack) -> None:
    """The oldest OpenSSL anywhere in the deployment is the one the target is held to."""
    context = [
        protocol("1.3"),
        library("3.5.0", location="usr/bin/newtool"),
        library("1.1.1f", location="usr/bin/legacytool"),
    ]
    advice = one(advise(finding("ECDH", Primitive.KEY_EXCHANGE), Verdict.QUANTUM_VULNERABLE, pack, x=5, context=context))

    assert advice.status is RecommendationStatus.BLOCKED
    entry = advice.prerequisites[0].as_dict()
    assert entry["observed"] == "openssl 1.1.1f"
    assert entry["observed_at"] == "usr/bin/legacytool"


def test_a_protocol_ceiling_is_never_borrowed_from_another_service(pack) -> None:
    """What 8444 negotiates says nothing about 8443."""
    context = [protocol("1.3", port=8444), library("3.5.0", location=f"{HOST}:{PORT}")]
    advice = one(advise(finding("ECDH", Primitive.KEY_EXCHANGE), Verdict.QUANTUM_VULNERABLE, pack, x=5, context=context))

    assert advice.status is RecommendationStatus.BLOCKED
    entry = advice.prerequisites[0].as_dict()
    assert entry["unmet"] == "TLS 1.3" and entry["observed"] is None


def test_a_config_asset_is_the_file_and_its_declared_ceiling_counts(pack) -> None:
    """A key exchange declared in a config file is tested against that file's own ceiling."""
    declared = Finding(
        collector=CollectorName.CONFIG,
        algorithm_name="TLSv1.2",
        algorithm_family="TLS",
        primitive=Primitive.PROTOCOL,
        protocol_version="1.2",
        evidence_location="weak-nginx/nginx.conf:43",
        evidence_raw={"observation": "protocol_version_declared", "file": "weak-nginx/nginx.conf"},
        confidence=Confidence.HIGH,
        source_layer=SourceLayer.CONFIG,
    )
    kex = finding(
        "DH",
        Primitive.KEY_EXCHANGE,
        collector=CollectorName.CONFIG,
        source_layer=SourceLayer.CONFIG,
        evidence_location="weak-nginx/nginx.conf:49",
        evidence_raw={"observation": "cipher_suite_declared"},
    )
    assert asset_of(kex) == asset_of(declared) == "weak-nginx/nginx.conf"

    advice = one(advise(kex, Verdict.QUANTUM_VULNERABLE, pack, x=5, context=[declared, library("3.5.0", location="weak-nginx/nginx.conf")]))

    assert advice.status is RecommendationStatus.BLOCKED
    assert [item.as_dict()["observed"] for item in advice.prerequisites] == ["TLS 1.2"]


# --------------------------------------------------------------------------- #
# unknown and no_path
# --------------------------------------------------------------------------- #


def test_a_finding_with_no_matching_rule_returns_unknown_with_no_target(pack) -> None:
    """§11's required test. No generic fallback: a wrong recommendation is worse than none."""
    advice = one(advise(finding("TLS", Primitive.PROTOCOL, protocol_version="1.0"), Verdict.BROKEN_NOW, pack, x=20))

    assert advice.status is RecommendationStatus.UNKNOWN
    assert advice.target is None
    assert advice.hybrid_target is None
    assert advice.action_class is None
    assert advice.prerequisites == ()
    assert "no target" in advice.source_citation


def test_a_no_path_entry_emits_the_compensating_control(policy_dir_factory) -> None:
    """``no_path`` comes from the pack saying so, never from this module deciding it."""

    def add_entry(doc):
        doc["targets"].append(
            {
                "id": "ssl3-appliance",
                "match": {"primitive": "protocol", "family": "SSL"},
                "compensating_control": "Isolate the appliance behind a TLS 1.3 terminating proxy.",
                "action_class": "hardware",
                "source": "RFC 7568",
            }
        )

    pack = load_policy(policy_dir_factory("pqc_targets.yaml", add_entry))
    validate_targets(pack)

    advice = one(advise(finding("SSL", Primitive.PROTOCOL, protocol_version="3.0"), Verdict.BROKEN_NOW, pack))

    assert advice.status is RecommendationStatus.NO_PATH
    assert advice.target is None
    assert "terminating proxy" in advice.side_effects
    assert advice.source_citation == "RFC 7568"
    assert advice.action_class is ActionClass.HARDWARE


@pytest.mark.parametrize("verdict", [Verdict.QUANTUM_SAFE, Verdict.HYGIENE, Verdict.UNKNOWN])
def test_a_finding_that_needs_no_migration_gets_no_advice(pack, verdict) -> None:
    """AES needs no target, and an unassessed 3DES has not been shown to need one either."""
    assert advise(finding("3DES", Primitive.CIPHER), verdict, pack, x=20) == ()


# --------------------------------------------------------------------------- #
# Step 4 — the hybrid policy, from the pack
# --------------------------------------------------------------------------- #


def test_with_prefer_hybrid_a_key_exchange_target_is_the_hybrid_value(pack, pure) -> None:
    """§11's required test. Read from policy, never hardcoded — national guidance differs."""
    context = [protocol("1.3"), library("3.5.0", location=f"{HOST}:{PORT}")]
    hybrid = one(advise(finding("ECDH", Primitive.KEY_EXCHANGE), Verdict.QUANTUM_VULNERABLE, pack, x=5, context=context))
    unilateral = one(advise(finding("ECDH", Primitive.KEY_EXCHANGE), Verdict.QUANTUM_VULNERABLE, pure, x=5, context=context))

    assert pack.prefer_hybrid is True
    assert hybrid.target == "X25519MLKEM768"
    assert hybrid.hybrid_target == "X25519MLKEM768"
    assert hybrid.rationale["pure_target"] == "ML-KEM-768"

    assert unilateral.target == "ML-KEM-768"
    # The hybrid is still on the row as the alternative the pack names.
    assert unilateral.hybrid_target == "X25519MLKEM768"


def test_the_hybrid_policy_never_touches_a_signature(pack) -> None:
    context = [library("3.5.0", location=f"{HOST}:{PORT}")]
    advice = one(advise(finding("ECDSA", Primitive.SIGNATURE), Verdict.QUANTUM_VULNERABLE, pack, x=5, context=context))

    assert advice.target == "ML-DSA-65"
    assert advice.hybrid_target is None


# --------------------------------------------------------------------------- #
# Step 2 — parameter sets from the data lifetime
# --------------------------------------------------------------------------- #


def test_a_signature_finding_with_a_20_year_lifetime_selects_slh_dsa(pack) -> None:
    """§11's required test: a long-lived root of trust gets the hash-based fallback.

    Both signature rules match at X=20. ML-DSA needs an OpenSSL nothing here has
    observed, so it is not feasible now; SLH-DSA needs nothing, and feasible
    beats theoretically better.
    """
    advice = one(advise(finding("RSA", Primitive.SIGNATURE, key_size=4096), Verdict.QUANTUM_VULNERABLE, pack, x=20))

    assert advice.status is RecommendationStatus.RECOMMENDED
    assert advice.target == "SLH-DSA-SHA2-128s"
    assert advice.rule_id == "sig-longlived-root"
    assert advice.source_citation == "NIST FIPS 205"
    assert "fallback" in advice.side_effects
    assert [item["rule_id"] for item in advice.rationale["passed_over"]] == ["sig-to-mldsa"]


def test_a_long_lifetime_selects_the_larger_parameter_set(pack, pure) -> None:
    """Higher classification → ML-KEM-1024 / ML-DSA-87, with the threshold read from the pack."""
    assert select_parameter_set("ML-KEM-768", pack, 20) == ("ML-KEM-1024", "longlived-max-parameter-set")
    assert select_parameter_set("ML-DSA-65", pack, 20) == ("ML-DSA-87", "longlived-max-parameter-set")
    assert select_parameter_set("ML-KEM-768", pack, 5) == ("ML-KEM-768", None)
    # An unstated lifetime clears no threshold.
    assert select_parameter_set("ML-KEM-768", pack, None) == ("ML-KEM-768", None)

    context = [protocol("1.3"), library("3.5.0", location=f"{HOST}:{PORT}")]
    kex = one(advise(finding("ECDH", Primitive.KEY_EXCHANGE), Verdict.QUANTUM_VULNERABLE, pure, x=20, context=context))
    assert kex.target == "ML-KEM-1024"

    # And the hybrid moves with it, rather than wrapping a smaller ML-KEM.
    hybrid = one(advise(finding("ECDH", Primitive.KEY_EXCHANGE), Verdict.QUANTUM_VULNERABLE, pack, x=20, context=context))
    assert hybrid.target == "SecP384r1MLKEM1024"
    assert hybrid.rationale["pure_target"] == "ML-KEM-1024"


def test_when_ml_dsa_is_feasible_it_beats_the_hardware_fallback(pack) -> None:
    """With OpenSSL 3.5 observed both signature rules are feasible, and the cheaper action wins.

    SLH-DSA's own note calls it a fallback. It is the answer when ML-DSA cannot
    be deployed, not the answer whenever the data is long-lived.
    """
    context = [library("3.5.0", location=f"{HOST}:{PORT}")]
    advice = one(advise(finding("ECDSA", Primitive.SIGNATURE), Verdict.QUANTUM_VULNERABLE, pack, x=20, context=context))

    assert advice.status is RecommendationStatus.RECOMMENDED
    assert advice.target == "ML-DSA-87"
    assert advice.action_class is ActionClass.LIBRARY_UPGRADE
    assert "2.4 KB" in advice.side_effects


# --------------------------------------------------------------------------- #
# Ties
# --------------------------------------------------------------------------- #


def test_a_genuine_tie_emits_both_with_the_tradeoff_stated(policy_dir_factory) -> None:
    """§11: do not manufacture a preference the pack does not state."""

    def add_twin(doc):
        doc["targets"].append(
            {
                "id": "hash-upgrade-sha3",
                "match": {"primitive": "hash", "family": ["MD5", "SHA-1"]},
                "target": "SHA3-256",
                "action_class": "code_change",
                "source": "NIST FIPS 202",
            }
        )

    pack = load_policy(policy_dir_factory("pqc_targets.yaml", add_twin))
    advice = advise(finding("MD5", Primitive.HASH), Verdict.BROKEN_NOW, pack, x=5)

    assert {item.target for item in advice} == {"SHA-256", "SHA3-256"}
    for item in advice:
        assert item.status is RecommendationStatus.RECOMMENDED
        assert "Tied with" in item.side_effects
        assert "NIST FIPS 202" in item.side_effects and "NIST SP 800-131A Rev.2" in item.side_effects


def test_a_draft_loses_to_a_standard_but_only_as_the_last_tie_break(policy_dir_factory) -> None:
    def add_draft(doc):
        doc["targets"].append(
            {
                "id": "hash-upgrade-draft",
                "match": {"primitive": "hash", "family": ["MD5", "SHA-1"]},
                "target": "SomethingNewer",
                "action_class": "code_change",
                "source": "draft-example-hash-00",
            }
        )

    pack = load_policy(policy_dir_factory("pqc_targets.yaml", add_draft))
    advice = one(advise(finding("MD5", Primitive.HASH), Verdict.BROKEN_NOW, pack, x=5))

    assert advice.target == "SHA-256"
    assert advice.rationale["passed_over"][0]["rule_id"] == "hash-upgrade-draft"


# --------------------------------------------------------------------------- #
# Pack validation
# --------------------------------------------------------------------------- #


def test_the_shipped_pack_validates(pack) -> None:
    validate_targets(pack)


def test_an_untestable_requirement_is_rejected_at_startup(policy_dir_factory) -> None:
    """A typo in ``requires`` would not fail — the prerequisite would vanish."""
    bad = policy_dir_factory(
        "pqc_targets.yaml",
        lambda doc: doc["targets"][0]["requires"].update({"libary": "openssl>=3.5"}),
    )
    with pytest.raises(PolicyValidationError, match="libary"):
        validate_targets(load_policy(bad))


def test_a_malformed_library_clause_is_rejected(policy_dir_factory) -> None:
    bad = policy_dir_factory(
        "pqc_targets.yaml",
        lambda doc: doc["targets"][0]["requires"].update({"library": "openssl three point five"}),
    )
    with pytest.raises(PolicyValidationError, match="openssl three"):
        validate_targets(load_policy(bad))


def test_an_entry_with_nothing_to_say_is_rejected(policy_dir_factory) -> None:
    bad = policy_dir_factory(
        "pqc_targets.yaml",
        lambda doc: doc["targets"].append({"id": "empty", "match": {"primitive": "hash"}, "source": "x"}),
    )
    with pytest.raises(PolicyValidationError, match="empty"):
        validate_targets(load_policy(bad))


def test_a_parameter_set_without_a_citation_fails_to_load(policy_dir_factory) -> None:
    bad = policy_dir_factory(
        "pqc_targets.yaml", lambda doc: doc["parameter_sets"][0].pop("source")
    )
    with pytest.raises(PolicyValidationError, match="longlived-max-parameter-set"):
        load_policy(bad)


# --------------------------------------------------------------------------- #
# Storing
# --------------------------------------------------------------------------- #


def stored(session, scan) -> list[Recommendation]:
    query = (
        sa.select(Recommendation)
        .join(Finding, Finding.id == Recommendation.finding_id)
        .where(Finding.scan_id == scan.id)
    )
    return list(session.scalars(query))


def test_advising_a_scan_writes_rows_and_counts_all_four_statuses(
    db_session, scan_factory
) -> None:
    scan = scan_factory(20)
    for row in (
        finding("ECDH", Primitive.KEY_EXCHANGE, scan_id=scan.id),
        finding("ECDSA", Primitive.SIGNATURE, scan_id=scan.id),
        finding("TLS", Primitive.PROTOCOL, scan_id=scan.id, protocol_version="1.0"),
        finding("AES", Primitive.CIPHER, scan_id=scan.id),
    ):
        db_session.add(row)
    db_session.flush()
    apply_policy(db_session, scan.id)

    rows = advise_scan(db_session, scan)

    counts = recommendation_counts(rows)
    assert counts == {"recommended": 1, "blocked": 1, "no_path": 0, "unknown": 1}
    assert len(stored(db_session, scan)) == 3
    blocked = next(row for row in rows if row.status is RecommendationStatus.BLOCKED)
    assert blocked.prerequisites[0]["unmet"] == "openssl>=3.5"


def test_re_advising_replaces_the_rows(db_session, scan_factory) -> None:
    scan = scan_factory(20)
    db_session.add(finding("ECDH", Primitive.KEY_EXCHANGE, scan_id=scan.id))
    db_session.flush()
    apply_policy(db_session, scan.id)

    advise_scan(db_session, scan)
    advise_scan(db_session, scan)

    assert len(stored(db_session, scan)) == 1


# --------------------------------------------------------------------------- #
# Through the pipeline
# --------------------------------------------------------------------------- #


def test_the_demo_produces_recommended_and_blocked_rows(demo_scan, db_session) -> None:
    """Build step 10's exit criterion, against the committed demo tree at X=20.

    The signatures get SLH-DSA, feasible with nothing observed. The three SSH key
    exchanges are held to prerequisites the file tree cannot show are met, and
    the two legacy TLS declarations match no rule at all.
    """
    counts = demo_scan["recommendation_counts"]
    assert set(counts) == {"recommended", "blocked", "no_path", "unknown"}
    assert counts["recommended"] > 0
    assert counts["blocked"] > 0
    assert counts["unknown"] > 0

    rows = db_session.execute(
        sa.select(Finding, Recommendation)
        .join(Recommendation, Recommendation.finding_id == Finding.id)
        .where(Finding.scan_id == UUID(demo_scan["scan_id"]))
    ).all()
    blocked = [rec for _, rec in rows if rec.status is RecommendationStatus.BLOCKED]
    assert all(rec.prerequisites for rec in blocked)
    assert all(
        {"unmet", "observed"} <= set(item) for rec in blocked for item in rec.prerequisites
    )
    # Every recommendation on a migration item cites something.
    assert all(rec.source_citation for _, rec in rows)


@needs_demo
def test_the_demo_weak_host_is_blocked_on_its_observed_protocol_ceiling(
    db_session, scan_factory, demo_dir: Path
) -> None:
    """demo/README.md §F, from a real probe: 8443 refuses TLS 1.3, so ML-KEM is blocked."""
    scan = scan_factory(5)
    ctx = ScanContext.build(
        scan_id=scan.id, work_dir=demo_dir, probe_targets=[{"host": HOST, "port": PORT}]
    )
    normalize(db_session, scan.id, NetworkCollector().collect(ctx))
    apply_policy(db_session, scan.id)

    rows = advise_scan(db_session, scan)

    blocked = [row for row in rows if row.status is RecommendationStatus.BLOCKED]
    assert blocked, [row.status for row in rows]
    chain = {item["unmet"]: item for item in blocked[0].prerequisites}
    assert chain["TLS 1.3"]["observed"] == "TLS 1.2"
    assert "openssl>=3.5" in chain
