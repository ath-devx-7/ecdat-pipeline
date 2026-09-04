"""Policy loader — SPEC.md §6.

The load-time citation check is the one that matters. A verdict a user cannot
trace back to a published standard is not evidence, so an uncited entry must
stop the process rather than degrade quietly.
"""

from __future__ import annotations

from datetime import date
from pathlib import Path

import pytest

from app.core.policy_loader import (
    PolicyError,
    PolicyValidationError,
    load_policy,
)


# --------------------------------------------------------------------------- #
# The shipped pack loads
# --------------------------------------------------------------------------- #


def test_shipped_policy_pack_loads(shipped_policy_dir: Path) -> None:
    pack = load_policy(shipped_policy_dir)

    assert pack.version.version == "2026.09"
    # §6's eight entries, plus the two step 6 added with citations: SHA-2,
    # because §6 also requires SHA-256 to resolve to quantum_safe and the pack as
    # printed has no rule that would do it, and DH/DSA, which the pack ruled on
    # in pqc_targets.yaml while having no verdict for them.
    assert len(pack.algorithms) == 18
    # Seven: §6's five, plus the two the layer scoping needed — OpenSSH's own
    # key exchange, and the same ML-KEM target for a key exchange that was
    # inventoried rather than observed on a service.
    assert len(pack.pqc_targets) == 7
    assert pack.prefer_hybrid is True
    # Both mapping files are populated now — the alias table in step 5, the named
    # groups in step 7. The loader only has to hand them over as mappings; what
    # they mean is tested in test_normalizer.py and test_collectors_network.py.
    assert dict(pack.aliases)
    assert pack.named_groups[4588] == "X25519MLKEM768"


def test_version_exposes_the_mosca_defaults(shipped_policy_dir: Path) -> None:
    version = load_policy(shipped_policy_dir).version

    assert version.z_years_default == 12
    assert version.y_years_default == 1
    assert version.staleness_warning_days == 180
    assert version.published == date(2026, 9, 1)


def test_every_shipped_entry_carries_a_citation(shipped_policy_dir: Path) -> None:
    pack = load_policy(shipped_policy_dir)

    for rule in pack.algorithms:
        assert rule.source.strip(), f"algorithms.yaml entry {rule.id!r} has no citation"
    for target in pack.pqc_targets:
        assert target.source.strip(), f"pqc_targets.yaml entry {target.id!r} has no citation"


def test_scalar_and_list_fields_both_normalise_to_tuples(shipped_policy_dir: Path) -> None:
    """``family: AES`` and ``family: [ECDSA, ECDH, EdDSA]`` are both valid YAML."""
    pack = load_policy(shipped_policy_dir)

    assert pack.algorithm("aes-safe").family == ("AES",)
    assert pack.algorithm("ecc-quantum").family == ("ECDSA", "ECDH", "EdDSA")
    assert pack.algorithm("rsa-quantum").primitive == ("key_exchange", "signature")


def test_shipped_pack_classifies_aes_and_sha256_as_quantum_safe(
    shipped_policy_dir: Path,
) -> None:
    """Guards the YAML itself (the engine's own test arrives in build step 6).

    Grover weakens symmetric crypto; it does not break it. Nothing in this pack
    may class AES as quantum_vulnerable.
    """
    pack = load_policy(shipped_policy_dir)

    assert pack.algorithm("aes-safe").verdict == "quantum_safe"
    assert not any(
        rule.verdict == "quantum_vulnerable" and "AES" in rule.family
        for rule in pack.algorithms
    )


# --------------------------------------------------------------------------- #
# Validation: a missing citation stops the load
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("filename", "collection", "offending_id"),
    [
        ("algorithms.yaml", "entries", "rsa-quantum"),
        ("pqc_targets.yaml", "targets", "sig-to-mldsa"),
    ],
)
def test_entry_without_source_fails_to_load(
    policy_dir_factory, filename: str, collection: str, offending_id: str
) -> None:
    def strip_citation(document: dict) -> None:
        entry = next(e for e in document[collection] if e["id"] == offending_id)
        del entry["source"]

    policy_dir = policy_dir_factory(filename, strip_citation)

    with pytest.raises(PolicyValidationError) as excinfo:
        load_policy(policy_dir)

    message = str(excinfo.value)
    assert filename in message
    assert offending_id in message, "the error must name the offending entry"
    assert "source" in message


def test_blank_source_is_treated_as_missing(policy_dir_factory) -> None:
    def blank_citation(document: dict) -> None:
        document["entries"][0]["source"] = "   "

    policy_dir = policy_dir_factory("algorithms.yaml", blank_citation)

    with pytest.raises(PolicyValidationError, match="md5-hash"):
        load_policy(policy_dir)


def test_uncited_entry_without_an_id_still_names_its_position(policy_dir_factory) -> None:
    def strip_id_and_citation(document: dict) -> None:
        entry = document["entries"][2]
        del entry["source"]
        del entry["id"]

    policy_dir = policy_dir_factory("algorithms.yaml", strip_id_and_citation)

    with pytest.raises(PolicyValidationError, match="index 2"):
        load_policy(policy_dir)


# --------------------------------------------------------------------------- #
# Validation: other structural problems
# --------------------------------------------------------------------------- #


def test_entry_without_a_verdict_fails_to_load(policy_dir_factory) -> None:
    def strip_verdict(document: dict) -> None:
        del document["entries"][0]["verdict"]

    with pytest.raises(PolicyValidationError, match="md5-hash"):
        load_policy(policy_dir_factory("algorithms.yaml", strip_verdict))


def test_duplicate_entry_id_fails_to_load(policy_dir_factory) -> None:
    def duplicate(document: dict) -> None:
        document["entries"].append(dict(document["entries"][0]))

    with pytest.raises(PolicyValidationError, match="duplicate"):
        load_policy(policy_dir_factory("algorithms.yaml", duplicate))


@pytest.mark.parametrize(
    "key", ["z_years_default", "y_years_default", "staleness_warning_days", "published"]
)
def test_version_missing_a_required_key_fails_to_load(policy_dir_factory, key: str) -> None:
    with pytest.raises(PolicyValidationError, match=key):
        load_policy(policy_dir_factory("version.yaml", lambda doc: doc.pop(key)))


def test_missing_policy_file_names_the_file(tmp_path: Path, shipped_policy_dir: Path) -> None:
    import shutil

    policy_dir = tmp_path / "policy"
    shutil.copytree(shipped_policy_dir, policy_dir)
    (policy_dir / "named_groups.yaml").unlink()

    with pytest.raises(PolicyError, match="named_groups.yaml"):
        load_policy(policy_dir)


def test_missing_policy_directory_is_rejected(tmp_path: Path) -> None:
    with pytest.raises(PolicyError, match="Policy directory not found"):
        load_policy(tmp_path / "does-not-exist")


# --------------------------------------------------------------------------- #
# The loaded pack is read-only
# --------------------------------------------------------------------------- #


def test_loaded_pack_cannot_be_mutated(shipped_policy_dir: Path) -> None:
    pack = load_policy(shipped_policy_dir)
    rule = pack.algorithm("rsa-weak-key")

    with pytest.raises((AttributeError, TypeError)):
        pack.prefer_hybrid = False
    with pytest.raises((AttributeError, TypeError)):
        rule.verdict = "quantum_safe"
    with pytest.raises(TypeError):
        rule.condition["key_size_lt"] = 512
    with pytest.raises(TypeError):
        pack.pqc_target("kex-to-mlkem").requires["library"] = "openssl>=1.0"

    assert isinstance(pack.algorithms, tuple)
    assert isinstance(pack.pqc_targets, tuple)


# --------------------------------------------------------------------------- #
# Staleness (§6)
# --------------------------------------------------------------------------- #


def test_pack_goes_stale_after_the_configured_window(shipped_policy_dir: Path) -> None:
    version = load_policy(shipped_policy_dir).version

    assert version.is_stale(date(2026, 9, 30)) is False
    assert version.is_stale(date(2027, 9, 1)) is True
