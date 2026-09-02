"""Startup wiring — the policy pack must load before anything serves a request."""

from __future__ import annotations

import pytest

from app.core import policy_loader
from app.core.policy_loader import PolicyValidationError
from app.startup import initialise


@pytest.fixture(autouse=True)
def _clear_policy_cache():
    policy_loader.reset_policy_cache()
    yield
    policy_loader.reset_policy_cache()


def test_initialise_loads_settings_and_the_shipped_policy_pack() -> None:
    settings, policy = initialise()

    assert policy.version.version == "2026.09"
    assert policy.policy_dir == settings.policy_dir.resolve()
    # SPEC §2 guards on the synchronous scan path.
    assert settings.max_files_per_scan == 5000
    assert settings.max_probe_targets == 20


def test_get_policy_returns_the_same_pack_each_call() -> None:
    assert policy_loader.get_policy() is policy_loader.get_policy()


def test_startup_fails_loudly_on_an_uncited_pack(policy_dir_factory, monkeypatch) -> None:
    """A bad pack stops the process here, rather than yielding uncited verdicts later."""
    bad_dir = policy_dir_factory(
        "algorithms.yaml", lambda doc: doc["entries"][0].pop("source")
    )
    monkeypatch.setattr(
        policy_loader, "get_settings", lambda: type("S", (), {"policy_dir": bad_dir})()
    )

    with pytest.raises(PolicyValidationError, match="md5-hash"):
        initialise()


def test_database_module_imports_without_a_live_database() -> None:
    """create_engine must not connect at import time."""
    from app.db import Base, SessionLocal, engine

    assert engine is not None
    assert SessionLocal is not None
    assert "findings" in Base.metadata.tables
