"""Startup wiring — the policy pack must load before anything serves a request.

The code rules' language coverage is checked here too, and the distinction
between the two kinds of check is the point of the last test: a pack defect
stops the process, an uncovered extension does not.
"""

from __future__ import annotations

import logging

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


def test_startup_names_the_scanned_extensions_no_rule_covers(caplog) -> None:
    """A gap in coverage is reported and survivable — unlike a gap in the pack.

    ``CODE_EXTENSIONS`` is wider than the rule file on purpose (§7.1), so this
    cannot be a failure. What it must not be is silent: a ``.rs`` file is sent to
    semgrep, parsed, and matched against nothing, and nobody would know.
    """
    with caplog.at_level(logging.WARNING, logger="app.collectors.code"):
        initialise()

    warning = next(
        record.getMessage()
        for record in caplog.records
        if "no rule behind them" in record.getMessage()
    )
    assert ".rs" in warning
    assert ".go" not in warning  # Go rules ship, so it is not part of the gap
