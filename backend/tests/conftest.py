"""Shared fixtures."""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest
import yaml

BACKEND_ROOT = Path(__file__).resolve().parent.parent
SHIPPED_POLICY_DIR = BACKEND_ROOT / "policy"


@pytest.fixture(scope="session")
def shipped_policy_dir() -> Path:
    """The real ``backend/policy/`` pack, as it will ship."""
    return SHIPPED_POLICY_DIR


@pytest.fixture
def policy_dir_factory(tmp_path: Path):
    """Build a mutated copy of the shipped pack.

    ``mutate`` receives the parsed YAML of ``filename`` and edits it in place, so
    a test can express exactly one deviation from a pack known to be valid.
    """

    def _factory(filename: str, mutate) -> Path:
        target = tmp_path / "policy"
        shutil.copytree(SHIPPED_POLICY_DIR, target)
        path = target / filename
        document = yaml.safe_load(path.read_text(encoding="utf-8"))
        mutate(document)
        path.write_text(yaml.safe_dump(document, sort_keys=False), encoding="utf-8")
        return target

    return _factory
