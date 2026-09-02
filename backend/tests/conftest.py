"""Shared fixtures."""

from __future__ import annotations

import shutil
from collections.abc import Iterator
from pathlib import Path

import pytest
import sqlalchemy as sa
import yaml
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session, sessionmaker

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


@pytest.fixture
def settings():
    """The process-wide settings object.

    Cached by ``lru_cache``, so a test that mutates an attribute here changes
    what the endpoints see — which is how the caps are exercised below.
    """
    from app.config import get_settings

    return get_settings()


@pytest.fixture
def db_session(tmp_path: Path) -> Iterator[Session]:
    """A SQLite-backed session with the full schema.

    Postgres is the only supported store for real scans; SQLite exists so the
    suite runs without a database server, exactly as the step 1 migration test
    already does.
    """
    from app.models import Base

    engine = sa.create_engine(f"sqlite+pysqlite:///{(tmp_path / 'test.sqlite').as_posix()}")
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
    session = factory()
    try:
        yield session
    finally:
        session.close()
        engine.dispose()


@pytest.fixture
def client(db_session: Session) -> Iterator[TestClient]:
    """The app with its session dependency bound to ``db_session``.

    Entering the context manager runs the lifespan hook, so every API test also
    exercises the real policy pack loading at startup.
    """
    from app.db import get_session
    from app.main import app

    def _session_override() -> Iterator[Session]:
        try:
            yield db_session
            db_session.commit()
        except Exception:
            db_session.rollback()
            raise

    app.dependency_overrides[get_session] = _session_override
    try:
        with TestClient(app) as test_client:
            yield test_client
    finally:
        app.dependency_overrides.clear()


@pytest.fixture
def source_folder(tmp_path: Path):
    """Make a scannable folder holding ``count`` files across a couple of levels."""

    def _factory(count: int, name: str = "src") -> Path:
        root = tmp_path / name
        (root / "nested").mkdir(parents=True)
        for index in range(count):
            target = root if index % 2 == 0 else root / "nested"
            (target / f"file_{index:03d}.txt").write_text(f"file {index}\n", encoding="utf-8")
        return root

    return _factory
