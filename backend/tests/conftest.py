"""Shared fixtures."""

from __future__ import annotations

import shutil
import socket
import ssl
import threading
from collections.abc import Iterator
from pathlib import Path

import pytest
import sqlalchemy as sa
import yaml
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session, sessionmaker

BACKEND_ROOT = Path(__file__).resolve().parent.parent
SHIPPED_POLICY_DIR = BACKEND_ROOT / "policy"
DEMO_DIR = BACKEND_ROOT.parent / "demo"
TEST_DATA_DIR = Path(__file__).resolve().parent / "data"


@pytest.fixture(scope="session")
def shipped_policy_dir() -> Path:
    """The real ``backend/policy/`` pack, as it will ship."""
    return SHIPPED_POLICY_DIR


@pytest.fixture(scope="session")
def demo_dir() -> Path:
    """The demo environment (build step 3), which is also a scan target."""
    return DEMO_DIR


@pytest.fixture(scope="session")
def weak_cert_pem() -> bytes:
    """The demo's RSA-1024 / SHA-1 self-signed certificate.

    Read from ``demo/certs/`` when the demo environment has been generated, and
    from the committed copy otherwise — see ``tests/data/README.md``. Both are the
    same bytes; the fallback exists so a fresh clone with no OpenSSL still runs
    the certificate assertions rather than skipping them.
    """
    generated = DEMO_DIR / "certs" / "weak.crt"
    source = generated if generated.is_file() else TEST_DATA_DIR / "weak-rsa1024-sha1.crt"
    return source.read_bytes()


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
def approve_all_files(client: TestClient):
    """Approve every file the surface scan listed, and return the approval response.

    The approval body is the whole point of the gate, so it is built from what
    ``GET /files`` actually returned rather than from a directory walk: a file the
    API never offered can never be approved by a test either.
    """

    def _approve(scan_id: str) -> dict:
        tree = client.get(f"/api/scans/{scan_id}/files")
        assert tree.status_code == 200, tree.text

        paths: list[str] = []

        def walk(node: dict) -> None:
            for child in node["children"]:
                if child["type"] == "file":
                    paths.append(child["path"])
                else:
                    walk(child)

        walk(tree.json()["root"])
        response = client.post(f"/api/scans/{scan_id}/approve", json={"paths": paths})
        assert response.status_code == 200, response.text
        return response.json()

    return _approve


@pytest.fixture
def demo_scan(client: TestClient, demo_dir: Path, approve_all_files) -> dict:
    """A completed ``files`` scan of ``demo/``, approved in full.

    ``data_lifetime_years = 20`` per demo/README.md: at X=20 the Mosca inequality
    actually bites, which is what makes wave_1 and wave_2 populate in step 9.
    """
    created = client.post(
        "/api/scans",
        json={
            "mode": "files",
            "source_type": "folder",
            "source_ref": str(demo_dir),
            "data_lifetime_years": 20,
        },
    )
    assert created.status_code == 201, created.text
    return approve_all_files(created.json()["id"])


@pytest.fixture
def blocked_scan(db_session: Session):
    """A scan whose recommendation is blocked, without needing the demo lab.

    A probed service that tops out at TLS 1.2 with no OpenSSL observed anywhere:
    §11's blocker chain, both clauses unmet, one from an observation and one from
    the absence of any. The committed demo tree produces no blocked rows of its
    own, so the tests that need one build it here.
    """
    from app.core.advisor import advise_scan
    from app.core.policy import apply_policy
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

    scan = Scan(
        mode=ScanMode.PROBE_ONLY,
        source_type=SourceType.FOLDER,
        source_ref="/srv/probe",
        data_lifetime_years=5,
        policy_version="2026.09",
        status=ScanStatus.COMPLETE,
    )
    db_session.add(scan)
    db_session.flush()

    service = {"host": "localhost", "port": 8443}
    db_session.add_all(
        [
            Finding(
                scan_id=scan.id,
                collector=CollectorName.NETWORK,
                algorithm_name="ECDH",
                algorithm_family="ECDH",
                primitive=Primitive.KEY_EXCHANGE,
                confidence=Confidence.HIGH,
                source_layer=SourceLayer.LIVE,
                evidence_location="localhost:8443",
                evidence_raw={**service, "observation": "negotiated_group"},
            ),
            Finding(
                scan_id=scan.id,
                collector=CollectorName.NETWORK,
                algorithm_name="TLS 1.2",
                algorithm_family="TLS",
                primitive=Primitive.PROTOCOL,
                protocol_version="1.2",
                confidence=Confidence.HIGH,
                source_layer=SourceLayer.LIVE,
                evidence_location="localhost:8443",
                evidence_raw={**service, "observation": "protocol_version_accepted"},
            ),
        ]
    )
    db_session.flush()
    apply_policy(db_session, scan.id)
    advise_scan(db_session, scan)
    db_session.commit()
    return scan


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


@pytest.fixture
def scan_context(tmp_path: Path):
    """Build a :class:`ScanContext` over a throwaway tree.

    ``files`` maps relative path to contents (``str`` or ``bytes``); ``approved``
    defaults to every one of them. Passing a shorter ``approved`` list is how the
    scope tests express "this file exists but was not approved".
    """
    from uuid import uuid4

    from app.collectors.base import ScanContext

    def _factory(files: dict[str, object], approved: list[str] | None = None, **kwargs):
        root = tmp_path / "work"
        root.mkdir(exist_ok=True)
        for relative, content in files.items():
            target = root / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            if isinstance(content, bytes):
                target.write_bytes(content)
            else:
                # LF endings so a file's byte size is the same on every
                # platform: the certificate collector reports it verbatim.
                target.write_text(str(content), encoding="utf-8", newline="\n")
        return ScanContext.build(
            scan_id=uuid4(),
            work_dir=root,
            approved_paths=list(files) if approved is None else approved,
            **kwargs,
        )

    return _factory


# --------------------------------------------------------------------------- #
# A live TLS endpoint, without Docker
# --------------------------------------------------------------------------- #


def free_port() -> int:
    """An unused loopback port. Racy in principle, fine for one test process."""
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


def reachable(host: str, port: int, timeout: float = 0.5) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


@pytest.fixture(scope="session")
def local_tls_server(request) -> tuple[str, int]:
    """A TLS 1.2+ server on a free port, using the demo's own certificate.

    In-process and stdlib-only, so the network collector and the drift check meet
    a real handshake without Docker running. The TLS 1.2 floor is the point: it
    makes this the same shape as the demo's clean host, which is what "offered
    and refused" and "declared floor undercut" both have to be tested against.
    """
    certs = DEMO_DIR / "certs"
    if not (certs / "strong.crt").is_file():
        pytest.skip("demo/certs is generated and gitignored; run demo/gen_certs.sh")

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certs / "strong.crt", certs / "strong.key")
    context.minimum_version = ssl.TLSVersion.TLSv1_2

    port = free_port()
    listener = socket.socket()
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", port))
    listener.listen(128)

    def serve() -> None:
        while True:
            try:
                client, _ = listener.accept()
            except OSError:
                return
            try:
                # sslyze opens one connection per suite it tests, and most of
                # them are meant to fail. None of that is this server's problem.
                with context.wrap_socket(client, server_side=True) as tls:
                    tls.recv(1024)
            except Exception:
                pass
            finally:
                try:
                    client.close()
                except OSError:
                    pass

    for _ in range(16):
        threading.Thread(target=serve, daemon=True).start()

    request.addfinalizer(listener.close)
    return "127.0.0.1", port
