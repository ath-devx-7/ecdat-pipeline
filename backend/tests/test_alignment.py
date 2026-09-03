"""Alignment check — SPEC.md §9.

The differentiator, so the tests are mostly about restraint rather than
detection. Finding a divergence is the easy half; the hard half is not reporting
one when a declaration agrees, when it governs a different service, when it is a
default a vhost may legitimately override, or when there is simply nothing on the
other side to compare against.

The headline case is reproduced without Docker: a config declaring a TLS 1.3
floor against a server that accepts TLS 1.2 is the same shape as the demo's
``openssl.cnf`` declaring TLS 1.2 against a host that accepts TLS 1.0 — a floor
the handshake goes underneath. The demo's own hosts need the lab running, and
those two tests skip with a message when it is not.
"""

from __future__ import annotations

import textwrap
from pathlib import Path
from uuid import uuid4

import pytest
import sqlalchemy as sa

from app.collectors.base import ScanContext
from app.collectors.config import ConfigCollector
from app.collectors.network import NetworkCollector
from app.core.alignment import (
    STATUS_COMPARED,
    STATUS_SKIPPED,
    UNCLASSIFIED_SUFFIX,
    align,
)
from app.core.normalizer import normalize
from app.models.enums import (
    CollectorName,
    Confidence,
    Primitive,
    ScanMode,
    ScanStatus,
    SourceLayer,
    SourceType,
)
from app.models.finding import AlignmentNote, Finding
from app.models.scan import Scan
from tests.conftest import reachable

DEMO_UP = reachable("localhost", 8443) and reachable("localhost", 8444)
needs_demo = pytest.mark.skipif(
    not DEMO_UP, reason="demo lab not running: docker compose -f demo/docker-compose.yml up"
)


@pytest.fixture
def scan_factory(db_session):
    """A ``scans`` row in whichever mode the test is about."""

    def _factory(mode: ScanMode = ScanMode.FILES_AND_PROBE) -> Scan:
        reads_files = mode is not ScanMode.PROBE_ONLY
        scan = Scan(
            mode=mode,
            source_type=SourceType.FOLDER if reads_files else SourceType.NONE,
            source_ref="/tmp/whatever" if reads_files else None,
            data_lifetime_years=20,
            policy_version="2026.09",
            status=ScanStatus.RUNNING,
        )
        db_session.add(scan)
        db_session.flush()
        return scan

    return _factory


def declared(scan, observation: str, version: str, location: str, server=None) -> Finding:
    """A config finding shaped as the normalizer would have stored it."""
    evidence = {"observation": observation, "file": location.split(":")[0]}
    if server is not None:
        evidence["server"] = server
    return Finding(
        scan_id=scan.id,
        collector=CollectorName.CONFIG,
        algorithm_name=f"TLSv{version}",
        algorithm_family="TLS",
        primitive=Primitive.PROTOCOL,
        protocol_version=version,
        evidence_location=location,
        evidence_raw=evidence,
        confidence=Confidence.HIGH,
        source_layer=SourceLayer.CONFIG,
    )


def observed(scan, observation: str, version: str, host: str, port: int) -> Finding:
    """A live finding, in the two shapes the prober emits for a version."""
    accepted = observation == "protocol_version_accepted"
    return Finding(
        scan_id=scan.id,
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


def notes_for(session, scan) -> list[AlignmentNote]:
    return list(
        session.scalars(sa.select(AlignmentNote).where(AlignmentNote.scan_id == scan.id))
    )


# --------------------------------------------------------------------------- #
# Nothing to compare — and it says so
# --------------------------------------------------------------------------- #


def test_alignment_is_skipped_in_probe_only_mode(db_session, scan_factory) -> None:
    """§9's required behaviour. The UI must show this, not an empty panel."""
    scan = scan_factory(ScanMode.PROBE_ONLY)
    db_session.add(observed(scan, "protocol_version_accepted", "1.0", "localhost", 8443))
    db_session.flush()

    result = align(db_session, scan)

    assert result.status == STATUS_SKIPPED
    assert "no config findings" in result.reason
    assert result.as_dict() == {"status": "skipped", "reason": result.reason}


def test_alignment_is_skipped_in_files_mode(db_session, scan_factory) -> None:
    """A files scan probes nothing, so there is no fact to hold the claim against."""
    scan = scan_factory(ScanMode.FILES)
    db_session.add(declared(scan, "protocol_floor", "1.2", "etc/ssl/openssl.cnf:31"))
    db_session.flush()

    result = align(db_session, scan)

    assert result.status == STATUS_SKIPPED
    assert "no live findings" in result.reason


def test_a_live_finding_with_no_config_finding_produces_no_note(
    db_session, scan_factory
) -> None:
    """§9: if no config finding covers a live finding's service, emit nothing.

    Not a note saying "undeclared" — nothing. A service the scan holds no
    declaration for is a service this check has no opinion about.
    """
    scan = scan_factory()
    db_session.add_all(
        [
            observed(scan, "protocol_version_accepted", "1.0", "localhost", 8443),
            # A declaration that governs a different service entirely.
            declared(
                scan,
                "protocol_version_declared",
                "1.3",
                "strong/nginx.conf:36",
                server={"ports": [8444], "server_names": ["modern.ecdat.demo"]},
            ),
        ]
    )
    db_session.flush()

    result = align(db_session, scan)

    assert result.status == STATUS_COMPARED
    assert result.notes == ()
    assert notes_for(db_session, scan) == []


def test_sshd_declarations_never_produce_a_note(db_session, scan_factory) -> None:
    """demo/README.md §H: config with no live counterpart produces nothing.

    Nothing in the demo probes SSH, and a check that reached for the nearest
    available live finding would be guessing at the join §9 forbids guessing at.
    """
    scan = scan_factory()
    ssh = Finding(
        scan_id=scan.id,
        collector=CollectorName.CONFIG,
        algorithm_name="diffie-hellman-group1-sha1",
        algorithm_family="DH",
        primitive=Primitive.KEY_EXCHANGE,
        evidence_location="sshd/sshd_config:6",
        evidence_raw={"observation": "ssh_kex_declared", "file": "sshd/sshd_config"},
        confidence=Confidence.HIGH,
        source_layer=SourceLayer.CONFIG,
    )
    db_session.add_all(
        [ssh, observed(scan, "protocol_version_accepted", "1.2", "localhost", 8443)]
    )
    db_session.flush()

    assert align(db_session, scan).notes == ()


# --------------------------------------------------------------------------- #
# Divergence
# --------------------------------------------------------------------------- #


def test_a_floor_the_server_undercuts_produces_exactly_one_note(
    db_session, scan_factory
) -> None:
    """The demo's headline note, in miniature.

    Two accepted versions sit below the declared floor. That is one divergence
    between one declaration and one service, not two: §9 rule 3's usage site is
    the probed service, so the note names both observations and is written once.
    """
    scan = scan_factory()
    db_session.add_all(
        [
            declared(scan, "protocol_floor", "1.2", "weak/openssl.cnf:31"),
            observed(scan, "protocol_version_accepted", "1.0", "localhost", 8443),
            observed(scan, "protocol_version_accepted", "1.1", "localhost", 8443),
            observed(scan, "protocol_version_accepted", "1.2", "localhost", 8443),
        ]
    )
    db_session.flush()

    result = align(db_session, scan)

    assert len(result.notes) == 1
    note = result.notes[0]
    assert "TLS 1.0 was accepted" in note.note
    assert "TLS 1.1 was accepted" in note.note
    assert "minimum protocol version of TLS 1.2" in note.note
    # Anchored to the live finding, because live is what the report carries.
    live = db_session.get(Finding, note.live_finding_id)
    assert live.source_layer is SourceLayer.LIVE
    assert live.protocol_version == "1.0"


def test_a_declaration_that_matches_produces_no_note(db_session, scan_factory) -> None:
    """``MaxProtocol = TLSv1.2`` on a host that tops out at 1.2 agrees with reality.

    demo/README.md calls this out by name: a check that flags the file because
    one other line in it diverges is wrong.
    """
    scan = scan_factory()
    db_session.add_all(
        [
            declared(scan, "protocol_ceiling", "1.2", "weak/openssl.cnf:37"),
            observed(scan, "protocol_version_accepted", "1.0", "localhost", 8443),
            observed(scan, "protocol_version_accepted", "1.2", "localhost", 8443),
            observed(scan, "protocol_version_not_offered", "1.3", "localhost", 8443),
        ]
    )
    db_session.flush()

    assert align(db_session, scan).notes == ()


def test_only_the_diverging_service_is_flagged(db_session, scan_factory) -> None:
    """§9 rule 3, stated exactly as the spec states it.

    One declaration covers two services. One diverges. One note, naming that
    service — and the service that agrees is not mentioned at all.
    """
    scan = scan_factory()
    db_session.add_all(
        [
            declared(scan, "protocol_floor", "1.2", "etc/ssl/openssl.cnf:31"),
            observed(scan, "protocol_version_accepted", "1.0", "localhost", 8443),
            observed(scan, "protocol_version_accepted", "1.3", "localhost", 8444),
        ]
    )
    db_session.flush()

    result = align(db_session, scan)

    assert len(result.notes) == 1
    assert "localhost:8443" in result.notes[0].asset_key
    assert "8444" not in result.notes[0].note


def test_a_version_declared_but_refused_is_also_a_divergence(
    db_session, scan_factory
) -> None:
    """The explicit negatives step 7 stores earn their keep here.

    The config says the service offers TLS 1.2 and the handshake says it does
    not. Storing "offered and refused" as a finding rather than as an absence is
    what makes that a comparison rather than a silence.
    """
    scan = scan_factory()
    server = {"ports": [8443], "server_names": ["legacy.ecdat.demo"]}
    db_session.add_all(
        [
            declared(scan, "protocol_version_declared", "1.2", "nginx.conf:43", server=server),
            declared(scan, "protocol_version_declared", "1.3", "nginx.conf:43", server=server),
            observed(scan, "protocol_version_accepted", "1.3", "localhost", 8443),
            observed(scan, "protocol_version_not_offered", "1.2", "localhost", 8443),
        ]
    )
    db_session.flush()

    result = align(db_session, scan)

    assert len(result.notes) == 1
    assert "TLS 1.2 is declared but was offered and refused" in result.notes[0].note


def test_the_note_reports_the_difference_without_classifying_it(
    db_session, scan_factory
) -> None:
    """§9 rule 4. The wording is the check, so the wording is tested.

    Whether a divergence is a misconfiguration or a deliberate exception for one
    host belongs to whoever owns the server. Nothing here may imply an answer.
    """
    scan = scan_factory()
    db_session.add_all(
        [
            declared(scan, "protocol_floor", "1.2", "weak/openssl.cnf:31"),
            observed(scan, "protocol_version_accepted", "1.0", "localhost", 8443),
        ]
    )
    db_session.flush()

    note = align(db_session, scan).notes[0].note

    # Both sides named, and which is which.
    assert "Observed on localhost:8443" in note
    assert "weak/openssl.cnf:31" in note
    assert "does not align" in note

    # Every note ends with the same refusal to classify, and it is the only
    # place the word "misconfiguration" may appear — as one of two possibilities
    # the tool explicitly declines to choose between.
    assert note.endswith(UNCLASSIFIED_SUFFIX)
    reported = note[: -len(UNCLASSIFIED_SUFFIX)].lower()
    banned = (
        "misconfigur", "violation", "insecure", "should", "must", "severity", "wrong",
    )
    for word in banned:
        assert word not in reported, word


def test_the_asset_key_records_what_matched(db_session, scan_factory) -> None:
    """§9: record the join, not just the fact that one happened."""
    scan = scan_factory()
    db_session.add_all(
        [
            declared(
                scan,
                "protocol_version_declared",
                "1.3",
                "weak/nginx.conf:43",
                server={"ports": [8443], "server_names": ["legacy.ecdat.demo"]},
            ),
            observed(scan, "protocol_version_accepted", "1.0", "localhost", 8443),
        ]
    )
    db_session.flush()

    key = align(db_session, scan).notes[0].asset_key

    assert key.startswith("localhost:8443")
    assert "8443" in key and "server block" in key


# --------------------------------------------------------------------------- #
# The scope guard
# --------------------------------------------------------------------------- #


def test_a_server_wide_nginx_default_is_not_compared_to_one_vhost(
    db_session, scan_factory
) -> None:
    """§9's scope guard, and the distinction it turns on.

    An ``ssl_protocols`` outside any server block is a default a server block may
    override, so a vhost negotiating differently may simply be a vhost that
    overrode it. Not drift. The skip is reported rather than silent — "we did not
    compare this, and why" belongs on the drift screen too.
    """
    scan = scan_factory()
    db_session.add_all(
        [
            # No `server` key in evidence: the directive sat at http level.
            declared(scan, "protocol_version_declared", "1.3", "nginx.conf:12"),
            observed(scan, "protocol_version_accepted", "1.0", "localhost", 8443),
        ]
    )
    db_session.flush()

    result = align(db_session, scan)

    assert result.notes == ()
    assert result.scope_skipped == ("nginx.conf:12 (a server-wide default)",)


def test_a_library_floor_is_compared_because_nothing_can_negotiate_below_it(
    db_session, scan_factory
) -> None:
    """The other side of the same guard, and why the demo's note exists at all.

    An ``openssl.cnf`` floor is not a default — it is a floor the library
    enforces, and nothing layered above it can negotiate underneath it. A
    handshake below it is a contradiction no vhost setting explains.
    """
    scan = scan_factory()
    db_session.add_all(
        [
            declared(scan, "protocol_floor", "1.2", "etc/ssl/openssl.cnf:31"),
            observed(scan, "protocol_version_accepted", "1.0", "localhost", 8443),
        ]
    )
    db_session.flush()

    result = align(db_session, scan)

    assert len(result.notes) == 1
    assert "library-wide" in result.notes[0].asset_key
    assert result.scope_skipped == ()


def test_rerunning_replaces_the_notes_rather_than_adding_to_them(
    db_session, scan_factory
) -> None:
    scan = scan_factory()
    db_session.add_all(
        [
            declared(scan, "protocol_floor", "1.2", "weak/openssl.cnf:31"),
            observed(scan, "protocol_version_accepted", "1.0", "localhost", 8443),
        ]
    )
    db_session.flush()

    align(db_session, scan)
    align(db_session, scan)

    assert len(notes_for(db_session, scan)) == 1


# --------------------------------------------------------------------------- #
# Through the real collectors
# --------------------------------------------------------------------------- #


OPENSSL_CNF = textwrap.dedent(
    """
    openssl_conf = default_conf

    [ default_conf ]
    ssl_conf = ssl_sect

    [ ssl_sect ]
    system_default = system_default_sect

    [ system_default_sect ]
    MinProtocol = TLSv1.3
    MaxProtocol = TLSv1.3
    """
).strip()


@pytest.fixture
def drift_scan(db_session, scan_factory, local_tls_server, tmp_path):
    """A real config parse and a real handshake, disagreeing.

    The same shape as the demo's weak host: a declared floor the server goes
    underneath. Here the floor is TLS 1.3 and the server accepts TLS 1.2, because
    nothing modern can be talked into speaking TLS 1.0 — the demo's Docker host
    is the only place that half exists.
    """
    host, port = local_tls_server
    scan = scan_factory(ScanMode.FILES_AND_PROBE)

    work = tmp_path / "work"
    work.mkdir()
    (work / "etc").mkdir()
    (work / "etc" / "openssl.cnf").write_text(OPENSSL_CNF, encoding="utf-8", newline="\n")

    file_ctx = ScanContext.build(
        scan_id=scan.id, work_dir=work, approved_paths=["etc/openssl.cnf"]
    )
    probe_ctx = ScanContext.build(
        scan_id=scan.id, work_dir=work, probe_targets=[{"host": host, "port": port}]
    )
    raw = ConfigCollector().collect(file_ctx) + NetworkCollector().collect(probe_ctx)
    normalize(db_session, scan.id, raw)
    return scan, f"{host}:{port}"


def test_a_real_scan_produces_one_note_naming_the_divergence(
    db_session, drift_scan
) -> None:
    """Build step 8's exit criterion, through the collectors rather than fixtures.

    One note: the declared floor against the service that goes under it. The
    ``MaxProtocol`` declaration on the line below agrees with reality — the
    server tops out at TLS 1.3 too — and is not flagged, which is the half that
    proves the check reads declarations rather than files.
    """
    scan, target = drift_scan

    result = align(db_session, scan)

    assert result.status == STATUS_COMPARED
    assert len(result.notes) == 1, [n.note for n in result.notes]
    note = result.notes[0]
    assert target in note.asset_key
    assert "TLS 1.2 was accepted" in note.note
    assert "minimum protocol version of TLS 1.3" in note.note
    assert "openssl.cnf" in note.note


def test_the_note_survives_into_the_database(db_session, drift_scan) -> None:
    """§9 runs before the policy engine, so the row has to be there, not in memory."""
    scan, _ = drift_scan
    align(db_session, scan)

    stored = notes_for(db_session, scan)
    assert len(stored) == 1
    config_side = db_session.get(Finding, stored[0].config_finding_id)
    live_side = db_session.get(Finding, stored[0].live_finding_id)
    assert config_side.source_layer is SourceLayer.CONFIG
    assert live_side.source_layer is SourceLayer.LIVE


def test_the_api_reports_the_skipped_state_rather_than_an_empty_panel(demo_scan) -> None:
    """§9: "the UI must display this, not an empty panel" — so it has to reach the UI.

    A ``files`` scan of the demo tree has plenty of declarations and no
    handshake to hold them against. "No drift found" and "drift was never
    checked" are different statements about a host, and only one of them is true
    here.
    """
    alignment = demo_scan["alignment"]

    assert alignment["status"] == "skipped"
    assert "no live findings" in alignment["reason"]


# --------------------------------------------------------------------------- #
# The demo lab
# --------------------------------------------------------------------------- #


@needs_demo
def test_the_demo_weak_host_produces_exactly_one_alignment_note(
    db_session, scan_factory, demo_dir: Path
) -> None:
    """The drift the whole project exists to demonstrate.

    Scoped to one host's files and one probe target, which is how the tool is
    actually pointed at a deployment: `demo/` holds two hosts' configs, and
    nothing in a config file says which host it governs — §9 forbids inferring
    that, so the scan scope is what separates them.
    """
    scan = scan_factory(ScanMode.FILES_AND_PROBE)
    file_ctx = ScanContext.build(
        scan_id=scan.id,
        work_dir=demo_dir,
        approved_paths=["weak-nginx/nginx.conf", "weak-nginx/openssl.cnf"],
    )
    probe_ctx = ScanContext.build(
        scan_id=scan.id, work_dir=demo_dir, probe_targets=[{"host": "localhost", "port": 8443}]
    )
    normalize(
        db_session,
        scan.id,
        ConfigCollector().collect(file_ctx) + NetworkCollector().collect(probe_ctx),
    )

    result = align(db_session, scan)

    assert len(result.notes) == 1, [n.note for n in result.notes]
    assert "TLS 1.0 was accepted" in result.notes[0].note
    assert "minimum protocol version of TLS 1.2" in result.notes[0].note


@needs_demo
def test_the_demo_clean_host_produces_zero_alignment_notes(
    db_session, scan_factory, demo_dir: Path
) -> None:
    """Every declaration on 8444 matches what it negotiates."""
    scan = scan_factory(ScanMode.FILES_AND_PROBE)
    file_ctx = ScanContext.build(
        scan_id=scan.id,
        work_dir=demo_dir,
        approved_paths=["strong-nginx/nginx.conf", "strong-nginx/openssl.cnf"],
    )
    probe_ctx = ScanContext.build(
        scan_id=scan.id, work_dir=demo_dir, probe_targets=[{"host": "localhost", "port": 8444}]
    )
    normalize(
        db_session,
        scan.id,
        ConfigCollector().collect(file_ctx) + NetworkCollector().collect(probe_ctx),
    )

    result = align(db_session, scan)

    assert result.status == STATUS_COMPARED
    assert result.notes == ()
