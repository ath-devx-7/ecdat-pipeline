"""Network probe — SPEC.md §7.5.

Three groups of tests, in the order §7.5 puts them.

**The allowlist.** These run first and need no server, because the property they
guard is not "the prober works" but "the prober cannot be pointed anywhere the
user did not name". An unbounded prober is an attack tool; that is a security
control, and it is tested as one.

**The wire.** A TLS server is started in-process on a free port from the demo's
own certificate, so the collector is exercised against a real handshake rather
than a mock. That server enforces a TLS 1.2 floor, which makes it the same shape
as the demo's clean host: it is what proves "TLS 1.0 was offered and refused" is
stored, rather than merely missing.

**The demo hosts.** `localhost:8443` and `:8444` need `docker compose up`, so
those tests skip when the lab is not running and say so. They are the only ones
that can prove the 8443 half — a server that genuinely accepts TLS 1.0 — because
nothing modern can be persuaded to speak it.
"""

from __future__ import annotations

import socket
import ssl
import threading
from pathlib import Path
from uuid import uuid4

import pytest

from app.collectors.base import ScanContext
from app.collectors.network import (
    OBS_PQC_GROUPS_UNDETERMINED,
    OBS_SUITE_PREFERENCE_UNDETERMINED,
    OBS_TARGET_UNREACHABLE,
    OBS_VERSION_NOT_OFFERED,
    NetworkCollector,
    ProbeScopeError,
    ProbeTarget,
    _named_group,
    declared_targets,
    ensure_allowed,
)
from app.core.policy_loader import load_policy
from app.models.enums import CollectorName, Confidence, Primitive, SourceLayer, Verdict


def context_for(*targets: tuple[str, int], **kwargs) -> ScanContext:
    return ScanContext.build(
        scan_id=uuid4(),
        work_dir=Path(__file__).parent,
        probe_targets=[{"host": host, "port": port} for host, port in targets],
        **kwargs,
    )


def named(findings, name: str) -> list:
    return [f for f in findings if f.algorithm_name == name]


def free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


def reachable(host: str, port: int, timeout: float = 0.5) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


# --------------------------------------------------------------------------- #
# Scope — the security control, tested before the scanner
# --------------------------------------------------------------------------- #


def test_the_prober_refuses_a_host_not_in_probe_targets() -> None:
    """The §16 test. The refusal is the feature, not an error path.

    Checked at the point of connection rather than while iterating the list, so a
    caller that reaches past ``collect()`` with a hostname of its own still
    cannot make this module open a socket to it.
    """
    ctx = context_for(("localhost", 8443))

    with pytest.raises(ProbeScopeError) as caught:
        ensure_allowed("example.com", 443, ctx)

    message = str(caught.value)
    assert "example.com:443" in message
    # The message names what *was* allowed, so the refusal is diagnosable.
    assert "localhost:8443" in message


def test_the_prober_refuses_a_declared_host_on_an_undeclared_port() -> None:
    """A port is part of the target, not a detail of it.

    8443 and 8444 in the demo are two services with opposite configurations.
    Treating a host as authorised for every port it happens to run would make the
    scope control decorative.
    """
    ctx = context_for(("localhost", 8443))

    with pytest.raises(ProbeScopeError):
        ensure_allowed("localhost", 8444, ctx)


def test_a_declared_target_is_matched_case_insensitively() -> None:
    """Hostnames are case-insensitive; refusing on capitalisation would be a bug."""
    ctx = context_for(("Demo.Example", 8443))

    assert ensure_allowed("demo.example", 8443, ctx) == ProbeTarget("Demo.Example", 8443)


def test_more_targets_than_the_cap_are_refused_rather_than_truncated(settings) -> None:
    """§2's cap. Reaching here means something built a scan without checking it.

    Probing the first twenty of an unvalidated list would be the wrong way to
    discover that: the scope was never approved, so none of it is in scope.
    """
    over_the_cap = settings.max_probe_targets + 1
    ctx = context_for(*[(f"host{n}.example", 443) for n in range(over_the_cap)])

    with pytest.raises(ProbeScopeError, match="cap"):
        declared_targets(ctx, settings)


def test_a_scan_with_no_targets_probes_nothing() -> None:
    """`files` mode reaches the collector registry but declares no targets."""
    assert NetworkCollector().collect(context_for()) == []


def test_every_attempt_is_logged(caplog) -> None:
    """§7.5 asks for a record of every target attempted — refusals included."""
    ctx = context_for(("localhost", 8443))

    with caplog.at_level("INFO"):
        with pytest.raises(ProbeScopeError):
            ensure_allowed("elsewhere.example", 443, ctx)

    assert any("elsewhere.example:443" in record.getMessage() for record in caplog.records)


# --------------------------------------------------------------------------- #
# Against a real handshake
# --------------------------------------------------------------------------- #


@pytest.fixture(scope="module")
def local_tls_server(request) -> tuple[str, int]:
    """A TLS 1.2+ server on a free port, using the demo's own certificate.

    In-process and stdlib-only, so the collector meets a real handshake without
    Docker. The TLS 1.2 floor is the point: it makes this the same shape as the
    demo's clean host, which is what "offered and refused" has to be tested on.
    """
    certs = Path(__file__).resolve().parent.parent.parent / "demo" / "certs"
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
                # sslyze opens one connection per suite it tests; each is
                # expected to fail for most of them, and none of that is
                # this server's problem.
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


@pytest.fixture(scope="module")
def probe_findings(local_tls_server) -> list:
    """One probe of the local server plus one dead port, run once for the module.

    The dead port is not a separate test setup — it is the "one target fails, the
    scan does not" case, asserted below on the same run that produced the rest.
    """
    host, port = local_tls_server
    ctx = context_for((host, port), (host, free_port()))
    return NetworkCollector().collect(ctx)


def test_the_probe_records_tls_1_0_as_explicitly_not_offered(
    probe_findings, local_tls_server
) -> None:
    """The 8444 property (§7.5), and the reason negatives are stored at all.

    A server that refuses TLS 1.0 and a server that never answered produce the
    same silence. Only one of them is a fact about the server, so the refusal is
    written down.
    """
    host, port = local_tls_server
    refused = [
        f
        for f in named(probe_findings, OBS_VERSION_NOT_OFFERED)
        if f.evidence_location == f"{host}:{port}"
    ]

    versions = {f.protocol_version for f in refused}
    assert {"1.0", "1.1", "3.0", "2.0"} <= versions
    for finding in refused:
        assert finding.evidence_raw["offered"] is False
        assert finding.source_layer is SourceLayer.LIVE
        assert finding.confidence is Confidence.HIGH


def test_a_refused_version_is_not_reported_as_a_use_of_it(probe_findings, db_session) -> None:
    """The correctness trap this collector is shaped around.

    ``tls-legacy`` says TLS below 1.2 is ``broken_now``. If a refusal carried the
    TLS family, the policy engine would fire that rule on a host whose whole
    merit is refusing it — reporting the clean configuration as the broken one.
    """
    from app.core.normalizer import normalize
    from app.core.policy import classify

    rows = normalize(db_session, uuid4(), named(probe_findings, OBS_VERSION_NOT_OFFERED))
    pack = load_policy(Path(__file__).resolve().parent.parent / "policy")

    assert rows, "the local server refuses TLS 1.0, so there is something to check"
    for row in rows:
        # The version is still on the row — the drift screen and the dashboard
        # join on it — it simply is not filed as a use of that version.
        assert row.protocol_version in {"1.0", "1.1", "2.0", "3.0"}
        assert row.algorithm_family != "TLS"
        assert classify(row, pack).verdict is not Verdict.BROKEN_NOW


def test_the_probe_records_the_versions_that_were_accepted(
    probe_findings, local_tls_server
) -> None:
    accepted = [
        f
        for f in probe_findings
        if f.evidence_raw.get("observation") == "protocol_version_accepted"
    ]

    assert {f.protocol_version for f in accepted} == {"1.2", "1.3"}
    for finding in accepted:
        assert finding.primitive is Primitive.PROTOCOL
        assert finding.collector is CollectorName.NETWORK
        # The spelling has to be one the alias table carries, or every protocol
        # finding off the wire lands unresolved (§8).
        assert finding.algorithm_name in {"TLS 1.2", "TLS 1.3"}


def test_each_accepted_suite_carries_the_version_it_was_accepted_at(probe_findings) -> None:
    """§7.5: a suite without its version is not an observation anyone can act on."""
    suites = [
        f
        for f in probe_findings
        if f.evidence_raw.get("observation") == "cipher_suite_accepted"
    ]

    assert suites
    for finding in suites:
        assert finding.protocol_version in {"1.2", "1.3"}
        assert finding.primitive is Primitive.CIPHER
        assert finding.algorithm_name.startswith("TLS_")
        # Both spellings kept: nginx declares the OpenSSL one for the same suite,
        # and collapsing the two is the normalizer's job.
        assert finding.evidence_raw["openssl_name"]


def test_the_negotiated_group_is_recorded_once_per_group(probe_findings) -> None:
    """Deduplicated per target: one group across twelve suites is one key exchange."""
    groups = [
        f for f in probe_findings if f.evidence_raw.get("observation") == "negotiated_group"
    ]

    names = [f.algorithm_name for f in groups]
    assert "X25519" in names
    assert len(names) == len(set(names))
    for finding in groups:
        assert finding.primitive is Primitive.KEY_EXCHANGE
        assert finding.key_size


def test_the_served_certificate_is_read_through_the_shared_extractor(probe_findings) -> None:
    """Same identities as the disk collector, differing only in source layer.

    §9 compares what a host serves against what its config declares. It cannot do
    that if the two halves were extracted by two different pieces of code.
    """
    certificate = [
        f
        for f in probe_findings
        if f.evidence_raw.get("observation") == "certificate_public_key"
    ]

    assert len(certificate) == 1
    finding = certificate[0]
    assert finding.algorithm_name == "ECDSA"
    assert finding.source_layer is SourceLayer.LIVE
    assert finding.collector is CollectorName.NETWORK
    assert finding.evidence_raw["served_over"] == "tls"
    assert finding.evidence_raw["subject"].startswith("CN=modern.ecdat.demo")


def test_what_sslyze_cannot_determine_is_stated_rather_than_omitted(
    probe_findings, local_tls_server
) -> None:
    """Two of §7.5's asks the installed version cannot answer.

    Reported at ``confidence: low`` instead of left out, because a PQC-readiness
    percentage computed over findings that silently omit "not measured" has a
    hole in it that nothing on the dashboard would show.
    """
    host, port = local_tls_server
    for marker in (OBS_SUITE_PREFERENCE_UNDETERMINED, OBS_PQC_GROUPS_UNDETERMINED):
        found = [
            f
            for f in named(probe_findings, marker)
            if f.evidence_location == f"{host}:{port}"
        ]
        assert len(found) == 1, marker
        assert found[0].confidence is Confidence.LOW
        assert found[0].evidence_raw["reason"]

    pqc = named(probe_findings, OBS_PQC_GROUPS_UNDETERMINED)[0]
    # The curve list it *could* see is kept, so the gap is legible rather than asserted.
    assert "X25519" in pqc.evidence_raw["supported_curves"]


def test_one_unreachable_target_does_not_cost_the_others(
    probe_findings, local_tls_server
) -> None:
    """The §16 survivability test, at target granularity rather than collector.

    The dead port produces an explicit finding of its own: "we could not reach
    it" is a different statement from "it offers nothing", and storing the first
    as the second is how a scanner reports a firewall as a clean bill of health.
    """
    host, live_port = local_tls_server
    unreachable = named(probe_findings, OBS_TARGET_UNREACHABLE)

    assert len(unreachable) == 1
    assert unreachable[0].evidence_location != f"{host}:{live_port}"
    assert unreachable[0].confidence is Confidence.LOW
    # …and the live target's findings all still arrived.
    live = [
        f for f in probe_findings if f.evidence_location == f"{host}:{live_port}"
    ]
    assert len(live) > 10


# --------------------------------------------------------------------------- #
# Named groups
# --------------------------------------------------------------------------- #


def test_a_raw_code_point_is_mapped_through_the_policy_table() -> None:
    """The mapping §7.5 asks for, for the day a scanner hands over a code point."""
    pack = load_policy(Path(__file__).resolve().parent.parent / "policy")

    assert _named_group("0x11EC", pack) == ("X25519MLKEM768", True)
    assert _named_group("29", pack) == ("x25519", True)


def test_a_group_this_build_cannot_name_is_flagged_rather_than_guessed() -> None:
    """nassl numbers unknown curves by OpenSSL NID, which is not a TLS code point.

    Two registries that do not correspond, so the table is not consulted and the
    string is reported verbatim — at low confidence, by the collector.
    """
    pack = load_policy(Path(__file__).resolve().parent.parent / "policy")

    name, recognised = _named_group("unknown-curve-with-openssl-id-1041", pack)
    assert name == "unknown-curve-with-openssl-id-1041"
    assert recognised is False


# --------------------------------------------------------------------------- #
# The demo lab — the only place a server that speaks TLS 1.0 exists
# --------------------------------------------------------------------------- #

DEMO_UP = reachable("localhost", 8443) and reachable("localhost", 8444)
needs_demo = pytest.mark.skipif(
    not DEMO_UP, reason="demo lab not running: docker compose -f demo/docker-compose.yml up"
)


@needs_demo
def test_the_demo_weak_host_accepts_tls_1_0() -> None:
    """Build step 7's exit criterion, and the fact the drift note is built on."""
    findings = NetworkCollector().collect(context_for(("localhost", 8443)))

    accepted = [
        f
        for f in findings
        if f.evidence_raw.get("observation") == "protocol_version_accepted"
        and f.protocol_version == "1.0"
    ]
    assert accepted, "8443 exists to accept TLS 1.0; see demo/README.md"
    assert accepted[0].source_layer is SourceLayer.LIVE


@needs_demo
def test_the_demo_clean_host_refuses_tls_1_0_explicitly() -> None:
    """The other half: refused, and recorded as refused rather than as absent."""
    findings = NetworkCollector().collect(context_for(("localhost", 8444)))

    refused = [
        f
        for f in named(findings, OBS_VERSION_NOT_OFFERED)
        if f.protocol_version == "1.0"
    ]
    assert len(refused) == 1
    assert refused[0].evidence_raw["offered"] is False
