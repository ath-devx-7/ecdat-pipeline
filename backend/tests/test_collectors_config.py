"""Config collector — SPEC.md §7.4.

Every finding here is tagged ``source_layer: config``, and that tag is load
bearing: it marks the finding as a *claim* about what a service will negotiate,
which is what §9 compares against the handshake. A test that let a config finding
through with any other layer would quietly break the drift check two steps later,
so it is asserted on each parser.

The openssl.cnf and nginx.conf cases read the real demo files rather than
fixtures. They are committed, they are the drift demo, and a parser tested only
against input written by the same person who wrote the parser proves less.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from app.collectors import config as config_module
from app.collectors.config import ConfigCollector
from app.models.enums import CollectorName, Confidence, Primitive, SourceLayer

DEMO_WEAK_NGINX = "etc/nginx/nginx.conf"
DEMO_WEAK_OPENSSL = "etc/ssl/openssl.cnf"


def collect(ctx) -> list:
    return ConfigCollector().collect(ctx)


def by_name(findings, name: str) -> list:
    return [finding for finding in findings if finding.algorithm_name == name]


def line_at(ctx, location: str) -> str:
    """The source line an ``evidence_location`` points at.

    Locations are asserted by reading the line back rather than by hardcoding a
    number, following the convention ``demo/README.md`` sets: editing a demo file
    should not silently invalidate a test, and a line number that has drifted onto
    a comment is a real defect a number-equality assertion would hide.
    """
    relative, _, number = location.rpartition(":")
    text = (ctx.work_dir / relative).read_text(encoding="utf-8")
    return text.splitlines()[int(number) - 1]


@pytest.fixture
def demo_file(demo_dir: Path):
    """Read a file out of the committed demo environment."""

    def _read(relative: str) -> str:
        return (demo_dir / relative).read_text(encoding="utf-8")

    return _read


# --------------------------------------------------------------------------- #
# openssl.cnf
# --------------------------------------------------------------------------- #


def test_the_demo_openssl_cnf_records_the_declared_tls_floor(scan_context, demo_file) -> None:
    """``MinProtocol = TLSv1.2`` — the claim half of the drift demo (§9)."""
    ctx = scan_context({DEMO_WEAK_OPENSSL: demo_file("weak-nginx/openssl.cnf")})

    findings = collect(ctx)

    floors = [
        finding
        for finding in findings
        if finding.evidence_raw.get("observation") == "protocol_floor"
    ]
    assert len(floors) == 1
    floor = floors[0]
    assert floor.algorithm_name == "TLSv1.2"
    assert floor.protocol_version == "TLSv1.2"
    assert floor.primitive is Primitive.PROTOCOL
    assert floor.collector is CollectorName.CONFIG
    assert floor.confidence is Confidence.HIGH
    # A declaration, not an observation. §9 exists because these can disagree.
    assert floor.source_layer is SourceLayer.CONFIG
    assert floor.evidence_raw["key"] == "MinProtocol"
    assert floor.evidence_raw["section"] == "system_default_sect"
    assert line_at(ctx, floor.evidence_location).strip() == "MinProtocol = TLSv1.2"

    # The ceiling is declared too, and it happens to agree with the server. The
    # collector reports both without deciding which one matters — that is §9's
    # job, and only the diverging site gets flagged there.
    ceilings = [
        finding
        for finding in findings
        if finding.evidence_raw.get("observation") == "protocol_ceiling"
    ]
    assert len(ceilings) == 1
    assert ceilings[0].algorithm_name == "TLSv1.2"


def test_the_weak_openssl_cnf_is_recorded_as_never_activated(scan_context, demo_file) -> None:
    """A fact, not a judgement: no ``openssl_conf`` pointer, so the section is inert.

    The declaration is still reported. §9 needs the claim in order to compare it
    against the handshake, and whether an inert file is an oversight or a
    leftover is the user's call (§9 rule 4).
    """
    weak = scan_context({DEMO_WEAK_OPENSSL: demo_file("weak-nginx/openssl.cnf")})
    strong = scan_context({"strong/openssl.cnf": demo_file("strong-nginx/openssl.cnf")})

    assert all(
        finding.evidence_raw["activated_by_openssl_conf"] is False
        for finding in collect(weak)
    )
    assert all(
        finding.evidence_raw["activated_by_openssl_conf"] is True
        for finding in collect(strong)
    )


def test_a_cipher_declaration_naming_no_suites_is_still_reported(
    scan_context, demo_file
) -> None:
    """``CipherString = DEFAULT@SECLEVEL=2`` is all selectors. Dropping it would lose it."""
    ctx = scan_context({"strong/openssl.cnf": demo_file("strong-nginx/openssl.cnf")})

    findings = collect(ctx)

    declaration = by_name(findings, "CipherString")
    assert len(declaration) == 1
    assert declaration[0].evidence_raw["observation"] == "cipher_selection_declared"
    assert declaration[0].evidence_raw["control_tokens"] == ["DEFAULT@SECLEVEL=2"]

    # Ciphersuites names two concrete TLS 1.3 suites, so those are enumerated.
    assert by_name(findings, "TLS_AES_256_GCM_SHA384")
    assert by_name(findings, "TLS_CHACHA20_POLY1305_SHA256")


# --------------------------------------------------------------------------- #
# nginx.conf
# --------------------------------------------------------------------------- #


def test_the_demo_nginx_conf_declares_one_finding_per_protocol_version(
    scan_context, demo_file
) -> None:
    """``ssl_protocols TLSv1 TLSv1.1 TLSv1.2`` is three declarations, not one.

    §9 flags diverging *usage sites*. A single row covering three versions cannot
    be diverged from in part, so the split has to happen here.
    """
    ctx = scan_context({DEMO_WEAK_NGINX: demo_file("weak-nginx/nginx.conf")})

    findings = collect(ctx)

    versions = {
        finding.protocol_version
        for finding in findings
        if finding.evidence_raw.get("observation") == "protocol_version_declared"
    }
    assert versions == {"TLSv1", "TLSv1.1", "TLSv1.2"}
    assert all(
        finding.source_layer is SourceLayer.CONFIG
        for finding in findings
    )


def test_nginx_findings_carry_the_server_block_that_step_8_joins_on(
    scan_context, demo_file
) -> None:
    """The listen port and server names, recorded where they are unambiguous (§9)."""
    ctx = scan_context({DEMO_WEAK_NGINX: demo_file("weak-nginx/nginx.conf")})

    findings = collect(ctx)

    server = by_name(findings, "TLSv1")[0].evidence_raw["server"]
    assert server["ports"] == [8443]
    assert server["server_names"] == ["legacy.ecdat.demo"]


def test_the_demo_nginx_cipher_list_separates_suites_from_selectors(
    scan_context, demo_file
) -> None:
    """``HIGH`` is not an algorithm and must not appear as one."""
    ctx = scan_context({DEMO_WEAK_NGINX: demo_file("weak-nginx/nginx.conf")})

    findings = collect(ctx)
    suites = {
        finding.algorithm_name
        for finding in findings
        if finding.evidence_raw.get("observation") == "cipher_suite_declared"
    }

    assert suites == {"AES128-SHA", "AES256-SHA", "DES-CBC3-SHA", "AES128-SHA256"}
    controls = by_name(findings, "DES-CBC3-SHA")[0].evidence_raw["control_tokens"]
    assert controls == ["HIGH", "MEDIUM", "@SECLEVEL=0"]
    assert not by_name(findings, "HIGH")


def test_nginx_certificate_paths_are_recorded_but_never_followed(
    scan_context, demo_file
) -> None:
    """A declared path points into the deployed filesystem, not into the approved tree."""
    ctx = scan_context({DEMO_WEAK_NGINX: demo_file("weak-nginx/nginx.conf")})

    findings = collect(ctx)

    certificate = by_name(findings, config_module.OBS_CERTIFICATE_PATH)
    key = by_name(findings, config_module.OBS_PRIVATE_KEY_PATH)
    assert certificate[0].evidence_raw["declared_path"] == "/etc/nginx/certs/weak.crt"
    assert key[0].evidence_raw["declared_path"] == "/etc/nginx/certs/weak.key"


def test_disabled_server_cipher_preference_is_reported_and_enabled_is_not(
    scan_context, demo_file
) -> None:
    weak = scan_context({DEMO_WEAK_NGINX: demo_file("weak-nginx/nginx.conf")})
    strong = scan_context({"strong/nginx.conf": demo_file("strong-nginx/nginx.conf")})

    assert by_name(collect(weak), config_module.OBS_NO_SERVER_CIPHER_PREFERENCE)
    assert not by_name(collect(strong), config_module.OBS_NO_SERVER_CIPHER_PREFERENCE)


def test_nginx_includes_are_not_followed(scan_context, monkeypatch) -> None:
    """An include would open a file the user never approved.

    The included file here does not even exist, which is the point: if crossplane
    were following includes this would surface as a parse error rather than as
    silence.
    """
    conf = (
        "http {\n"
        "    include /etc/nginx/conf.d/*.conf;\n"
        "    server {\n"
        "        listen 8443 ssl;\n"
        "        ssl_protocols TLSv1;\n"
        "    }\n"
        "}\n"
    )
    ctx = scan_context({"nginx.conf": conf})

    opened: list[str] = []
    real_open = Path.open

    def _tracking_open(self, *args, **kwargs):
        opened.append(str(self))
        return real_open(self, *args, **kwargs)

    monkeypatch.setattr(Path, "open", _tracking_open)
    findings = collect(ctx)

    assert by_name(findings, "TLSv1")
    assert not any("conf.d" in path for path in opened)


# --------------------------------------------------------------------------- #
# sshd_config
# --------------------------------------------------------------------------- #


def test_the_demo_sshd_config_declares_each_algorithm_with_its_primitive(
    scan_context, demo_file
) -> None:
    """The directive names the primitive — recording it is reading, not inferring."""
    ctx = scan_context({"etc/ssh/sshd_config": demo_file("sshd/sshd_config")})

    findings = collect(ctx)
    primitives = {finding.algorithm_name: finding.primitive for finding in findings}

    assert primitives["3des-cbc"] is Primitive.CIPHER
    assert primitives["diffie-hellman-group1-sha1"] is Primitive.KEY_EXCHANGE
    assert primitives["hmac-md5"] is Primitive.HASH
    assert primitives["ssh-rsa"] is Primitive.SIGNATURE
    assert all(finding.source_layer is SourceLayer.CONFIG for finding in findings)

    kex = by_name(findings, "diffie-hellman-group1-sha1")[0]
    assert line_at(ctx, kex.evidence_location).startswith("KexAlgorithms ")


def test_an_sshd_removal_list_is_one_finding_not_one_per_algorithm(scan_context) -> None:
    """``Ciphers -3des-cbc`` declares what the host switches *off*."""
    ctx = scan_context({"sshd_config": "Ciphers -3des-cbc,aes128-cbc\n"})

    findings = collect(ctx)

    assert len(findings) == 1
    assert findings[0].algorithm_name == "Ciphers"
    assert findings[0].evidence_raw["observation"] == "ssh_algorithms_removed"
    assert findings[0].evidence_raw["entries"] == ["3des-cbc", "aes128-cbc"]
    assert not by_name(findings, "3des-cbc")


# --------------------------------------------------------------------------- #
# java.security
# --------------------------------------------------------------------------- #


def test_the_demo_java_security_reports_one_finding_per_disabled_list(
    scan_context, demo_file
) -> None:
    """A disabled list is a negative declaration. Enumerating it would invert its meaning."""
    ctx = scan_context({"conf/java.security": demo_file("javaapp/java.security")})

    findings = collect(ctx)

    assert len(findings) == 2
    names = {finding.algorithm_name for finding in findings}
    assert names == {"jdk.tls.disabledAlgorithms", "jdk.certpath.disabledAlgorithms"}
    # RC4 is disabled here. A finding named RC4 would say this host uses it.
    assert not by_name(findings, "RC4")

    tls = by_name(findings, "jdk.tls.disabledAlgorithms")[0]
    assert tls.source_layer is SourceLayer.CONFIG
    assert "RC4" in tls.evidence_raw["entries"]
    # The continuation lines are joined, so what the property permits by omission
    # can be read off the entry list rather than guessed from the first line.
    assert "include jdk.disabled.namedCurves" in tls.evidence_raw["entries"]
    assert not any(entry.startswith("TLSv1") for entry in tls.evidence_raw["entries"])


# --------------------------------------------------------------------------- #
# Dispatch and scope
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("path", "expected"),
    [
        ("etc/ssl/openssl.cnf", "parse_openssl_cnf"),
        ("deep/nested/tree/openssl.conf", "parse_openssl_cnf"),
        ("etc/nginx/nginx.conf", "parse_nginx_conf"),
        ("containers/web-nginx.conf", "parse_nginx_conf"),
        ("etc/ssh/sshd_config", "parse_sshd_config"),
        ("image/etc/ssh/sshd_config", "parse_sshd_config"),
        ("jdk/conf/security/java.security", "parse_java_security"),
        # Not configs this collector understands.
        ("certs/embedded-cert.conf", None),
        ("app/settings.conf", None),
        ("README.md", None),
    ],
)
def test_files_are_recognised_by_name_anywhere_in_the_tree(path: str, expected) -> None:
    """§7.4: by name pattern, not by fixed path — location is a packaging accident."""
    parser = config_module._parser_for(path)

    assert (parser.__name__ if parser else None) == expected


def test_only_approved_files_are_parsed(scan_context, demo_file) -> None:
    conf = demo_file("weak-nginx/nginx.conf")
    ctx = scan_context(
        {"approved/nginx.conf": conf, "unapproved/nginx.conf": conf},
        approved=["approved/nginx.conf"],
    )

    findings = collect(ctx)

    assert findings
    assert {finding.evidence_raw["file"] for finding in findings} == {"approved/nginx.conf"}


def test_one_unparseable_file_does_not_lose_the_others(scan_context, demo_file) -> None:
    """A malformed config costs its own findings, not the run's."""
    ctx = scan_context(
        {
            "broken/nginx.conf": "http { server { ssl_protocols TLSv1;\n",  # unclosed
            "good/openssl.cnf": demo_file("weak-nginx/openssl.cnf"),
        }
    )

    findings = collect(ctx)

    assert any(finding.evidence_raw["file"] == "good/openssl.cnf" for finding in findings)
