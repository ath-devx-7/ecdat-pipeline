"""Network probe — SPEC.md §7.5, build step 7.

The only collector that touches something outside the machine, and the only one
whose bugs are someone else's incident. Everything below is shaped by that.

**The allowlist is the feature.** :func:`ensure_allowed` runs at the point of
connection, not at the point of iteration, so a caller that reaches past
``collect()`` with a hostname of its own still cannot make this module open a
socket to it. An unbounded prober is an attack tool; a prober that can only reach
hosts the user typed into the scan is a scanner. The check and its test were
written before the scanning logic, which is the order §7.5 asks for.

**Absence of a result is not a result.** A server that refuses TLS 1.0 and a
server that never answered look identical if you only record what succeeded, and
"we could not reach it" must never be reported as "it is not offered". So three
different silences are stored as three different findings: a version that was
offered and refused, a target that could not be reached at all, and a scan
command that errored.

**A refusal is not a use.** ``tls-version-not-offered`` deliberately does not
carry the TLS family, because the policy engine (§10) would match it against
``tls-legacy`` and report a host that *rejects* TLS 1.0 as broken for supporting
it. The version still lands in ``protocol_version`` so the drift check and the
dashboard can join on it; only the identity says what kind of observation it is.

**What the installed sslyze cannot see is written down.** Version 6.3.1 does not
report cipher-suite preference at all, and its group enumeration walks
``nassl``'s ``OpenSslEcNidEnum`` — thirty classical curves, no hybrid PQC groups,
so it does not fail on ``X25519MLKEM768``, it simply never asks. Both produce an
explicit ``confidence: low`` finding rather than silence, because a PQC-readiness
percentage that quietly counts "not measured" as "not present" is a number nobody
should act on.

Certificates seen on the wire go through ``certificate_findings()`` in
``collectors/certs.py`` — one implementation, two source layers. §9 compares
exactly that pair, and it cannot compare them if they were extracted twice.
"""

from __future__ import annotations

import logging
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any, ClassVar

from sslyze import (
    ScanCommand,
    ScanCommandAttempt,
    ScanCommandAttemptStatusEnum,
    Scanner,
    ServerNetworkConfiguration,
    ServerNetworkLocation,
    ServerScanRequest,
    ServerScanResult,
    ServerScanStatusEnum,
    TlsVersionEnum,
)

from app.collectors.base import Collector, RawFinding, ScanContext
from app.collectors.certs import CertificateSource, certificate_findings
from app.config import Settings, get_settings
from app.core.policy_loader import PolicyPack, get_policy
from app.models.enums import CollectorName, Confidence, Primitive, SourceLayer

logger = logging.getLogger(__name__)

__all__ = [
    "NetworkCollector",
    "ProbeScopeError",
    "ProbeTarget",
    "declared_targets",
    "ensure_allowed",
]


class ProbeScopeError(RuntimeError):
    """A target outside the scan's declared scope, or more targets than §2 allows.

    Raised rather than skipped. A prober asked to reach somewhere it was not
    authorised to reach has been misused, and continuing quietly with the rest of
    the list would leave no trace of the attempt in anything but a log line.
    """


@dataclass(frozen=True, slots=True)
class ProbeTarget:
    """One ``{host, port}`` entry of the scan's allowlist."""

    host: str
    port: int

    @property
    def key(self) -> tuple[str, int]:
        """Comparison form. Hostnames are case-insensitive; ports are not text."""
        return self.host.strip().lower(), self.port

    def __str__(self) -> str:
        return f"{self.host}:{self.port}"


# --------------------------------------------------------------------------- #
# Scope — written first, on purpose
# --------------------------------------------------------------------------- #


def declared_targets(
    ctx: ScanContext, settings: Settings | None = None
) -> tuple[ProbeTarget, ...]:
    """The scan's allowlist, parsed and capped (§2).

    Exceeding the cap raises rather than truncating. The API rejects an oversized
    target list at creation, so reaching here means a scan row was built by
    something that did not check — and half-probing an unvalidated scope silently
    is the wrong way to find that out.
    """
    settings = settings or get_settings()
    targets: list[ProbeTarget] = []
    for entry in ctx.probe_targets:
        host = str(entry.get("host", "")).strip()
        if not host:
            continue
        targets.append(ProbeTarget(host=host, port=int(entry.get("port", 443))))

    if len(targets) > settings.max_probe_targets:
        raise ProbeScopeError(
            f"scan declares {len(targets)} probe targets, above the per-scan cap of "
            f"{settings.max_probe_targets} (§2). Split the run, or raise "
            "ECDAT_MAX_PROBE_TARGETS."
        )
    return tuple(targets)


def ensure_allowed(
    host: str, port: int, ctx: ScanContext, settings: Settings | None = None
) -> ProbeTarget:
    """Return the target, or refuse. **Every** connection goes through here.

    Deliberately takes a bare host and port rather than a :class:`ProbeTarget`:
    the caller has to present what it intends to connect to, and this function —
    not the caller's own bookkeeping — decides whether that is in scope.
    """
    requested = ProbeTarget(host=str(host), port=int(port))
    allowed = {target.key: target for target in declared_targets(ctx, settings)}

    # Logged whether or not it is allowed: §7.5 asks for a record of every target
    # attempted, and the refusals are the half worth having.
    logger.info("scan %s: probe requested for %s", ctx.scan_id, requested)

    if requested.key not in allowed:
        declared = ", ".join(str(target) for target in allowed.values()) or "(none)"
        raise ProbeScopeError(
            f"{requested} is not in this scan's probe_targets. Declared: {declared}. "
            "The prober refuses any host the user did not name — this is a scope "
            "control, not a configuration default."
        )
    return allowed[requested.key]


# --------------------------------------------------------------------------- #
# Vocabulary
# --------------------------------------------------------------------------- #

#: sslyze's version enum → (the spelling the alias table resolves, canonical
#: version). The left column has to stay a spelling ``algorithm_aliases.yaml``
#: carries, or every protocol finding from the wire lands unresolved.
TLS_VERSIONS: Mapping[TlsVersionEnum, tuple[str, str]] = {
    TlsVersionEnum.SSL_2_0: ("SSL 2.0", "2.0"),
    TlsVersionEnum.SSL_3_0: ("SSL 3.0", "3.0"),
    TlsVersionEnum.TLS_1_0: ("TLS 1.0", "1.0"),
    TlsVersionEnum.TLS_1_1: ("TLS 1.1", "1.1"),
    TlsVersionEnum.TLS_1_2: ("TLS 1.2", "1.2"),
    TlsVersionEnum.TLS_1_3: ("TLS 1.3", "1.3"),
}

#: Every ``*_cipher_suites`` command, plus the four §7.5 names by hand.
SCAN_COMMANDS = frozenset(
    {
        ScanCommand.SSL_2_0_CIPHER_SUITES,
        ScanCommand.SSL_3_0_CIPHER_SUITES,
        ScanCommand.TLS_1_0_CIPHER_SUITES,
        ScanCommand.TLS_1_1_CIPHER_SUITES,
        ScanCommand.TLS_1_2_CIPHER_SUITES,
        ScanCommand.TLS_1_3_CIPHER_SUITES,
        ScanCommand.CERTIFICATE_INFO,
        ScanCommand.ELLIPTIC_CURVES,
        ScanCommand.SESSION_RENEGOTIATION,
        ScanCommand.TLS_COMPRESSION,
    }
)

#: Observation names. None of them are algorithms, and the normalizer keeps them
#: as their own identity rather than pretending the alias table knows them.
OBS_VERSION_NOT_OFFERED = "tls-version-not-offered"
OBS_TARGET_UNREACHABLE = "probe-target-unreachable"
OBS_COMMAND_FAILED = "probe-command-failed"
OBS_SUITE_PREFERENCE_UNDETERMINED = "tls-suite-preference-undetermined"
OBS_PQC_GROUPS_UNDETERMINED = "pqc-group-support-undetermined"
OBS_INSECURE_RENEGOTIATION = "tls-insecure-renegotiation"
OBS_RENEGOTIATION_DOS = "tls-client-renegotiation-dos"
OBS_COMPRESSION_ENABLED = "tls-compression-enabled"

#: What nassl calls a group it has no name for. Its numbering is OpenSSL NIDs,
#: not TLS code points, so it is reported verbatim and flagged rather than
#: guessed at — see ``policy/named_groups.yaml``.
_UNNAMED_CURVE = re.compile(r"^unknown-curve-with-openssl-id-(\d+)$")

#: A group reported as a bare TLS code point, which `named_groups.yaml` maps.
#: ``0x11EC`` is hex, ``4588`` is decimal, and an unprefixed ``11EC`` matches
#: neither on purpose — it could be either base, and a group identified by
#: guessing at a number's base is not identified.
_CODE_POINT = re.compile(r"^(?:0x([0-9a-fA-F]{1,4})|(\d{1,5}))$")


# --------------------------------------------------------------------------- #
# The collector
# --------------------------------------------------------------------------- #


class NetworkCollector(Collector):
    """§7.5. ``source_layer: live`` — the only collector that observes a fact."""

    name: ClassVar[CollectorName] = CollectorName.NETWORK

    def collect(self, ctx: ScanContext) -> list[RawFinding]:
        settings = get_settings()
        targets = declared_targets(ctx, settings)
        if not targets:
            return []

        ctx.check_budget("probing")
        policy = get_policy()

        # Queued together rather than probed in sequence: sslyze parallelises
        # across servers, and a per-server failure already comes back as that
        # server's own result rather than as an exception. Twenty targets at the
        # §2 cap would not fit the collector budget serially.
        results = _run_scans(targets, ctx, settings)

        findings: list[RawFinding] = []
        for target in targets:
            result = results.get(target.key)
            if result is None:
                findings.append(
                    _marker(
                        OBS_TARGET_UNREACHABLE,
                        target,
                        confidence=Confidence.LOW,
                        evidence={"reason": "sslyze returned no result for this target"},
                    )
                )
                continue
            try:
                findings.extend(_findings_for(result, target, policy))
            except Exception as exc:  # noqa: BLE001 - one target, not the scan
                # §7.5's own rule, applied one level down from the runner's: a
                # host that answers something this parser was not written for
                # costs its own findings and nothing else.
                logger.exception("scan %s: could not read the scan of %s", ctx.scan_id, target)
                findings.append(
                    _marker(
                        OBS_COMMAND_FAILED,
                        target,
                        confidence=Confidence.LOW,
                        evidence={"error": f"{type(exc).__name__}: {exc}"},
                    )
                )
        return findings


def _run_scans(
    targets: Sequence[ProbeTarget], ctx: ScanContext, settings: Settings
) -> dict[tuple[str, int], ServerScanResult]:
    """Queue every allowed target and collect the results, keyed for lookup."""
    requests = []
    for target in targets:
        # Re-checked here even though `declared_targets` produced the list. This
        # is the line that actually precedes a socket, and the guarantee is worth
        # more than the microsecond.
        allowed = ensure_allowed(target.host, target.port, ctx, settings)
        requests.append(
            ServerScanRequest(
                server_location=ServerNetworkLocation(
                    hostname=allowed.host, port=allowed.port
                ),
                network_configuration=ServerNetworkConfiguration(
                    tls_server_name_indication=allowed.host,
                    network_timeout=settings.probe_timeout_seconds,
                ),
                scan_commands=set(SCAN_COMMANDS),
            )
        )

    scanner = Scanner()
    scanner.queue_scans(requests)
    return {
        (result.server_location.hostname.strip().lower(), result.server_location.port): result
        for result in scanner.get_results()
    }


# --------------------------------------------------------------------------- #
# Result → findings
# --------------------------------------------------------------------------- #


def _findings_for(
    result: ServerScanResult, target: ProbeTarget, policy: PolicyPack
) -> list[RawFinding]:
    if result.scan_status is not ServerScanStatusEnum.COMPLETED:
        # The distinction §7.5 exists to preserve: this is "we could not ask",
        # which is not the same statement as "the server does not offer it".
        return [
            _marker(
                OBS_TARGET_UNREACHABLE,
                target,
                confidence=Confidence.LOW,
                evidence={
                    "scan_status": result.scan_status.name,
                    "connectivity_status": result.connectivity_status.name
                    if result.connectivity_status
                    else None,
                    "error_trace": _trace_text(result.connectivity_error_trace),
                },
            )
        ]

    attempts = result.scan_result
    findings: list[RawFinding] = []
    findings.extend(_protocol_and_suite_findings(attempts, target))
    findings.extend(_group_findings(attempts, target, policy))
    findings.extend(_certificate_findings(attempts, target))
    findings.extend(_hygiene_findings(attempts, target))
    findings.extend(_undetermined_findings(attempts, target))
    return findings


def _protocol_and_suite_findings(attempts: Any, target: ProbeTarget) -> list[RawFinding]:
    """One finding per version — offered or not — and one per accepted suite."""
    findings: list[RawFinding] = []

    for version, (spelling, canonical) in TLS_VERSIONS.items():
        attempt = getattr(attempts, f"{version.name.lower()}_cipher_suites")
        if not _completed(attempt):
            findings.append(_command_failure(attempt, target, f"{spelling} cipher suites"))
            continue

        accepted = list(attempt.result.accepted_cipher_suites)
        rejected = len(attempt.result.rejected_cipher_suites)
        context = {
            "host": target.host,
            "port": target.port,
            "version": spelling,
            "accepted_suite_count": len(accepted),
            "rejected_suite_count": rejected,
        }

        if not accepted:
            findings.append(
                RawFinding(
                    collector=CollectorName.NETWORK,
                    # Not the TLS family: a refusal must never be matched by a
                    # rule written about a use. See the module docstring.
                    algorithm_name=OBS_VERSION_NOT_OFFERED,
                    source_layer=SourceLayer.LIVE,
                    confidence=Confidence.HIGH,
                    protocol_version=canonical,
                    evidence_location=str(target),
                    evidence_raw={
                        **context,
                        "observation": "protocol_version_not_offered",
                        "offered": False,
                    },
                )
            )
            continue

        findings.append(
            RawFinding(
                collector=CollectorName.NETWORK,
                algorithm_name=spelling,
                source_layer=SourceLayer.LIVE,
                confidence=Confidence.HIGH,
                primitive=Primitive.PROTOCOL,
                protocol_version=canonical,
                evidence_location=str(target),
                evidence_raw={
                    **context,
                    "observation": "protocol_version_accepted",
                    "offered": True,
                },
            )
        )
        findings.extend(_suite_findings(accepted, target, spelling, canonical))

    return findings


def _suite_findings(
    accepted: Sequence[Any], target: ProbeTarget, spelling: str, canonical: str
) -> list[RawFinding]:
    """Each accepted suite, carrying the version it was accepted at (§7.5)."""
    findings: list[RawFinding] = []
    for entry in accepted:
        suite = entry.cipher_suite
        findings.append(
            RawFinding(
                collector=CollectorName.NETWORK,
                # The IANA name. nginx writes the OpenSSL spelling of the same
                # suite; collapsing the two is the normalizer's job (§8), which
                # is why both are recorded.
                algorithm_name=suite.name,
                source_layer=SourceLayer.LIVE,
                confidence=Confidence.HIGH,
                primitive=Primitive.CIPHER,
                key_size=suite.key_size,
                protocol_version=canonical,
                evidence_location=str(target),
                evidence_raw={
                    "host": target.host,
                    "port": target.port,
                    "observation": "cipher_suite_accepted",
                    "version": spelling,
                    "suite": suite.name,
                    "openssl_name": suite.openssl_name,
                    "is_anonymous": suite.is_anonymous,
                    "ephemeral_key": _ephemeral_evidence(entry.ephemeral_key),
                },
            )
        )
    return findings


def _group_findings(
    attempts: Any, target: ProbeTarget, policy: PolicyPack
) -> list[RawFinding]:
    """The groups actually negotiated, one finding each.

    Taken from the ephemeral key of each accepted suite rather than from the
    ``elliptic_curves`` command: that command reports what the server *would*
    accept, while this is what it *did* use. Deduplicated per target, because one
    group offered across twelve suites is one key exchange, not twelve.
    """
    seen: dict[tuple[str, int | None], dict[str, Any]] = {}
    for version, _ in TLS_VERSIONS.items():
        attempt = getattr(attempts, f"{version.name.lower()}_cipher_suites")
        if not _completed(attempt):
            continue
        for entry in attempt.result.accepted_cipher_suites:
            key_info = entry.ephemeral_key
            if key_info is None:
                continue
            name = getattr(key_info, "curve_name", None) or key_info.type_name
            seen.setdefault((name, key_info.size), _ephemeral_evidence(key_info))

    findings: list[RawFinding] = []
    for (name, size), evidence in seen.items():
        resolved, recognised = _named_group(name, policy)
        findings.append(
            RawFinding(
                collector=CollectorName.NETWORK,
                algorithm_name=resolved,
                source_layer=SourceLayer.LIVE,
                # A group whose name the tool had to invent is not a high
                # confidence identification of anything.
                confidence=Confidence.HIGH if recognised else Confidence.LOW,
                primitive=Primitive.KEY_EXCHANGE,
                key_size=size,
                evidence_location=str(target),
                evidence_raw={
                    "host": target.host,
                    "port": target.port,
                    "observation": "negotiated_group",
                    "reported_name": name,
                    "recognised": recognised,
                    **evidence,
                },
            )
        )
    return findings


def _certificate_findings(attempts: Any, target: ProbeTarget) -> list[RawFinding]:
    """The served chain, through the same extractor the disk collector uses."""
    attempt = attempts.certificate_info
    if not _completed(attempt):
        return [_command_failure(attempt, target, "certificate_info")]

    findings: list[RawFinding] = []
    for deployment in attempt.result.certificate_deployments:
        chain = list(deployment.received_certificate_chain)
        if not chain:
            continue
        findings.extend(
            certificate_findings(
                chain[0],
                CertificateSource(
                    location=str(target),
                    collector=CollectorName.NETWORK,
                    source_layer=SourceLayer.LIVE,
                    evidence={
                        "host": target.host,
                        "port": target.port,
                        "served_over": "tls",
                        "sni": attempt.result.hostname_used_for_server_name_indication,
                        "chain_length": len(chain),
                        "chain_has_valid_order": deployment.received_chain_has_valid_order,
                        "verified_chain_has_sha1_signature": (
                            deployment.verified_chain_has_sha1_signature
                        ),
                    },
                    # A certificate served on a socket has no path to be
                    # unremarkable in. §7.3's dev-path exemption is about a file
                    # under tests/, and nothing here is under anything.
                    is_dev_path=False,
                ),
            )
        )
    return findings


def _hygiene_findings(attempts: Any, target: ProbeTarget) -> list[RawFinding]:
    """Renegotiation and compression. Only the notable case is reported.

    A finding for every correctly configured host is noise that trains people to
    skim, which is the config collector's rule applied to the wire.
    """
    findings: list[RawFinding] = []

    renegotiation = attempts.session_renegotiation
    if _completed(renegotiation):
        result = renegotiation.result
        if not result.supports_secure_renegotiation:
            findings.append(
                _marker(
                    OBS_INSECURE_RENEGOTIATION,
                    target,
                    evidence={"observation": "secure_renegotiation_unsupported"},
                )
            )
        if result.is_vulnerable_to_client_renegotiation_dos:
            findings.append(
                _marker(
                    OBS_RENEGOTIATION_DOS,
                    target,
                    evidence={
                        "observation": "client_renegotiation_dos",
                        "successful_renegotiations": (
                            result.client_renegotiations_success_count
                        ),
                    },
                )
            )

    compression = attempts.tls_compression
    if _completed(compression) and compression.result.supports_compression:
        findings.append(
            _marker(
                OBS_COMPRESSION_ENABLED,
                target,
                evidence={"observation": "tls_compression_enabled"},
            )
        )
    return findings


def _undetermined_findings(attempts: Any, target: ProbeTarget) -> list[RawFinding]:
    """Two things §7.5 asks for that sslyze 6.3.1 cannot answer.

    Both are emitted every time rather than left out. A readiness percentage
    computed over findings that silently omit "not measured" is a number with a
    hole in it, and the hole is invisible unless something says so.
    """
    curves = attempts.elliptic_curves
    curve_evidence: dict[str, Any] = {"elliptic_curves_command": "not completed"}
    if _completed(curves):
        curve_evidence = {
            "supports_ecdh_key_exchange": curves.result.supports_ecdh_key_exchange,
            "supported_curves": [c.name for c in (curves.result.supported_curves or [])],
            "rejected_curves": [c.name for c in (curves.result.rejected_curves or [])],
        }

    return [
        _marker(
            OBS_SUITE_PREFERENCE_UNDETERMINED,
            target,
            confidence=Confidence.LOW,
            evidence={
                "observation": "suite_preference_undetermined",
                "reason": (
                    "sslyze 6.x reports accepted and rejected suites per version but "
                    "not whether the server enforces its own ordering"
                ),
            },
        ),
        _marker(
            OBS_PQC_GROUPS_UNDETERMINED,
            target,
            confidence=Confidence.LOW,
            evidence={
                "observation": "pqc_group_support_undetermined",
                "reason": (
                    "the installed sslyze enumerates groups from nassl's "
                    "OpenSslEcNidEnum, which carries classical curves only — a "
                    "hybrid group such as X25519MLKEM768 is never offered, so its "
                    "absence from the results is not evidence of absence"
                ),
                **curve_evidence,
            },
        ),
    ]


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #


def _completed(attempt: ScanCommandAttempt) -> bool:
    if attempt.status is not ScanCommandAttemptStatusEnum.COMPLETED:
        return False
    return attempt.result is not None


def _command_failure(
    attempt: ScanCommandAttempt, target: ProbeTarget, command: str
) -> RawFinding:
    """A command that errored. Recorded, because it is not the same as a refusal."""
    return _marker(
        OBS_COMMAND_FAILED,
        target,
        confidence=Confidence.LOW,
        evidence={
            "observation": "scan_command_failed",
            "command": command,
            "status": attempt.status.name,
            "error_reason": (
            attempt.error_reason.name if attempt.error_reason else None
        ),
            "error_trace": _trace_text(attempt.error_trace),
        },
    )


def _marker(
    name: str,
    target: ProbeTarget,
    *,
    confidence: Confidence = Confidence.HIGH,
    evidence: Mapping[str, Any] | None = None,
) -> RawFinding:
    """An observation that is not an algorithm use — a refusal, a gap, a hygiene note."""
    return RawFinding(
        collector=CollectorName.NETWORK,
        algorithm_name=name,
        source_layer=SourceLayer.LIVE,
        confidence=confidence,
        evidence_location=str(target),
        evidence_raw={"host": target.host, "port": target.port, **dict(evidence or {})},
    )


def _ephemeral_evidence(key_info: Any) -> dict[str, Any]:
    """The negotiated key exchange, without its public bytes."""
    if key_info is None:
        return {}
    return {
        "type": key_info.type_name,
        "size": key_info.size,
        "curve": getattr(key_info, "curve_name", None),
    }


def _named_group(name: str, policy: PolicyPack) -> tuple[str, bool]:
    """Resolve a group name, mapping a raw code point through ``named_groups.yaml``.

    Returns the name to report and whether it was recognised. The unrecognised
    case is why the table exists: §7.5 anticipated sslyze reporting a hybrid PQC
    group as a bare code point, and while the installed version does not get that
    far, a group this build cannot name must not be reported as though it could.
    """
    text = (name or "").strip()
    if not text:
        return "unknown-group", False

    unnamed = _UNNAMED_CURVE.match(text)
    if unnamed:
        # An OpenSSL NID, not a TLS code point — different numbering, so the
        # table is not consulted. Reported verbatim and flagged.
        return text, False

    match = _CODE_POINT.match(text)
    if match:
        hexadecimal, decimal = match.groups()
        code = int(hexadecimal, 16) if hexadecimal else int(decimal)
        mapped = policy.named_groups.get(code, policy.named_groups.get(text))
        return (str(mapped), True) if mapped else (text, False)

    return text, True


def _trace_text(trace: Any) -> str | None:
    if trace is None:
        return None
    return str(trace)[:2000]
