"""Alignment check — SPEC.md §9, build step 8.

The drift finding, and the reason this project exists. Every other stage reports
what it found; this one reports that two things which should agree do not, and
exactly where.

It runs after the findings are stored and **before** the policy engine, so
everything downstream sees findings that already carry their note.

Four rules from §9, and each one is a decision that could have gone the other
way:

**Live is fact; config is a claim.** The reported result is what the handshake
did. A configuration file is a statement of intent, and the entire value of this
check is that intent and behaviour can differ without anyone noticing — the
demo's ``openssl.cnf`` declares a TLS 1.2 floor and is never activated, so it
reads as hardened and enforces nothing.

**Flag per usage site, not per config declaration.** One declaration covering
five services that diverges at two of them produces two notes, not one about the
file and not five. The usage site is the probed service: a note is written per
(declaration, service) pair, and the three services that agree are not mentioned.

**Do not classify.** Nothing here decides whether a divergence is a
misconfiguration or a deliberate exception for one host. There is no severity, no
"expected vs actual" framing that implies fault, and no code path that guesses.
The note says the observed value does not align with the declaration, names both,
and stops. That judgement belongs to whoever owns the server.

**Do not guess the join.** The correlation key is the probe target the user
typed, joined against config findings from the same scan. A live finding whose
service no declaration covers produces nothing at all.

THE SCOPE GUARD, AND WHY THE TWO KINDS OF "SERVER-WIDE" DIFFER

§9 says a server-wide floor tested against one virtual host is not drift. That is
about precedence, not about breadth, and the two config kinds here fall on
opposite sides of it:

* An nginx ``ssl_protocols`` outside any ``server`` block is a **default**. A
  server block may override it, so a vhost that negotiates differently may simply
  be a vhost that overrode it. Not comparable to a single probed service, and
  skipped.
* An ``openssl.cnf`` ``MinProtocol`` is a **floor the library enforces**. Nothing
  layered above it can negotiate below it, so a handshake underneath it is a
  contradiction no vhost setting explains. Comparable, and it is the demo's
  headline note.

What is deliberately not compared is cipher suites. An OpenSSL cipher string
mixes concrete suite names with selectors — the demo's weak host declares
``HIGH:MEDIUM:@SECLEVEL=0`` — and the config collector does not expand selectors
into the suites they stand for, on purpose. Comparing a declared suite *list*
against an accepted suite set would therefore report every suite admitted through
``HIGH`` as undeclared drift. A check that cries wolf on a correct configuration
is worse than one that says nothing, so protocol versions are the only dimension
compared until selector expansion exists to make the other one true.
"""

from __future__ import annotations

import logging
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any
from uuid import UUID

import sqlalchemy as sa
from sqlalchemy.orm import Session

from app.models.enums import ScanMode, SourceLayer
from app.models.finding import AlignmentNote, Finding
from app.models.scan import Scan

logger = logging.getLogger(__name__)

__all__ = [
    "AlignmentResult",
    "Declaration",
    "PROTOCOL_ORDER",
    "STATUS_COMPARED",
    "STATUS_SKIPPED",
    "UNCLASSIFIED_SUFFIX",
    "ServiceScope",
    "align",
    "describe_alignment",
]

STATUS_COMPARED = "compared"
STATUS_SKIPPED = "skipped"

#: Protocol ordering, written out rather than computed. Numeric comparison puts
#: "3.0" above "1.2" and would rank SSL 3.0 as the most modern protocol in the
#: file — the exact trap the alias table keeps SSL in its own family to avoid.
PROTOCOL_ORDER: Mapping[str, int] = {
    "2.0": 0,
    "3.0": 1,
    "1.0": 2,
    "1.1": 3,
    "1.2": 4,
    "1.3": 5,
}

#: For the note text. A user reading "1.0" has to know which protocol that is.
PROTOCOL_LABEL: Mapping[str, str] = {
    "2.0": "SSL 2.0",
    "3.0": "SSL 3.0",
    "1.0": "TLS 1.0",
    "1.1": "TLS 1.1",
    "1.2": "TLS 1.2",
    "1.3": "TLS 1.3",
}

#: Config observations that state something about protocol versions.
OBS_FLOOR = "protocol_floor"
OBS_CEILING = "protocol_ceiling"
OBS_DECLARED = "protocol_version_declared"

#: Live observations that answer them.
OBS_ACCEPTED = "protocol_version_accepted"
OBS_NOT_OFFERED = "protocol_version_not_offered"

#: The fixed closing sentence of every note. §9 rule 4 in one line, and a
#: constant rather than an inline string so it is impossible to write a note
#: without it — and so a test can strip it and check that nothing in the
#: *reporting* half of the wording implies a judgement either.
UNCLASSIFIED_SUFFIX = (
    "Whether the difference is a misconfiguration or an intentional exception for "
    "this service is not determined here."
)

SCOPE_SERVICE = "service"
SCOPE_LIBRARY = "library"
SCOPE_SERVER_WIDE = "server_wide"


def _label(version: str | None) -> str:
    return PROTOCOL_LABEL.get(version or "", version or "an unknown version")


def _rank(version: str | None) -> int | None:
    return PROTOCOL_ORDER.get(version or "")


# --------------------------------------------------------------------------- #
# Scope
# --------------------------------------------------------------------------- #


@dataclass(frozen=True, slots=True)
class ServiceScope:
    """What a declaration governs, taken from the config's own words.

    ``ports`` and ``server_names`` come from the enclosing nginx ``server``
    block's ``listen`` and ``server_name`` lines — the config saying which
    service it configures. Nothing here is inferred from a file's path: where a
    config file sits on disk is a packaging accident (§7.4), and §9 forbids
    guessing the join.
    """

    kind: str
    ports: frozenset[int] = frozenset()
    server_names: frozenset[str] = frozenset()

    @property
    def comparable(self) -> bool:
        """A server-wide nginx default is not comparable to one probed vhost (§9)."""
        return self.kind in (SCOPE_SERVICE, SCOPE_LIBRARY)

    def covers(self, host: str, port: int) -> bool:
        if self.kind == SCOPE_LIBRARY:
            # A library floor applies to every service the library serves, and
            # nothing above it can negotiate below it.
            return True
        if self.kind != SCOPE_SERVICE:
            return False
        if port in self.ports:
            return True
        # A hostname match is accepted only when the config named it; the demo
        # probes `localhost` against a block answering to `legacy.ecdat.demo`,
        # so in practice the port is what joins.
        named = {name.strip().lower() for name in self.server_names}
        return host.strip().lower() in named

    def describe(self) -> str:
        if self.kind == SCOPE_LIBRARY:
            return "a library-wide declaration"
        if self.kind == SCOPE_SERVICE:
            ports = ", ".join(str(port) for port in sorted(self.ports)) or "no port"
            return f"a server block listening on {ports}"
        return "a server-wide default"


def _scope_of(finding: Finding) -> ServiceScope:
    evidence = finding.evidence_raw or {}
    observation = evidence.get("observation")

    if observation in (OBS_FLOOR, OBS_CEILING):
        # openssl.cnf. A floor and a ceiling the library itself enforces.
        return ServiceScope(kind=SCOPE_LIBRARY)

    server = evidence.get("server")
    if not isinstance(server, Mapping):
        # An nginx directive outside any server block: a default a vhost may
        # override, so comparing it to one vhost proves nothing (§9).
        return ServiceScope(kind=SCOPE_SERVER_WIDE)

    ports = {int(port) for port in server.get("ports") or [] if str(port).isdigit()}
    names = {str(name) for name in server.get("server_names") or []}
    return ServiceScope(
        kind=SCOPE_SERVICE,
        ports=frozenset(ports),
        server_names=frozenset(names),
    )


# --------------------------------------------------------------------------- #
# The two sides
# --------------------------------------------------------------------------- #


@dataclass(frozen=True, slots=True)
class Declaration:
    """One config statement about protocol versions, at one site."""

    kind: str  # floor | ceiling | enumeration
    versions: tuple[str, ...]
    scope: ServiceScope
    site: str
    #: the config finding a note points at
    anchor: Finding

    def describe(self) -> str:
        listed = ", ".join(_label(v) for v in self.versions)
        if self.kind == "floor":
            return f"a minimum protocol version of {listed}"
        if self.kind == "ceiling":
            return f"a maximum protocol version of {listed}"
        return f"exactly these protocol versions: {listed}"


@dataclass(frozen=True, slots=True)
class ObservedService:
    """One probed service, and what it did with each protocol version."""

    host: str
    port: int
    accepted: Mapping[str, Finding] = field(default_factory=dict)
    refused: Mapping[str, Finding] = field(default_factory=dict)

    def __str__(self) -> str:
        return f"{self.host}:{self.port}"


def _declarations(config_findings: Iterable[Finding]) -> list[Declaration]:
    """Group config findings into the statements they make.

    ``ssl_protocols TLSv1 TLSv1.1 TLSv1.2`` is three findings from one directive
    — one per version, so §9 rule 3 can flag the versions that diverge — but it
    is a single *declaration* of a set, and comparing it version by version would
    miss "the server offers something this line does not list".
    """
    declarations: list[Declaration] = []
    enumerations: dict[str, list[Finding]] = {}

    for finding in config_findings:
        observation = (finding.evidence_raw or {}).get("observation")
        version = finding.protocol_version
        if version is None or version not in PROTOCOL_ORDER:
            continue

        if observation == OBS_FLOOR:
            declarations.append(
                Declaration(
                    kind="floor",
                    versions=(version,),
                    scope=_scope_of(finding),
                    site=finding.evidence_location or "(unknown location)",
                    anchor=finding,
                )
            )
        elif observation == OBS_CEILING:
            declarations.append(
                Declaration(
                    kind="ceiling",
                    versions=(version,),
                    scope=_scope_of(finding),
                    site=finding.evidence_location or "(unknown location)",
                    anchor=finding,
                )
            )
        elif observation == OBS_DECLARED:
            # Keyed by location: every version on one `ssl_protocols` line shares
            # a file:line, which is what makes them one declaration.
            enumerations.setdefault(finding.evidence_location or "", []).append(finding)

    for site, findings in enumerations.items():
        ordered = sorted(findings, key=lambda f: _rank(f.protocol_version) or 0)
        declarations.append(
            Declaration(
                kind="enumeration",
                versions=tuple(f.protocol_version for f in ordered),
                scope=_scope_of(ordered[0]),
                site=site or "(unknown location)",
                anchor=ordered[0],
            )
        )
    return declarations


def _observed_services(live_findings: Iterable[Finding]) -> list[ObservedService]:
    """Fold live protocol findings into one record per probed service."""
    accepted: dict[tuple[str, int], dict[str, Finding]] = {}
    refused: dict[tuple[str, int], dict[str, Finding]] = {}

    for finding in live_findings:
        evidence = finding.evidence_raw or {}
        observation = evidence.get("observation")
        version = finding.protocol_version
        if version not in PROTOCOL_ORDER:
            continue
        host, port = evidence.get("host"), evidence.get("port")
        if host is None or port is None:
            continue
        key = (str(host), int(port))
        if observation == OBS_ACCEPTED:
            accepted.setdefault(key, {})[version] = finding
        elif observation == OBS_NOT_OFFERED:
            refused.setdefault(key, {})[version] = finding

    services = []
    for key in sorted(set(accepted) | set(refused)):
        services.append(
            ObservedService(
                host=key[0],
                port=key[1],
                accepted=accepted.get(key, {}),
                refused=refused.get(key, {}),
            )
        )
    return services


# --------------------------------------------------------------------------- #
# Comparison
# --------------------------------------------------------------------------- #


@dataclass(frozen=True, slots=True)
class _Divergence:
    finding: Finding
    described: str
    #: lower sorts first when choosing which live finding the note anchors to
    weight: int


def _divergences(declaration: Declaration, service: ObservedService) -> list[_Divergence]:
    """Every way this service fails to match this declaration. No judgement attached."""
    found: list[_Divergence] = []

    if declaration.kind == "floor":
        floor = _rank(declaration.versions[0])
        for version, finding in service.accepted.items():
            rank = _rank(version)
            if rank is not None and floor is not None and rank < floor:
                found.append(
                    _Divergence(finding, f"{_label(version)} was accepted", rank)
                )

    elif declaration.kind == "ceiling":
        ceiling = _rank(declaration.versions[0])
        for version, finding in service.accepted.items():
            rank = _rank(version)
            if rank is not None and ceiling is not None and rank > ceiling:
                found.append(
                    _Divergence(finding, f"{_label(version)} was accepted", -rank)
                )

    else:
        declared = set(declaration.versions)
        for version, finding in service.accepted.items():
            if version not in declared:
                found.append(
                    _Divergence(
                        finding,
                        f"{_label(version)} was accepted but is not in the declared list",
                        _rank(version) or 0,
                    )
                )
        for version, finding in service.refused.items():
            if version in declared:
                found.append(
                    _Divergence(
                        finding,
                        f"{_label(version)} is declared but was offered and refused",
                        100 + (_rank(version) or 0),
                    )
                )

    return sorted(found, key=lambda d: d.weight)


def _note_text(
    declaration: Declaration,
    service: ObservedService,
    found: Sequence[_Divergence],
) -> str:
    """The wording, and it is wording the whole check stands on.

    States what was observed, states what the configuration declares, and says
    they do not align. It does not say which is wrong, does not call the
    configuration violated or the server misconfigured, and offers no severity.
    §9 rule 4: the tool reports that they differ and exactly where.
    """
    observations = "; ".join(item.described for item in found)
    return (
        f"Observed on {service}: {observations}. "
        f"The configuration at {declaration.site} declares {declaration.describe()} "
        f"for this asset. The observed value does not align with that declaration. "
        f"{UNCLASSIFIED_SUFFIX}"
    )


# --------------------------------------------------------------------------- #
# Result
# --------------------------------------------------------------------------- #


@dataclass(frozen=True, slots=True)
class AlignmentResult:
    """What the check did, in a shape the UI can render — including doing nothing."""

    status: str
    reason: str | None = None
    notes: tuple[AlignmentNote, ...] = ()
    compared_services: tuple[str, ...] = ()
    #: declarations skipped because their scope is not comparable (§9 scope guard)
    scope_skipped: tuple[str, ...] = ()

    @property
    def skipped(self) -> bool:
        return self.status == STATUS_SKIPPED

    def as_dict(self) -> dict[str, Any]:
        """§9: the UI must display the skipped state, not an empty panel."""
        if self.skipped:
            return {"status": self.status, "reason": self.reason}
        return {
            "status": self.status,
            "note_count": len(self.notes),
            "compared_services": list(self.compared_services),
            "scope_skipped": list(self.scope_skipped),
        }


# --------------------------------------------------------------------------- #
# Entry point
# --------------------------------------------------------------------------- #


def align(session: Session, scan: Scan) -> AlignmentResult:
    """Compare this scan's live findings against its config findings.

    Called by ``app/runner.py`` after the normalizer and before the policy
    engine (§9). Re-running replaces this scan's notes rather than appending to
    them.
    """
    findings = list(
        session.scalars(
            sa.select(Finding).where(Finding.scan_id == scan.id).order_by(Finding.id)
        )
    )
    live = [f for f in findings if f.source_layer is SourceLayer.LIVE]
    config = [f for f in findings if f.source_layer is SourceLayer.CONFIG]

    # `source` and `artifact` findings are not compared here, ever. §9's second
    # scope guard: an MD5 call in an unimported module is a finding, not a
    # config conflict, and alignment is live-against-config only.
    skipped = _nothing_to_compare(scan, live, config)
    if skipped is not None:
        logger.info("scan %s: alignment skipped — %s", scan.id, skipped)
        return AlignmentResult(status=STATUS_SKIPPED, reason=skipped)

    session.execute(
        sa.delete(AlignmentNote).where(AlignmentNote.scan_id == scan.id),
        execution_options={"synchronize_session": False},
    )

    declarations = _declarations(config)
    services = _observed_services(live)

    if not services:
        reason = "the probe produced no protocol observations to compare"
        logger.info("scan %s: alignment skipped — %s", scan.id, reason)
        return AlignmentResult(status=STATUS_SKIPPED, reason=reason)

    notes: list[AlignmentNote] = []
    scope_skipped: list[str] = []

    for declaration in declarations:
        if not declaration.scope.comparable:
            # Recorded rather than dropped: "we did not compare this, and why"
            # is worth as much on the drift screen as a note is.
            scope_skipped.append(f"{declaration.site} ({declaration.scope.describe()})")
            continue

        for service in services:
            if not declaration.scope.covers(service.host, service.port):
                continue
            found = _divergences(declaration, service)
            if not found:
                # §9 rule 3: the sites that agree are not flagged at all.
                continue
            notes.append(
                AlignmentNote(
                    scan_id=scan.id,
                    # Live is what the report carries; the config finding is the
                    # claim it failed to match.
                    live_finding_id=found[0].finding.id,
                    config_finding_id=declaration.anchor.id,
                    asset_key=f"{service} via {declaration.scope.describe()}",
                    note=_note_text(declaration, service, found),
                )
            )

    session.add_all(notes)
    session.flush()

    compared = tuple(str(service) for service in services)
    logger.info(
        "scan %s: alignment compared %d declaration(s) against %d service(s): %d note(s)"
        "%s",
        scan.id,
        len(declarations) - len(scope_skipped),
        len(services),
        len(notes),
        f"; {len(scope_skipped)} declaration(s) out of scope" if scope_skipped else "",
    )
    return AlignmentResult(
        status=STATUS_COMPARED,
        notes=tuple(notes),
        compared_services=compared,
        scope_skipped=tuple(scope_skipped),
    )


def describe_alignment(session: Session, scan: Scan) -> AlignmentResult:
    """What :func:`align` decided, re-read without re-deciding it.

    The dashboard (§13 screen 5) needs the ``skipped`` state and its reason as
    much as it needs the notes, and neither is stored — only the notes are. So
    the skip logic is re-evaluated over the stored findings, which is
    deterministic, and the notes are read back rather than regenerated. This
    function writes nothing: a GET must not rewrite the drift table.
    """
    findings = list(
        session.scalars(
            sa.select(Finding).where(Finding.scan_id == scan.id).order_by(Finding.id)
        )
    )
    live = [f for f in findings if f.source_layer is SourceLayer.LIVE]
    config = [f for f in findings if f.source_layer is SourceLayer.CONFIG]

    skipped = _nothing_to_compare(scan, live, config)
    if skipped is not None:
        return AlignmentResult(status=STATUS_SKIPPED, reason=skipped)
    services = _observed_services(live)
    if not services:
        return AlignmentResult(
            status=STATUS_SKIPPED,
            reason="the probe produced no protocol observations to compare",
        )

    notes = tuple(
        session.scalars(
            sa.select(AlignmentNote)
            .where(AlignmentNote.scan_id == scan.id)
            .order_by(AlignmentNote.asset_key, AlignmentNote.id)
        )
    )
    scope_skipped = tuple(
        f"{declaration.site} ({declaration.scope.describe()})"
        for declaration in _declarations(config)
        if not declaration.scope.comparable
    )
    return AlignmentResult(
        status=STATUS_COMPARED,
        notes=notes,
        compared_services=tuple(str(service) for service in services),
        scope_skipped=scope_skipped,
    )


def _nothing_to_compare(
    scan: Scan, live: Sequence[Finding], config: Sequence[Finding]
) -> str | None:
    """The reason there is nothing to do, or None. Never an empty panel (§9)."""
    if scan.mode is ScanMode.PROBE_ONLY:
        return (
            "no config findings to compare: a probe_only scan reads no files, so "
            "there is no declaration to hold the handshake against"
        )
    if scan.mode is ScanMode.FILES:
        return (
            "no live findings to compare: a files scan probes nothing, so there is "
            "no handshake to hold the declarations against"
        )
    if not config:
        return "no config findings to compare: nothing approved for this scan declares TLS"
    if not live:
        return "no live findings to compare: the probe returned no observations"
    return None
