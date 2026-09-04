"""Advisor — SPEC.md §11, build step 10.

What to migrate each finding *to*, and — the more valuable half — what stands in
the way when it cannot be deployed yet. Four steps, in the order §11 gives them,
and each one is a place where a plausible shortcut produces a wrong answer.

**1. Match on primitive plus family, never on the algorithm name.** RSA maps to
ML-KEM when it is doing key exchange and to ML-DSA when it is signing, and only
the primitive tells those apart. The lookup itself lives in ``core/policy.py``
(``pqc_targets_for``), because §12's wave table needed it two steps before this
module existed; everything here is built on top of it.

**2. Select the parameter set from the scan's ``data_lifetime_years``.** Data
that has to stay secret for a long time gets the largest parameter set —
ML-KEM-1024 and ML-DSA-87 — and the threshold is read from the pack's
``parameter_sets`` block rather than written here. Where that line sits is
national guidance, and guidance differs.

**3. Check feasibility, and when it fails emit the blocker chain rather than the
target.** Every ``requires`` clause is tested against what the collectors
observed: the protocol ceiling from the probe or the config, the library version
from the binary collector. "Adopt ML-KEM" is a wish; "upgrade OpenSSL, then
enable TLS 1.3, then adopt ML-KEM" is a work plan, and the chain is ordered so the
item with the procurement lead time comes first.

**4. Apply the hybrid policy.** ``prefer_hybrid`` is read from the pack and never
assumed. Where it is on and the primitive is key exchange, the deployable target
is the hybrid group.

WHAT COUNTS AS OBSERVED, AND FOR WHICH ASSET

A prerequisite is tested against the finding's own asset first — the probed
service, or the file the finding was read from. Two fallbacks exist, and they
point in opposite directions on purpose:

* A **library** version observed elsewhere in the same scan is used when the
  asset itself shows none, and the entry names where it was seen. The scan's file
  tree is one deployment, and an OpenSSL 1.1.1 linked anywhere in it is a fact
  about that deployment. When several are seen, the *lowest* is the one reported,
  so borrowing evidence can block a target but can never confirm one that the
  asset's own evidence would not.
* A **protocol** ceiling is a property of one service, and what port 8444
  negotiates says nothing about port 8443 — so it is never taken from an
  unrelated service. It is borrowed along one route only: the correlation §9
  already recorded, an ``alignment_notes`` row linking this config finding's file
  to a probed service. The borrowed entry then names the *service* in
  ``observed_at`` and says so in its note, because a borrowed observation that
  reads like a direct one is worse than no observation. Where a file is linked to
  several services, the lowest ceiling is the one reported, so a borrowed ceiling
  can block a target but never confirms one on an ambiguity. A file no note links
  to anything keeps ``observed: null``.

A requirement nothing observed at all is **not met**. It is listed in the chain
with ``observed: null`` and the work item is to confirm it. Rounding an
unobserved prerequisite to "presumably fine" would be the optimistic direction
demo/README.md warns against, and a target recommended on that basis is the
wrong recommendation §11 says is worse than none.

WHAT GETS A ROW

Only findings the policy engine judged ``broken_now`` or ``quantum_vulnerable``.
A ``quantum_safe`` finding needs no migration; a ``hygiene`` one is not an
algorithm; and an ``unknown`` verdict means the pack could not say whether the
algorithm is a problem, so recommending a replacement for it would be advising a
migration nothing has established is needed. Those findings sit in the ``verify``
wave (§12) where the action is confirmation.

Among findings that do get a row, ``unknown`` means no ``pqc_targets`` rule
matched. There is no generic fallback — not "use something post-quantum", not
the nearest-looking rule. The row says the pack has no answer, and closing that
is a cited entry in the pack, not a guess in this module.

TIE-BREAKING

In §11's order: feasible now beats theoretically better; a hybrid, interoperable
route beats a unilateral switch; the cheaper action class wins; an explicitly
standardised target beats a draft. If two candidates are still tied, both are
emitted with the tradeoff written into ``side_effects``. Manufacturing a
preference the pack does not state would be this module deciding policy.
"""

from __future__ import annotations

import logging
import re
from collections import Counter
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field, replace
from typing import Any
from uuid import UUID

import sqlalchemy as sa
from sqlalchemy.orm import Session

from app.core.alignment import PROTOCOL_LABEL, PROTOCOL_ORDER
from app.core.policy import ACTION_CLASS_ORDER, pqc_targets_for
from app.core.policy_loader import (
    PolicyPack,
    PolicyValidationError,
    PqcParameterSet,
    PqcTarget,
    get_policy,
)
from app.models.analysis import Recommendation, VerdictRow
from app.models.enums import (
    ActionClass,
    Primitive,
    RecommendationStatus,
    SourceLayer,
    Verdict,
)
from app.models.finding import AlignmentNote, Finding
from app.models.scan import Scan

logger = logging.getLogger(__name__)

__all__ = [
    "Advice",
    "BlockedChain",
    "LIBRARY_OBSERVATIONS",
    "MATCHABLE_OBSERVATIONS",
    "MATCH_KEYS",
    "MIGRATION_VERDICTS",
    "NO_TARGET_CITATION",
    "OBS_LIBRARY_VERSION",
    "OBS_LINKED_LIBRARY",
    "PROTOCOL_OBSERVATIONS",
    "Prerequisite",
    "REQUIREMENT_KEYS",
    "ScanObservations",
    "advise_finding",
    "advise_scan",
    "asset_of",
    "blocked_chains",
    "recommendation_counts",
    "requirement_of",
    "select_parameter_set",
    "validate_targets",
]

#: The verdicts that mean "this has to be replaced". Nothing else gets advice.
MIGRATION_VERDICTS = frozenset({Verdict.BROKEN_NOW, Verdict.QUANTUM_VULNERABLE})

#: The ``match`` keys a ``pqc_targets`` entry may use. Anything else is rejected
#: at startup: an unrecognised key would not narrow the rule, it would be ignored.
#: ``source_layer`` is how an entry says which context it was written for: a
#: ``requires`` clause is only meaningful where the collectors can observe it, and
#: a TLS ceiling means nothing on an SSH directive or a source-level call site.
MATCH_KEYS = frozenset(
    {"primitive", "family", "asset_lifetime_gt", "source_layer", "observation"}
)

#: Observation strings a ``pqc_targets`` entry may narrow itself with. The
#: collectors write these into ``evidence_raw["observation"]``. ``source_layer``
#: says which layer a rule was written for; this says which *kind* of declaration
#: within it, which is what separates an ``sshd_config`` ``KexAlgorithms`` line
#: from a TLS configuration's key exchange — both are config-layer key exchanges
#: of the same family, and only one of them can be held to a TLS clause.
#:
#: Written out and checked at startup because an entry naming an observation no
#: collector emits would not narrow itself, it would *silence* itself: the rule
#: would match nothing and the findings it was written for would come back
#: ``unknown``, with nothing to show that the pack has an answer for them.
#: Widening this set is a one-line edit beside the collector that emits the value.
MATCHABLE_OBSERVATIONS = frozenset(
    {
        "ssh_kex_declared",
        "ssh_cipher_declared",
        "ssh_mac_declared",
        "ssh_host_key_algorithm_declared",
    }
)

#: The ``requires`` clauses this module can test. A clause it cannot test is a
#: prerequisite it would skip, and a skipped prerequisite is a recommendation
#: rounded in the optimistic direction — so the pack is refused instead.
REQUIREMENT_KEYS = frozenset({"library", "protocol_min"})

#: The order prerequisites are listed in: the long-lead item first (§11). A
#: library upgrade is procurement; a protocol version is a config line.
_REQUIREMENT_ORDER: tuple[str, ...] = ("library", "protocol_min")

#: Evidence shapes the binary collector (§7.2, build step 11) writes for a
#: library it saw. Defined here because this is the consumer: ``evidence_raw``
#: carries ``observation`` as one of these, ``library`` as the lower-case name,
#: and ``version`` as observed — ``1.1.1f`` from an ``OPENSSL_VERSION_TEXT``
#: string, or ``1.1`` / ``3`` when only a soname was available.
OBS_LINKED_LIBRARY = "linked_library"
OBS_LIBRARY_VERSION = "library_version_string"
LIBRARY_OBSERVATIONS = frozenset({OBS_LINKED_LIBRARY, OBS_LIBRARY_VERSION})

#: Findings that state a protocol ceiling for their asset: a version the probe
#: saw accepted, a version a config enumerates, or a declared maximum. A floor
#: alone says nothing about the ceiling and is not in this set.
PROTOCOL_OBSERVATIONS = frozenset(
    {"protocol_version_accepted", "protocol_version_declared", "protocol_ceiling"}
)

#: What an ``unknown`` row cites. §11's rule is that no rule matching produces
#: no target, and the row has to say that rather than leave the field empty.
NO_TARGET_CITATION = (
    "No pqc_targets.yaml entry matches this finding's primitive and family. "
    "SPEC.md §11: an unmatched finding gets no target — never a generic suggestion, "
    "because a wrong recommendation is worse than an absent one."
)

_LIBRARY_CLAUSE = re.compile(r"^\s*([A-Za-z][\w.+-]*)\s*(>=|>|==)\s*(\d+(?:\.\d+)*)\s*$")
_VERSION_PREFIX = re.compile(r"^\s*v?(\d+(?:\.\d+)*)")
_PROTOCOL_CLAUSE = re.compile(r"^\s*(?:TLS|tls)?\s*v?\s*(\d)(?:\.(\d))?\s*$")


# --------------------------------------------------------------------------- #
# Requirement clauses
# --------------------------------------------------------------------------- #


def _version_tuple(text: str | None) -> tuple[int, ...] | None:
    """``"1.1.1f"`` → ``(1, 1, 1)``; ``"3"`` → ``(3,)``. Letters after the digits are dropped."""
    if not text:
        return None
    match = _VERSION_PREFIX.match(str(text))
    if not match:
        return None
    return tuple(int(part) for part in match.group(1).split("."))


def _parse_library_clause(clause: str) -> tuple[str, str, tuple[int, ...]]:
    match = _LIBRARY_CLAUSE.match(clause)
    if not match:
        raise PolicyValidationError(
            f"pqc_targets.yaml: 'library' requirement {clause!r} is not of the form "
            "'<name><op><version>', e.g. 'openssl>=3.5'"
        )
    name, operator, version = match.groups()
    return name.lower(), operator, tuple(int(part) for part in version.split("."))


def _parse_protocol_clause(clause: str) -> str:
    """``"TLS 1.3"``, ``"TLSv1.3"`` or ``"1.3"`` → the canonical ``"1.3"`` (§8)."""
    match = _PROTOCOL_CLAUSE.match(str(clause))
    if not match:
        raise PolicyValidationError(
            f"pqc_targets.yaml: 'protocol_min' requirement {clause!r} is not a TLS "
            "version such as \"TLS 1.3\""
        )
    major, minor = match.groups()
    version = f"{major}.{minor or 0}"
    if version not in PROTOCOL_ORDER:
        raise PolicyValidationError(
            f"pqc_targets.yaml: 'protocol_min' requirement {clause!r} names a version "
            "the advisor cannot compare"
        )
    return version


def _satisfies(observed: tuple[int, ...], operator: str, wanted: tuple[int, ...]) -> bool | None:
    """Does the observed version meet the clause? ``None`` when it cannot be told.

    The undecidable case is a soname: ``libcrypto.so.3`` says OpenSSL 3 and
    nothing more, and ``3`` neither meets nor fails ``>=3.5``. That is reported
    as its own thing rather than rounded either way.
    """
    depth = min(len(observed), len(wanted))
    head, want = observed[:depth], wanted[:depth]
    if head != want:
        if operator == "==":
            return False
        return head > want
    if len(observed) < len(wanted):
        return None
    if operator == ">=" or operator == "==":
        return True
    return observed[depth:] != () and any(observed[depth:])


# --------------------------------------------------------------------------- #
# Observations
# --------------------------------------------------------------------------- #


def asset_of(finding: Finding) -> str:
    """The unit a prerequisite is tested against.

    A probed service is ``host:port``; a file is its path with the line number
    removed, so every finding read from one binary or one config shares an asset.
    """
    evidence = finding.evidence_raw or {}
    host, port = evidence.get("host"), evidence.get("port")
    if host is not None and port is not None:
        return f"{host}:{port}"
    location = finding.evidence_location or ""
    if finding.source_layer is SourceLayer.LIVE:
        return location
    return re.sub(r":\d+$", "", location)


@dataclass(frozen=True, slots=True)
class LibraryObservation:
    library: str
    version: str
    parsed: tuple[int, ...]
    location: str
    asset: str
    observation: str

    def describe(self) -> str:
        return f"{self.library} {self.version}"


@dataclass(frozen=True, slots=True)
class ProtocolObservation:
    version: str
    location: str
    observation: str
    #: set when this ceiling was observed on a *correlated* service rather than
    #: on the asset asking for it — the probed ``host:port`` §9 linked it to
    borrowed_from: str | None = None
    #: the ``alignment_notes.asset_key`` that recorded the correlation
    asset_key: str | None = None


class ScanObservations:
    """What the collectors saw, indexed by asset, for the feasibility check.

    Built once per scan from every finding in it — including the ones that need
    no migration themselves. A ``protocol_version_accepted`` row is nobody's
    migration item, but it is the evidence that decides someone else's.

    The scan's alignment notes come in alongside the findings. §9 has already
    worked out which config file speaks for which probed service, and that
    correlation is the only route by which a protocol ceiling crosses from one
    asset to another. Deriving a second correlation scheme here would be a second
    chance to get the join wrong.
    """

    def __init__(
        self,
        findings: Iterable[Finding],
        alignment_notes: Iterable[AlignmentNote] = (),
    ) -> None:
        self._ceilings: dict[str, ProtocolObservation] = {}
        self._libraries: dict[str, dict[str, list[LibraryObservation]]] = {}
        #: config asset → {probed service: the note's ``asset_key``}
        self._links: dict[str, dict[str, str]] = {}
        for finding in findings:
            self._absorb(finding)
        for note in alignment_notes:
            self._link(note)

    def _link(self, note: AlignmentNote) -> None:
        """Record §9's correlation: this config finding's file speaks for that service."""
        config, live = note.config_finding, note.live_finding
        if config is None or live is None:
            return
        config_asset, service = asset_of(config), asset_of(live)
        if not config_asset or not service or config_asset == service:
            return
        # First note wins the key for a pair; they all name the same correlation.
        self._links.setdefault(config_asset, {}).setdefault(service, note.asset_key)

    def _absorb(self, finding: Finding) -> None:
        evidence = finding.evidence_raw or {}
        observation = evidence.get("observation")
        asset = asset_of(finding)

        if observation in PROTOCOL_OBSERVATIONS and finding.protocol_version in PROTOCOL_ORDER:
            seen = ProtocolObservation(
                version=finding.protocol_version,
                location=finding.evidence_location or asset,
                observation=str(observation),
            )
            current = self._ceilings.get(asset)
            if current is None or PROTOCOL_ORDER[seen.version] > PROTOCOL_ORDER[current.version]:
                self._ceilings[asset] = seen

        elif observation in LIBRARY_OBSERVATIONS:
            name = str(evidence.get("library") or "").strip().lower()
            parsed = _version_tuple(evidence.get("version"))
            if not name or parsed is None:
                return
            seen = LibraryObservation(
                library=name,
                version=str(evidence.get("version")).strip(),
                parsed=parsed,
                location=finding.evidence_location or asset,
                asset=asset,
                observation=str(observation),
            )
            self._libraries.setdefault(asset, {}).setdefault(name, []).append(seen)

    def protocol_ceiling(self, asset: str) -> ProtocolObservation | None:
        """The highest protocol version this asset was seen to accept or declare.

        Failing that, the ceiling of a service §9 correlated this asset with —
        marked as borrowed, so the prerequisite can say where it really came
        from. An asset no alignment note links to anything gets nothing: what
        8444 negotiates still says nothing about 8443.
        """
        own = self._ceilings.get(asset)
        if own is not None:
            return own

        borrowed = [
            (self._ceilings[service], service, asset_key)
            for service, asset_key in self._links.get(asset, {}).items()
            if service in self._ceilings
        ]
        if not borrowed:
            return None
        # Lowest first, the same direction ``libraries`` borrows in: evidence
        # taken from somewhere else may block a target, never confirm one that
        # the linked services disagree about.
        seen, service, asset_key = min(
            borrowed, key=lambda item: PROTOCOL_ORDER[item[0].version]
        )
        return replace(seen, borrowed_from=service, asset_key=asset_key)

    def libraries(self, asset: str, name: str) -> tuple[LibraryObservation, ...]:
        """Versions of ``name`` seen on this asset — or, failing that, anywhere in the scan."""
        own = self._libraries.get(asset, {}).get(name)
        if own:
            return tuple(own)
        borrowed: list[LibraryObservation] = []
        for per_library in self._libraries.values():
            borrowed.extend(per_library.get(name, ()))
        return tuple(borrowed)


# --------------------------------------------------------------------------- #
# Prerequisites
# --------------------------------------------------------------------------- #


@dataclass(frozen=True, slots=True)
class Prerequisite:
    """One unmet requirement, in the shape §11 prints."""

    unmet: str
    observed: str | None
    observed_at: str | None = None
    note: str | None = None

    def as_dict(self) -> dict[str, Any]:
        entry: dict[str, Any] = {"unmet": self.unmet, "observed": self.observed}
        if self.observed_at is not None:
            entry["observed_at"] = self.observed_at
        if self.note is not None:
            entry["note"] = self.note
        return entry


def _check_library(clause: str, asset: str, observations: ScanObservations) -> Prerequisite | None:
    name, operator, wanted = _parse_library_clause(clause)
    seen = observations.libraries(asset, name)
    if not seen:
        return Prerequisite(
            unmet=clause,
            observed=None,
            note=f"no {name} version was observed for this asset; confirm before deploying",
        )

    # Lowest first: a scan that links two OpenSSLs is held to the older one.
    undecided: list[LibraryObservation] = []
    confirmed: list[LibraryObservation] = []
    for observation in sorted(seen, key=lambda item: item.parsed):
        verdict = _satisfies(observation.parsed, operator, wanted)
        if verdict is False:
            return Prerequisite(
                unmet=clause,
                observed=observation.describe(),
                observed_at=observation.location,
            )
        (confirmed if verdict else undecided).append(observation)

    for observation in undecided:
        # A soname and a version string read from the *same* binary describe one
        # library, and the string carries what the soname lacks. A precise version
        # seen on some other asset settles nothing about this one.
        if any(
            other.asset == observation.asset
            and other.parsed[: len(observation.parsed)] == observation.parsed
            for other in confirmed
        ):
            continue
        return Prerequisite(
            unmet=clause,
            observed=observation.describe(),
            observed_at=observation.location,
            note=(
                f"only the major version was observed ({observation.version}), which "
                f"cannot confirm {clause}; a soname does not carry the minor release"
            ),
        )
    return None


def _check_protocol(clause: str, asset: str, observations: ScanObservations) -> Prerequisite | None:
    wanted = _parse_protocol_clause(clause)
    seen = observations.protocol_ceiling(asset)
    if seen is None:
        return Prerequisite(
            unmet=clause,
            observed=None,
            note="no protocol version was observed for this asset; confirm before deploying",
        )
    if PROTOCOL_ORDER[seen.version] >= PROTOCOL_ORDER[wanted]:
        return None
    if seen.borrowed_from is not None:
        # Traceability is the point. The reader has to be able to tell that
        # nothing was measured on this file.
        return Prerequisite(
            unmet=clause,
            observed=PROTOCOL_LABEL[seen.version],
            observed_at=seen.borrowed_from,
            note=(
                f"observed on {seen.borrowed_from}, the service this asset is "
                f"correlated with ({seen.asset_key}), not on this file"
            ),
        )
    return Prerequisite(
        unmet=clause,
        observed=PROTOCOL_LABEL[seen.version],
        observed_at=seen.location,
    )


_CHECKS = {"library": _check_library, "protocol_min": _check_protocol}


def _unmet_prerequisites(
    requires: Mapping[str, Any], asset: str, observations: ScanObservations
) -> tuple[Prerequisite, ...]:
    """Every unmet clause, in work-plan order (long-lead first), whatever order the YAML used."""
    unmet: list[Prerequisite] = []
    for key in _REQUIREMENT_ORDER:
        if key not in requires:
            continue
        result = _CHECKS[key](str(requires[key]), asset, observations)
        if result is not None:
            unmet.append(result)
    for key in requires:
        if key not in _CHECKS:
            # validate_targets rejects this at startup; reaching it means the
            # pack changed under a running process.
            raise PolicyValidationError(
                f"pqc_targets.yaml: unsupported requirement '{key}'"
            )
    return tuple(unmet)


# --------------------------------------------------------------------------- #
# Parameter sets — §11 step 2
# --------------------------------------------------------------------------- #


def _lifetime_matches(match: Mapping[str, Any], data_lifetime_years: int | None) -> bool:
    """``asset_lifetime_gt`` against the scan's X. An unstated lifetime clears no threshold."""
    threshold = match.get("asset_lifetime_gt")
    if threshold is None:
        return True
    return data_lifetime_years is not None and data_lifetime_years > int(threshold)


def select_parameter_set(
    name: str | None, policy: PolicyPack, data_lifetime_years: int | None
) -> tuple[str | None, str | None]:
    """The parameter set for this scan's data lifetime, and the rule that chose it.

    Reads the pack's ``parameter_sets`` block. With no matching entry, or none
    that names this target, the rule's own target stands.
    """
    if name is None:
        return None, None
    for entry in policy.parameter_sets:
        if not _lifetime_matches(entry.match, data_lifetime_years):
            continue
        replacement = entry.replace.get(name)
        if replacement:
            return str(replacement), entry.id
    return name, None


# --------------------------------------------------------------------------- #
# The decision
# --------------------------------------------------------------------------- #


@dataclass(frozen=True, slots=True)
class _Candidate:
    rule: PqcTarget
    target: str
    hybrid_target: str | None
    deploy: str
    action_class: ActionClass | None
    prerequisites: tuple[Prerequisite, ...]
    parameter_set: str | None
    hybrid_applied: bool

    @property
    def feasible(self) -> bool:
        return not self.prerequisites

    @property
    def standardised(self) -> bool:
        return "draft" not in self.rule.source.lower()

    def tie_break_key(self) -> tuple[int, int, int, int]:
        """§11's four tie-breaks, in order. Lower wins."""
        action_rank = (
            ACTION_CLASS_ORDER.index(self.action_class)
            if self.action_class is not None
            else len(ACTION_CLASS_ORDER)
        )
        return (
            0 if self.feasible else 1,
            0 if self.hybrid_applied else 1,
            action_rank,
            0 if self.standardised else 1,
        )


@dataclass(frozen=True, slots=True)
class Advice:
    """One recommendation, and the whole basis for it."""

    status: RecommendationStatus
    target: str | None
    hybrid_target: str | None
    action_class: ActionClass | None
    prerequisites: tuple[Prerequisite, ...]
    side_effects: str | None
    source_citation: str
    rule_id: str | None
    #: every factor that produced the row — logged, and returned to callers
    rationale: dict[str, Any] = field(default_factory=dict)

    def as_row(self, finding_id: UUID) -> Recommendation:
        return Recommendation(
            finding_id=finding_id,
            status=self.status,
            target=self.target,
            hybrid_target=self.hybrid_target,
            action_class=self.action_class,
            prerequisites=[item.as_dict() for item in self.prerequisites],
            side_effects=self.side_effects,
            source_citation=self.source_citation,
        )


def _action_class_of(rule: PqcTarget) -> ActionClass | None:
    if rule.action_class is None:
        return None
    try:
        return ActionClass(str(rule.action_class))
    except ValueError as exc:
        raise PolicyValidationError(
            f"pqc_targets.yaml: entry '{rule.id}' names action_class {rule.action_class!r}, "
            f"which is not one of {', '.join(a.value for a in ActionClass)}"
        ) from exc


def _candidate(
    rule: PqcTarget,
    finding: Finding,
    asset: str,
    policy: PolicyPack,
    data_lifetime_years: int | None,
    observations: ScanObservations,
) -> _Candidate:
    # Step 2: the parameter set, for the target and for its hybrid alike.
    target, parameter_set = select_parameter_set(rule.target, policy, data_lifetime_years)
    hybrid, _ = select_parameter_set(rule.hybrid, policy, data_lifetime_years)
    # Step 3: what stands in the way on this asset.
    prerequisites = _unmet_prerequisites(rule.requires, asset, observations)
    # Step 4: the hybrid policy, from the pack and only for key exchange.
    hybrid_applied = bool(
        policy.prefer_hybrid and hybrid and finding.primitive is Primitive.KEY_EXCHANGE
    )
    return _Candidate(
        rule=rule,
        target=str(target),
        hybrid_target=hybrid,
        deploy=str(hybrid) if hybrid_applied else str(target),
        action_class=_action_class_of(rule),
        prerequisites=prerequisites,
        parameter_set=parameter_set,
        hybrid_applied=hybrid_applied,
    )


def _side_effects(candidate: _Candidate, tied_with: Sequence[_Candidate]) -> str | None:
    parts: list[str] = []
    if candidate.rule.side_effects:
        parts.append(candidate.rule.side_effects.strip())
    if candidate.rule.note:
        parts.append(candidate.rule.note.strip())
    for other in tied_with:
        parts.append(
            f"Tied with {other.deploy} ({other.rule.id}) under every tie-break; the pack "
            f"states no preference, so both are emitted. This route is a "
            f"{candidate.action_class.value if candidate.action_class else 'unstated'} "
            f"action per {candidate.rule.source}; the other is a "
            f"{other.action_class.value if other.action_class else 'unstated'} action per "
            f"{other.rule.source}."
        )
    return " ".join(parts) or None


def _unknown(finding: Finding, rationale: dict[str, Any]) -> Advice:
    return Advice(
        status=RecommendationStatus.UNKNOWN,
        target=None,
        hybrid_target=None,
        action_class=None,
        prerequisites=(),
        side_effects=None,
        source_citation=NO_TARGET_CITATION,
        rule_id=None,
        rationale={**rationale, "status": RecommendationStatus.UNKNOWN.value},
    )


def advise_finding(
    finding: Finding,
    verdict: Verdict,
    *,
    data_lifetime_years: int | None,
    policy: PolicyPack,
    observations: ScanObservations,
) -> tuple[Advice, ...]:
    """Advice for one finding: usually one entry, several only on a genuine tie.

    Empty when the finding needs no migration — see the module docstring for why
    an ``unknown`` verdict is in that set.
    """
    if verdict not in MIGRATION_VERDICTS:
        return ()

    asset = asset_of(finding)
    matched = pqc_targets_for(finding, policy, data_lifetime_years)
    rationale: dict[str, Any] = {
        "verdict": verdict.value,
        "primitive": (finding.primitive or Primitive.UNKNOWN).value,
        "family": finding.algorithm_family,
        "asset": asset,
        "data_lifetime_years": data_lifetime_years,
        "prefer_hybrid": policy.prefer_hybrid,
        "matched_rules": [rule.id for rule in matched],
    }

    if not matched:
        return (_unknown(finding, rationale),)

    with_target = [rule for rule in matched if rule.target]
    if not with_target:
        # Every matching entry says "no upgrade" — emit the compensating control.
        # If several do, the ids order them so the row is reproducible.
        rule = sorted(matched, key=lambda item: item.id)[0]
        if not rule.compensating_control:
            return (_unknown(finding, rationale),)
        return (
            Advice(
                status=RecommendationStatus.NO_PATH,
                target=None,
                hybrid_target=None,
                action_class=_action_class_of(rule),
                prerequisites=(),
                side_effects=rule.compensating_control.strip(),
                source_citation=rule.source,
                rule_id=rule.id,
                rationale={
                    **rationale,
                    "status": RecommendationStatus.NO_PATH.value,
                    "rule_id": rule.id,
                },
            ),
        )

    candidates = [
        _candidate(rule, finding, asset, policy, data_lifetime_years, observations)
        for rule in with_target
    ]
    best = min(candidate.tie_break_key() for candidate in candidates)
    winners = [candidate for candidate in candidates if candidate.tie_break_key() == best]
    passed_over = [candidate for candidate in candidates if candidate.tie_break_key() != best]

    advice: list[Advice] = []
    for candidate in winners:
        tied_with = [other for other in winners if other is not candidate]
        status = (
            RecommendationStatus.RECOMMENDED
            if candidate.feasible
            else RecommendationStatus.BLOCKED
        )
        advice.append(
            Advice(
                status=status,
                target=candidate.deploy,
                hybrid_target=candidate.hybrid_target,
                action_class=candidate.action_class,
                prerequisites=candidate.prerequisites,
                side_effects=_side_effects(candidate, tied_with),
                source_citation=candidate.rule.source,
                rule_id=candidate.rule.id,
                rationale={
                    **rationale,
                    "status": status.value,
                    "rule_id": candidate.rule.id,
                    "pure_target": candidate.target,
                    "hybrid_applied": candidate.hybrid_applied,
                    "parameter_set_rule": candidate.parameter_set,
                    "feasible": candidate.feasible,
                    "tie_break_key": list(candidate.tie_break_key()),
                    "tied_with": [other.rule.id for other in tied_with],
                    "passed_over": [
                        {
                            "rule_id": other.rule.id,
                            "target": other.deploy,
                            "feasible": other.feasible,
                            "tie_break_key": list(other.tie_break_key()),
                        }
                        for other in passed_over
                    ],
                },
            )
        )
    return tuple(advice)


# --------------------------------------------------------------------------- #
# Pack validation — at startup, not mid-scan
# --------------------------------------------------------------------------- #


def validate_targets(policy: PolicyPack | None = None) -> None:
    """Check every ``pqc_targets`` entry can actually be applied. Raises if not.

    The loader enforces the citation and the id. What it cannot know is whether
    ``requires: {libary: "openssl>=3.5"}`` means anything — and that typo does not
    fail, it *disappears*: the target loses its prerequisite and is recommended
    onto an OpenSSL that cannot run it. A pack defect stops the process.
    """
    pack = policy or get_policy()
    for rule in pack.pqc_targets:
        for key in rule.match:
            if key not in MATCH_KEYS:
                raise PolicyValidationError(
                    f"pqc_targets.yaml: entry '{rule.id}' matches on '{key}', which the "
                    f"advisor does not implement. Supported: {', '.join(sorted(MATCH_KEYS))}."
                )
        for value in _as_list(rule.match.get("primitive")):
            try:
                Primitive(str(value))
            except ValueError as exc:
                raise PolicyValidationError(
                    f"pqc_targets.yaml: entry '{rule.id}' names primitive {value!r}, which "
                    f"is not one of {', '.join(p.value for p in Primitive)}"
                ) from exc
        for value in _as_list(rule.match.get("observation")):
            if str(value) not in MATCHABLE_OBSERVATIONS:
                raise PolicyValidationError(
                    f"pqc_targets.yaml: entry '{rule.id}' matches observation {value!r}, "
                    "which no collector emits — the entry would match nothing. "
                    f"Supported: {', '.join(sorted(MATCHABLE_OBSERVATIONS))}."
                )
        for value in _as_list(rule.match.get("source_layer")):
            # A misspelt layer would not narrow the entry, it would silence it:
            # the rule would match nothing and the findings it was written for
            # would come back as `unknown` with no sign that a rule exists.
            try:
                SourceLayer(str(value))
            except ValueError as exc:
                raise PolicyValidationError(
                    f"pqc_targets.yaml: entry '{rule.id}' names source_layer {value!r}, "
                    f"which is not one of {', '.join(layer.value for layer in SourceLayer)}"
                ) from exc
        _validate_lifetime(rule.match, f"entry '{rule.id}'")

        if not rule.target and not rule.compensating_control:
            raise PolicyValidationError(
                f"pqc_targets.yaml: entry '{rule.id}' has neither a 'target' nor a "
                "'compensating_control'. An entry has to say what to do."
            )
        _action_class_of(rule)

        for key, clause in rule.requires.items():
            if key not in REQUIREMENT_KEYS:
                raise PolicyValidationError(
                    f"pqc_targets.yaml: entry '{rule.id}' requires '{key}', which the "
                    "advisor cannot test. Supported: "
                    f"{', '.join(sorted(REQUIREMENT_KEYS))}. An untestable prerequisite "
                    "would be skipped, and a skipped prerequisite is a target recommended "
                    "onto a host that cannot run it."
                )
            if key == "library":
                _parse_library_clause(str(clause))
            else:
                _parse_protocol_clause(str(clause))

    for entry in pack.parameter_sets:
        for key in entry.match:
            if key != "asset_lifetime_gt":
                raise PolicyValidationError(
                    f"pqc_targets.yaml: parameter_sets entry '{entry.id}' matches on "
                    f"'{key}'; only 'asset_lifetime_gt' is supported"
                )
        _validate_lifetime(entry.match, f"parameter_sets entry '{entry.id}'")
        if not entry.replace:
            raise PolicyValidationError(
                f"pqc_targets.yaml: parameter_sets entry '{entry.id}' replaces nothing"
            )


def _as_list(value: Any) -> tuple[Any, ...]:
    if value is None:
        return ()
    if isinstance(value, (list, tuple)):
        return tuple(value)
    return (value,)


def _validate_lifetime(match: Mapping[str, Any], label: str) -> None:
    threshold = match.get("asset_lifetime_gt")
    if threshold is not None and not isinstance(threshold, int):
        raise PolicyValidationError(
            f"pqc_targets.yaml: {label}: 'asset_lifetime_gt' must be an integer number "
            f"of years, got {threshold!r}"
        )


# --------------------------------------------------------------------------- #
# Entry point
# --------------------------------------------------------------------------- #


def advise_scan(
    session: Session, scan: Scan, policy: PolicyPack | None = None
) -> list[Recommendation]:
    """Write ``recommendations`` rows for every finding in a scan that needs migrating.

    Called by ``app/runner.py`` after the policy engine, beside the risk scorer
    (§4 step 10). Re-running replaces this scan's rows: advice under a newer
    pack, or after a collector observed the OpenSSL upgrade, is a legitimate
    thing to want, and a finding wearing two contradictory recommendations is not.
    """
    pack = policy or get_policy()

    findings = session.scalars(
        sa.select(Finding).where(Finding.scan_id == scan.id).order_by(Finding.id)
    ).all()
    # §9 ran before the policy engine, so its notes are already stored. They are
    # what lets a config finding be tested against the ceiling of the service it
    # was correlated with.
    notes = session.scalars(
        sa.select(AlignmentNote)
        .where(AlignmentNote.scan_id == scan.id)
        .options(
            sa.orm.joinedload(AlignmentNote.config_finding),
            sa.orm.joinedload(AlignmentNote.live_finding),
        )
        .order_by(AlignmentNote.id)
    ).all()
    # Every finding feeds the feasibility check, whether or not it gets a row.
    observations = ScanObservations(findings, notes)

    verdicts = {
        row.finding_id: row.verdict
        for row in session.scalars(
            sa.select(VerdictRow).where(
                VerdictRow.finding_id.in_(sa.select(Finding.id).where(Finding.scan_id == scan.id))
            )
        )
    }

    finding_ids = sa.select(Finding.id).where(Finding.scan_id == scan.id)
    session.execute(
        sa.delete(Recommendation).where(Recommendation.finding_id.in_(finding_ids)),
        execution_options={"synchronize_session": False},
    )

    rows: list[Recommendation] = []
    counts: Counter[str] = Counter()
    for finding in findings:
        verdict = verdicts.get(finding.id)
        if verdict is None:
            continue
        for advice in advise_finding(
            finding,
            verdict,
            data_lifetime_years=scan.data_lifetime_years,
            policy=pack,
            observations=observations,
        ):
            counts[advice.status.value] += 1
            rows.append(advice.as_row(finding.id))
            if advice.status is RecommendationStatus.BLOCKED:
                logger.info(
                    "finding %s (%s %s): %s blocked by %s",
                    finding.id,
                    finding.algorithm_family,
                    (finding.primitive or Primitive.UNKNOWN).value,
                    advice.target,
                    "; ".join(
                        f"{item.unmet} (observed: {item.observed or 'nothing'})"
                        for item in advice.prerequisites
                    ),
                )

    session.add_all(rows)
    session.flush()

    logger.info(
        "scan %s: %d recommendation(s) — %s",
        scan.id,
        len(rows),
        ", ".join(
            f"{status.value} {counts.get(status.value, 0)}" for status in RecommendationStatus
        ),
    )
    return rows


def recommendation_counts(rows: Sequence[Recommendation]) -> dict[str, int]:
    """Rows per status. Four keys, always — §11: reporting only ``recommended`` hides the hard part."""
    counts = {status.value: 0 for status in RecommendationStatus}
    for row in rows:
        counts[row.status.value] += 1
    return counts


# --------------------------------------------------------------------------- #
# Rolling the chains up — one work item, however many findings wear it
# --------------------------------------------------------------------------- #


@dataclass(frozen=True, slots=True)
class BlockedChain:
    """One distinct blocker chain, and everything held behind it.

    A per-finding blocked count scales with how thoroughly the scan searched,
    not with how much work there is. Forty findings behind "upgrade OpenSSL,
    then enable TLS 1.3" are one procurement item and one config line — and that
    is the number someone planning the migration needs.
    """

    #: the work item and what was seen — ``unmet`` and ``observed`` per entry,
    #: long-lead item first. Where it was seen is the ``assets`` list; carrying
    #: one row's ``observed_at`` up here would name one asset out of several.
    prerequisites: tuple[Mapping[str, Any], ...]
    #: distinct findings blocked by exactly this chain
    finding_count: int
    #: the assets those findings sit on, in the order they were first seen
    assets: tuple[str, ...]

    def as_dict(self) -> dict[str, Any]:
        return {
            "prerequisites": [dict(item) for item in self.prerequisites],
            "finding_count": self.finding_count,
            "assets": list(self.assets),
        }


def requirement_of(unmet: str) -> str | None:
    """Which ``_REQUIREMENT_ORDER`` key a chain entry came from, read back off the clause.

    The stored row carries the clause as the pack wrote it, not the key it was
    filed under, and the rollup has to order chains the same way the chains
    themselves are ordered. ``None`` for a clause from a pack this build cannot
    parse — it sorts last rather than crashing a read endpoint.
    """
    if _LIBRARY_CLAUSE.match(unmet):
        return "library"
    if _PROTOCOL_CLAUSE.match(unmet):
        return "protocol_min"
    return None


def _chain_rank(prerequisites: Sequence[Mapping[str, Any]]) -> tuple[int, ...]:
    ranks = []
    for item in prerequisites:
        key = requirement_of(str(item.get("unmet") or ""))
        ranks.append(
            _REQUIREMENT_ORDER.index(key) if key in _REQUIREMENT_ORDER else len(_REQUIREMENT_ORDER)
        )
    return tuple(ranks)


def _chain_entries(
    prerequisites: Iterable[Mapping[str, Any]],
) -> tuple[dict[str, Any], ...]:
    """A chain reduced to the work it describes: what is unmet, and what was seen.

    Two findings share a chain when the same clauses are unmet against the same
    observations. What is deliberately *not* part of that identity is
    ``observed_at`` — where the evidence came from is the ``assets`` list, and
    keeping it in the key would split one "enable TLS 1.3" job into one row per
    host. What *is* part of it is ``observed``: "openssl 1.1.1f" and "no openssl
    observed at all" are different work, and rolling them together would hide a
    confirmation task inside an upgrade task.
    """
    return tuple(
        {"unmet": item.get("unmet"), "observed": item.get("observed")}
        for item in prerequisites
    )


def blocked_chains(pairs: Iterable[tuple[Recommendation, Finding]]) -> list[BlockedChain]:
    """Distinct blocker chains across a scan, long-lead-first.

    Ordered by the same ``_REQUIREMENT_ORDER`` the chains themselves are built
    with, so a chain that starts with a procurement item comes before one that
    is only a config line; then by how much is held behind it.
    """
    grouped: dict[Any, dict[str, Any]] = {}
    for row, finding in pairs:
        if row.status is not RecommendationStatus.BLOCKED or not row.prerequisites:
            continue
        prerequisites = _chain_entries(row.prerequisites)
        entry = grouped.setdefault(
            tuple((item["unmet"], item["observed"]) for item in prerequisites),
            {"prerequisites": prerequisites, "findings": set(), "assets": []},
        )
        entry["findings"].add(finding.id if finding.id is not None else id(finding))
        asset = asset_of(finding)
        if asset and asset not in entry["assets"]:
            entry["assets"].append(asset)

    chains = [
        BlockedChain(
            prerequisites=entry["prerequisites"],
            finding_count=len(entry["findings"]),
            assets=tuple(entry["assets"]),
        )
        for entry in grouped.values()
    ]
    chains.sort(
        key=lambda chain: (
            _chain_rank(chain.prerequisites),
            -chain.finding_count,
            # Last, so two chains of equal rank and equal weight still come out
            # in the same order on every read of the same scan.
            [
                (str(item.get("unmet") or ""), str(item.get("observed") or ""))
                for item in chain.prerequisites
            ],
        )
    )
    return chains
