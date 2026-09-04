"""Policy engine — SPEC.md §10, build step 6.

Every finding gets a verdict, and every verdict names the published standard it
came from. That traceability is the product: an unsourced claim that an algorithm
is broken is an opinion, and nobody migrates a payments system on an opinion.

**This is a lookup and nothing else.** There is no computation here, no
heuristic, no inference about cryptographic strength — only "does this finding
match this entry in ``algorithms.yaml``". Every judgement lives in the pack,
where it carries a citation and can be reviewed by someone who knows more
cryptography than this code does. The whole value of the split is that closing a
gap is a policy edit with a citation rather than a code change.

Five outcomes: ``broken_now``, ``quantum_vulnerable``, ``quantum_safe``,
``hygiene``, ``unknown``. Four decisions shape how they are reached.

**``broken_now`` and ``quantum_vulnerable`` are independent, not two points on
one scale.** RSA-4096 is quantum-vulnerable and perfectly secure today. MD5 is
broken today and irrelevant to quantum. Nothing here collapses them into a
severity number, and nothing downstream may either.

**One finding, one verdict — chosen by precedence, not by severity arithmetic.**
Several entries can match honestly: AES-256-ECB is a 256-bit AES key (safe) used
in a mode that leaks structure (broken), and RSA-1024 is both too small today and
quantum-vulnerable tomorrow. The verdict reported is the one that says "not this,
not now", because a finding that is broken today is not made less broken by also
being a problem in 2035. Every rule that matched is kept on the decision and
logged, so the ones that did not win are visible rather than lost.

**The pack's ``family`` and ``oid`` are two names for one algorithm, not two
conditions.** An entry that gives both matches a finding carrying either. A
``primitive`` list and a ``condition`` are constraints and must all hold.

**An unknown primitive is not a wildcard.** A finding whose use was never
observed does not satisfy an entry that names a primitive. Step 9 applies Mosca's
inequality to confidentiality primitives and not to signatures; letting "we don't
know" match "key_exchange" would route a signature into a confidentiality wave on
the strength of a shrug.

Anything with no matching entry is ``unknown`` — never guessed, never assumed
safe. The row still carries a citation-shaped explanation of *why* there is no
standard cited, because a verdict row with an empty provenance field is
indistinguishable from a bug.
"""

from __future__ import annotations

import logging
import re
from collections import Counter
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any
from uuid import UUID

import sqlalchemy as sa
from sqlalchemy.orm import Session

from app.core.normalizer import get_alias_index, identity_key
from app.core.policy_loader import (
    AlgorithmRule,
    PolicyPack,
    PolicyValidationError,
    PqcTarget,
    get_policy,
)
from app.models.analysis import VerdictRow
from app.models.enums import ActionClass, Primitive, Verdict
from app.models.finding import Finding

logger = logging.getLogger(__name__)

__all__ = [
    "CONDITION_KEYS",
    "NO_RULE_CITATION",
    "PolicyDecision",
    "VERDICT_PRECEDENCE",
    "ACTION_CLASS_ORDER",
    "apply_policy",
    "classify",
    "cheapest_action_class",
    "pqc_targets_for",
    "validate_rules",
]

#: The condition keys §6 defines. A pack using anything else is rejected at
#: startup rather than silently ignored: an unrecognised condition would widen
#: its rule to every finding of that family, which turns a typo into a wrong
#: verdict on everything.
CONDITION_KEYS = frozenset({"key_size_lt", "key_size_gte", "mode", "protocol_version_lt"})

#: Which verdict is reported when several entries match. Not a severity scale —
#: it is a reporting order, and the two classifications it orders stay
#: independent everywhere else. "Do not use this today" outranks "this will need
#: replacing", which outranks "this is untidy", which outranks "this is fine".
VERDICT_PRECEDENCE: tuple[Verdict, ...] = (
    Verdict.BROKEN_NOW,
    Verdict.QUANTUM_VULNERABLE,
    Verdict.HYGIENE,
    Verdict.QUANTUM_SAFE,
)

#: What a verdict row says when the pack has no entry for the finding. §10 makes
#: "unknown" a deliberate answer rather than a missing one, and this is where
#: that shows up in the audit trail.
NO_RULE_CITATION = (
    "No entry in the policy pack matches this algorithm identity. SPEC.md §10: an "
    "unmatched finding is reported as 'unknown' — never guessed, never assumed safe."
)

_VERSION_PATTERN = re.compile(r"^\d+(?:\.\d+)*$")


# --------------------------------------------------------------------------- #
# The decision
# --------------------------------------------------------------------------- #


@dataclass(frozen=True, slots=True)
class PolicyDecision:
    """One finding's verdict, and the whole basis for it."""

    verdict: Verdict
    #: the entry that fired, or ``None`` when nothing matched
    rule: AlgorithmRule | None
    #: §10 requires the engine to emit this; step 9's Mosca gate turns on it
    primitive: Primitive
    #: every entry that matched, in the order precedence considered them
    matches: tuple[AlgorithmRule, ...] = ()

    @property
    def rule_id(self) -> str | None:
        return self.rule.id if self.rule is not None else None

    @property
    def source_citation(self) -> str:
        """Never empty. A verdict nobody can trace is not evidence (§10)."""
        return self.rule.source if self.rule is not None else NO_RULE_CITATION

    @property
    def also_matched(self) -> tuple[AlgorithmRule, ...]:
        """The entries precedence passed over. Kept so they are visible, not lost."""
        return self.matches[1:]


# --------------------------------------------------------------------------- #
# Matching
# --------------------------------------------------------------------------- #


def _identity_matches(rule: AlgorithmRule, finding: Finding) -> bool:
    """Does this entry name the algorithm the finding carries?

    ``family`` and ``oid`` are alternatives: an entry writing both is naming one
    algorithm twice, so matching either is matching the algorithm. An entry
    naming neither constrains only by primitive and condition, and applies to
    whatever satisfies those.
    """
    if not rule.family and not rule.oid:
        return True

    if rule.family and finding.algorithm_family:
        observed = identity_key(finding.algorithm_family)
        if any(observed == identity_key(str(family)) for family in rule.family):
            return True

    if rule.oid and finding.algorithm_oid:
        if finding.algorithm_oid.strip() == str(rule.oid).strip():
            return True

    return False


def _primitive_matches(rule: AlgorithmRule, finding: Finding) -> bool:
    """An entry naming primitives needs the finding to have observed one of them.

    ``unknown`` is not a wildcard here. See the module docstring: the field this
    guards is the one step 9 uses to decide whether Mosca applies at all.
    """
    if not rule.primitive:
        return True
    if finding.primitive is None or finding.primitive is Primitive.UNKNOWN:
        return False
    return any(finding.primitive.value == str(value) for value in rule.primitive)


def _version_tuple(value: str | None) -> tuple[int, ...] | None:
    """``"1.0"`` → ``(1, 0)``. Anything not dotted-numeric is ``None``.

    The normalizer canonicalises TLS versions to this shape (§8). A version it
    could not canonicalise arrives here as its observed spelling and returns
    ``None``, which fails the comparison rather than guessing where it sorts.
    """
    if not value or not _VERSION_PATTERN.match(value.strip()):
        return None
    return tuple(int(part) for part in value.strip().split("."))


def _condition_holds(key: str, expected: Any, finding: Finding) -> bool:
    """One ``condition`` clause. Absent evidence never satisfies a clause.

    A finding with no recorded key size does not match ``key_size_lt: 2048`` and
    does not match ``key_size_gte: 128`` either. Both directions have to fail,
    because a missing size is not a small one and it is not a large one — it is
    an unmeasured one, and §10 has exactly one answer for those.
    """
    if key == "key_size_lt":
        return finding.key_size is not None and finding.key_size < int(expected)
    if key == "key_size_gte":
        return finding.key_size is not None and finding.key_size >= int(expected)
    if key == "mode":
        return finding.mode is not None and identity_key(finding.mode) == identity_key(
            str(expected)
        )
    if key == "protocol_version_lt":
        observed = _version_tuple(finding.protocol_version)
        limit = _version_tuple(str(expected))
        return observed is not None and limit is not None and observed < limit
    # validate_rules rejects these at startup; reaching here means the pack
    # changed under a running process, and a silently ignored condition is the
    # one failure mode this engine must not have.
    raise PolicyValidationError(f"algorithms.yaml: unsupported condition '{key}'")


def _rule_matches(rule: AlgorithmRule, finding: Finding) -> bool:
    if not _identity_matches(rule, finding):
        return False
    if not _primitive_matches(rule, finding):
        return False
    return all(_condition_holds(key, value, finding) for key, value in rule.condition.items())


def _verdict_of(rule: AlgorithmRule) -> Verdict:
    try:
        return Verdict(rule.verdict)
    except ValueError as exc:
        allowed = ", ".join(v.value for v in Verdict)
        raise PolicyValidationError(
            f"algorithms.yaml: entry '{rule.id}' has verdict {rule.verdict!r}, "
            f"which is not one of {allowed}"
        ) from exc


def _precedence_rank(rule: AlgorithmRule) -> int:
    verdict = _verdict_of(rule)
    if verdict not in VERDICT_PRECEDENCE:
        raise PolicyValidationError(
            f"algorithms.yaml: entry '{rule.id}' asserts '{verdict.value}', which is the "
            "answer for a finding no entry matched. An entry cannot assert it."
        )
    return VERDICT_PRECEDENCE.index(verdict)


def classify(finding: Finding, policy: PolicyPack | None = None) -> PolicyDecision:
    """Look one finding up in the pack. No fallback, no default, no guess."""
    pack = policy or get_policy()
    matched = [rule for rule in pack.algorithms if _rule_matches(rule, finding)]
    # Ties inside one verdict are broken by rule id so the same finding and the
    # same pack always produce the same row — an audit that cannot be repeated
    # is not an audit.
    matched.sort(key=lambda rule: (_precedence_rank(rule), rule.id))

    winner = matched[0] if matched else None
    return PolicyDecision(
        verdict=_verdict_of(winner) if winner is not None else Verdict.UNKNOWN,
        rule=winner,
        primitive=finding.primitive or Primitive.UNKNOWN,
        matches=tuple(matched),
    )


# --------------------------------------------------------------------------- #
# Pack validation — at startup, not mid-scan
# --------------------------------------------------------------------------- #


def validate_rules(policy: PolicyPack | None = None) -> None:
    """Check every entry can actually be applied. Raises on a pack that cannot.

    The loader (§6) already enforces the citation and the id. What it cannot know
    is whether ``condition: {keysize_lt: 2048}`` means anything — and that typo
    does not fail, it *widens*: the rule loses its size constraint and calls every
    RSA key broken. A pack defect has to stop the process, not produce confident
    wrong verdicts for a week.
    """
    pack = policy or get_policy()
    for rule in pack.algorithms:
        _precedence_rank(rule)  # rejects an unknown or 'unknown' verdict

        for value in rule.primitive:
            try:
                Primitive(str(value))
            except ValueError as exc:
                allowed = ", ".join(p.value for p in Primitive)
                raise PolicyValidationError(
                    f"algorithms.yaml: entry '{rule.id}' names primitive {value!r}, "
                    f"which is not one of {allowed}"
                ) from exc

        for key, expected in rule.condition.items():
            if key not in CONDITION_KEYS:
                supported = ", ".join(sorted(CONDITION_KEYS))
                raise PolicyValidationError(
                    f"algorithms.yaml: entry '{rule.id}' uses condition '{key}', which "
                    f"the engine does not implement. Supported: {supported}."
                )
            if key in ("key_size_lt", "key_size_gte") and not isinstance(expected, int):
                raise PolicyValidationError(
                    f"algorithms.yaml: entry '{rule.id}': '{key}' must be an integer, "
                    f"got {expected!r}"
                )
            if key == "protocol_version_lt" and _version_tuple(str(expected)) is None:
                raise PolicyValidationError(
                    f"algorithms.yaml: entry '{rule.id}': 'protocol_version_lt' must be a "
                    f"dotted version such as \"1.2\", got {expected!r}"
                )

    _warn_about_families_nothing_produces(pack)


def _warn_about_families_nothing_produces(pack: PolicyPack) -> None:
    """A rule on a family the alias table never emits can never fire.

    A warning rather than an error: a pack may legitimately rule ahead of the
    identity table, and refusing to start over it would make the pack harder to
    edit than the code — which is the wrong way round. But a silent no-op rule is
    how a pack ends up looking more complete than it is.
    """
    produced = {identity_key(entry.family) for entry in get_alias_index(pack).entries}
    for rule in pack.algorithms:
        if rule.verdict == Verdict.HYGIENE.value:
            # Hygiene entries rule on the collectors' marker names — a private
            # key file, a hardcoded key — which are not algorithms and are
            # deliberately absent from the alias table. Firing on an unresolved
            # spelling is exactly how they are meant to fire.
            continue
        unreachable = [
            str(family)
            for family in rule.family
            if identity_key(str(family)) not in produced
        ]
        if unreachable:
            logger.warning(
                "algorithms.yaml: entry '%s' rules on family %s, which no alias entry "
                "produces — it can only fire on an unresolved finding that happens to "
                "spell itself that way",
                rule.id,
                ", ".join(unreachable),
            )


# --------------------------------------------------------------------------- #
# Entry point
# --------------------------------------------------------------------------- #


def apply_policy(
    session: Session, scan_id: UUID, policy: PolicyPack | None = None
) -> list[VerdictRow]:
    """Write one ``verdicts`` row per finding in a scan, and return them.

    Called by ``app/runner.py`` after the findings are stored. §9 puts the
    alignment check between those two steps, so that from step 8 a finding
    already carries its drift note by the time it is classified.

    Re-running replaces this scan's verdicts rather than adding to them:
    reclassifying under a newer pack is a legitimate thing to do, and a findings
    row wearing two contradictory verdicts is not.
    """
    pack = policy or get_policy()

    scan_findings = sa.select(Finding.id).where(Finding.scan_id == scan_id)
    session.execute(
        sa.delete(VerdictRow).where(VerdictRow.finding_id.in_(scan_findings)),
        execution_options={"synchronize_session": False},
    )

    findings = session.scalars(
        sa.select(Finding).where(Finding.scan_id == scan_id).order_by(Finding.id)
    ).all()

    rows: list[VerdictRow] = []
    counts: Counter[str] = Counter()
    gaps: Counter[str] = Counter()

    for finding in findings:
        decision = classify(finding, pack)
        # §10 requires the engine to emit a primitive. The normalizer sets one on
        # every row it writes; this is the backstop for a finding that reached the
        # table another way, so step 9 never has to handle a null.
        if finding.primitive is None:
            finding.primitive = Primitive.UNKNOWN

        counts[decision.verdict.value] += 1
        if decision.rule is None:
            gaps[finding.algorithm_family or "(no family)"] += 1
        elif decision.also_matched:
            logger.debug(
                "finding %s: '%s' fired; also matched %s",
                finding.id,
                decision.rule.id,
                ", ".join(other.id for other in decision.also_matched),
            )

        rows.append(
            VerdictRow(
                finding_id=finding.id,
                verdict=decision.verdict,
                rule_id=decision.rule_id,
                source_citation=decision.source_citation,
                # The pack that actually produced the verdict, which is the one
                # loaded now — not necessarily the one stamped on the scan when it
                # was created, if the pack has been carried in since.
                policy_version=pack.version.version,
            )
        )

    session.add_all(rows)
    session.flush()

    logger.info(
        "scan %s: %d verdict(s) from policy pack %s — %s",
        scan_id,
        len(rows),
        pack.version.version,
        ", ".join(f"{verdict} {count}" for verdict, count in sorted(counts.items())) or "none",
    )
    if gaps:
        # The pack's gaps, named. Closing one is an entry with a citation, and
        # this list is the shortest description of which entries to write.
        logger.info(
            "scan %s: no pack entry matched %s",
            scan_id,
            ", ".join(f"{family} x{count}" for family, count in gaps.most_common()),
        )
    return rows


# --------------------------------------------------------------------------- #
# PQC target matching — §11's first step, needed here by §12's wave table
# --------------------------------------------------------------------------- #

#: Cheapest first. §11's third tie-break ("lower action class wins") and §12's
#: split between wave_1 and wave_2 both read this order, so it is written once.
ACTION_CLASS_ORDER: tuple[ActionClass, ...] = (
    ActionClass.CONFIG,
    ActionClass.LIBRARY_UPGRADE,
    ActionClass.CODE_CHANGE,
    ActionClass.HARDWARE,
)


def _match_values(match: Mapping[str, Any], key: str) -> tuple[str, ...]:
    """``family: AES`` and ``family: [RSA, ECDH]`` are both valid YAML (§6)."""
    value = match.get(key)
    if value is None:
        return ()
    if isinstance(value, str):
        return (value,)
    return tuple(str(item) for item in value)


def pqc_targets_for(
    finding: Finding, policy: PolicyPack, data_lifetime_years: int | None = None
) -> tuple[PqcTarget, ...]:
    """Every ``pqc_targets.yaml`` entry whose ``match`` block covers this finding.

    §11's first step, and a pure lookup like everything else in this module.
    Matching is on **primitive plus family**, never on algorithm name alone: RSA
    maps to ML-KEM for key exchange and ML-DSA for signatures, and only the
    primitive tells them apart. Getting that wrong makes the advisor wrong about
    half the time.

    An entry may narrow itself further with ``source_layer`` — the context it was
    written for. A rule whose prerequisites are properties of a running service
    says so, rather than firing on a source file and then holding it to a clause
    nothing there could ever satisfy.

    It lives here rather than in the advisor because §12's wave table needs an
    action class two steps before the advisor exists — ``wave_1`` and ``wave_2``
    are the same finding at different migration costs. Step 10 builds parameter
    selection, feasibility and hybrid policy on top of this; none of that belongs
    in a lookup.
    """
    matched: list[PqcTarget] = []
    for target in policy.pqc_targets:
        primitives = _match_values(target.match, "primitive")
        if primitives and finding.primitive.value not in primitives:
            continue

        # An entry may state the layer it was written for. `kex-to-mlkem`
        # requires a TLS 1.3 ceiling, which is a statement about a deployed
        # service — meaningless against a `dh.generate_parameters()` call in a
        # source file, where no collector can ever observe it. An entry that
        # names no layer applies to every layer, as it always did.
        layers = _match_values(target.match, "source_layer")
        if layers and finding.source_layer.value not in layers:
            continue

        # And an entry may narrow further to the kind of declaration the
        # collector recorded. An sshd_config `KexAlgorithms` line and an nginx
        # key exchange are both config-layer DH; only the second one has a TLS
        # version to be held to.
        observations = _match_values(target.match, "observation")
        if observations:
            seen = (finding.evidence_raw or {}).get("observation")
            if seen is None or str(seen) not in observations:
                continue

        families = _match_values(target.match, "family")
        if families:
            observed = identity_key(finding.algorithm_family or "")
            if not observed or observed not in {identity_key(f) for f in families}:
                continue

        lifetime_gt = target.match.get("asset_lifetime_gt")
        if lifetime_gt is not None:
            # An unstated lifetime does not clear a threshold. The same rule the
            # verdict conditions follow: absent evidence satisfies nothing.
            if data_lifetime_years is None or data_lifetime_years <= int(lifetime_gt):
                continue

        matched.append(target)
    return tuple(matched)


def cheapest_action_class(
    targets: Sequence[PqcTarget],
) -> tuple[ActionClass | None, str | None]:
    """The lowest action class among matching targets, and which rule carried it.

    §11's tie-break says the lower action class wins, and the same choice is the
    right one for planning: the wave should reflect the cheapest route that
    exists, not the most expensive one that also matches.
    """
    best: ActionClass | None = None
    best_id: str | None = None
    for target in targets:
        if target.action_class is None:
            continue
        try:
            action = ActionClass(str(target.action_class))
        except ValueError:
            logger.warning(
                "pqc_targets.yaml: entry '%s' names action_class %r, which is not one "
                "of %s; ignored for planning",
                target.id,
                target.action_class,
                ", ".join(a.value for a in ActionClass),
            )
            continue
        if best is None or ACTION_CLASS_ORDER.index(action) < ACTION_CLASS_ORDER.index(best):
            best, best_id = action, target.id
    return best, best_id
