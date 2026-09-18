"""Risk scorer — SPEC.md §12, build step 9.

Waves, not a sorted list. A ranked list that puts a three-year rewrite at
position one is operationally useless: nobody can start at the top and work
down, so nobody starts.

**The primitive gate is the whole thing.** Mosca's inequality is a statement
about *harvest now, decrypt later*: traffic recorded today and opened once a
quantum computer exists. That only threatens confidentiality — a key exchange or
a cipher. It says nothing about a signature, because forging a signature in 2035
does not retroactively forge a 2026 transaction. There is no harvest step, so the
data's lifetime X is irrelevant and the deadline is Z alone.

So a signature finding gets ``urgency_years = null`` and goes to ``wave_3``,
however long-lived the data is. An implementation that skips this gate ranks a
certificate's signing key as urgently as the key exchange protecting the traffic,
which is wrong in a way that would reorder somebody's entire migration budget.

**Every input is stored, not just the answer.** X, Y and Z all land on the row
alongside the wave, and ``rationale`` carries every factor that produced it. An
auditor who cannot reconstruct a wave assignment from the row will not trust any
of them, and "the tool said so" is not a defence at a review board.

**All three inputs vary, and each one says where it came from.** X comes from
the lifetime the user set for that finding's own file on the approval screen and
falls back to the scan-wide value; Y comes from the finding's cheapest action
class and falls back to the pack default; Z is the slider. Two of those are assumptions rather than measurements, which is why the
row carries ``x_source`` and ``y_source`` beside the numbers. A single Y for
every finding would say that swapping a cipher suite in a config file and
replacing an HSM take the same time to do, and a ranking built on that claim
puts everything in one wave — which is the one outcome §12 exists to avoid.

**No machine learning here, and there is no version of this component that should
have any.** There is no labelled training data for correct migration order, and a
wave nobody can explain is a wave nobody can act on.

WHAT GETS A ROW

The wave table in §12 is written in terms of ``broken_now``, ``quantum_vulnerable``
and the uncertain cases. Nothing in it covers ``quantum_safe`` or ``hygiene``, and
that is not an oversight to paper over: a risk score says *when this must be
migrated*, and neither of those has to be. They get no row, which is what
``demo/README.md`` records as a wave of "—". Their verdicts still appear
everywhere verdicts appear.

ORDER OF THE CHECKS, AND WHY UNCERTAINTY COMES FIRST

``verify`` is evaluated before anything else. A finding whose observation is weak,
or whose verdict no cited rule produced, is not a migration item yet — the action
it needs is confirmation, and filing it as ``wave_0`` would send somebody chasing
an algorithm that may not be there. The uncertainty is the finding.
"""

from __future__ import annotations

import logging
import re
from collections import Counter
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

import sqlalchemy as sa
from sqlalchemy.orm import Session

from app.core.policy import cheapest_action_class, pqc_targets_for
from app.core.policy_loader import PolicyPack, get_policy
from app.models.analysis import RiskScore, VerdictRow
from app.models.enums import ActionClass, Confidence, Primitive, Verdict, Wave
from app.models.finding import Finding
from app.models.scan import Scan, ScanFile

logger = logging.getLogger(__name__)

__all__ = [
    "AUTHENTICATION_PRIMITIVES",
    "CONFIDENTIALITY_PRIMITIVES",
    "LOW_EFFORT_ACTION_CLASSES",
    "RiskDecision",
    "hndl_applies",
    "resolve_data_lifetime",
    "score_finding",
    "score_scan",
    "wave_counts",
]

#: Recordable today, decryptable later. Mosca applies to exactly these (§12).
CONFIDENTIALITY_PRIMITIVES = frozenset({Primitive.KEY_EXCHANGE, Primitive.CIPHER})

#: Authentication. No harvest step exists, so X does not enter the arithmetic.
#: Named separately from "everything else" because §12 singles it out, and
#: because a reader needs to see that the exclusion was deliberate.
AUTHENTICATION_PRIMITIVES = frozenset({Primitive.SIGNATURE})

#: §12's wave_1 / wave_2 split. High effort is *why* a finding needs budgeting
#: now rather than a reason to defer it, so the expensive half is not "later" —
#: it is a different wave that starts at the same time and finishes after.
LOW_EFFORT_ACTION_CLASSES = frozenset({ActionClass.CONFIG, ActionClass.LIBRARY_UPGRADE})


def hndl_applies(primitive: Primitive | None) -> bool:
    """Is this finding exposed to harvest-now-decrypt-later?

    Only confidentiality primitives are. ``hash``, ``protocol`` and ``unknown``
    are not confidentiality primitives either, so they fall out of Mosca for the
    same reason signatures do — there is nothing to record now and open later.
    """
    return primitive in CONFIDENTIALITY_PRIMITIVES


@dataclass(frozen=True, slots=True)
class RiskDecision:
    """One finding's wave, and every input that produced it."""

    wave: Wave
    urgency_years: int | None
    x_years: int | None
    y_years: int
    z_years: int
    rationale: dict[str, Any]


#: A source finding records ``path:line`` and a probed one ``host:port``. A
#: lifetime is set on a file, not on a line of it, so the ordinal comes off
#: before the lookup — and the unstripped spelling is tried first, so a probe
#: target could still be named exactly if it ever carried one.
_TRAILING_ORDINAL = re.compile(r":\d+$")


def _location_candidates(location: str | None) -> tuple[str, ...]:
    """The spellings an asset's lifetime may be stored under, most exact first."""
    if not location or not location.strip():
        return ()
    exact = location.strip()
    without_ordinal = _TRAILING_ORDINAL.sub("", exact)
    return (exact,) if without_ordinal == exact else (exact, without_ordinal)


def _urgency(x_years: int | None, y_years: int, z_years: int) -> int | None:
    """``(X + Y) − Z``. Positive means overdue. ``None`` when X is not known."""
    if x_years is None:
        return None
    return (x_years + y_years) - z_years


def resolve_data_lifetime(
    finding: Finding,
    file_lifetimes: Mapping[str, int],
    fallback: int | None,
) -> tuple[int | None, str]:
    """X for one finding: its own file's lifetime, else the scan's.

    X is the one Mosca input nobody can measure from a file. One value per scan
    is a reasonable default and a poor description of a real estate — a customer
    database and a monitoring endpoint behind the same nginx do not share a
    confidentiality horizon, and scoring them identically is what collapses a
    wave chart into a single bar.

    The lookup is by exact path, because that is what the user set: on the
    approval screen they gave a lifetime to a row they were looking at. A
    finding's ``evidence_location`` is ``path:line`` in a source file and
    ``host:port`` on a probed service, so the trailing ``:<digits>`` is stripped
    before the lookup — a lifetime belongs to the file, not to line 14 of it. A
    probed host has no file and no override, and is scored at the scan's value.
    """
    for candidate in _location_candidates(finding.evidence_location):
        years = file_lifetimes.get(candidate)
        if years is not None:
            return years, f"file: {candidate}"

    if fallback is None:
        return None, "not supplied"
    return fallback, "scan default"


def score_finding(
    finding: Finding,
    verdict: Verdict,
    *,
    data_lifetime_years: int | None,
    policy: PolicyPack,
    z_years: int | None = None,
    file_lifetimes: Mapping[str, int] | None = None,
) -> RiskDecision | None:
    """Place one finding in a wave, or return ``None`` if it needs no migration.

    ``z_years`` overrides the policy default so the UI's slider (§12) can ask
    "what if a quantum computer arrives sooner" without editing the pack. What
    was actually used is stored on the row either way.

    ``file_lifetimes`` maps a file path to the X the user set for that file on
    the approval screen; ``data_lifetime_years`` remains the fallback for every
    asset that has no entry there.

    All three inputs vary, and each says where it came from. Y is read from the
    finding's cheapest action class, because a config change and a hardware
    replacement are not the same migration and pretending otherwise flattens the
    ranking this component exists to produce. Both provenance keys —
    ``x_source`` and ``y_source`` — sit on the row beside the numbers: an
    auditor has to see not only that Y was 3 but that it was 3 *because the
    cheapest route was a code change*, and that the pack states that as an
    assumption rather than a measurement.
    """
    z = policy.version.z_years_default if z_years is None else z_years
    x, x_source = resolve_data_lifetime(finding, file_lifetimes or {}, data_lifetime_years)

    # Y before the action class is resolved: the gates below exit before there
    # is anything to resolve, and a verify row still has to carry a Y.
    y = policy.version.y_years_default
    y_source = "policy_default (action class not resolved)"

    primitive = finding.primitive or Primitive.UNKNOWN
    confidentiality = hndl_applies(primitive)

    rationale: dict[str, Any] = {
        "verdict": verdict.value,
        "primitive": primitive.value,
        "hndl_applicable": confidentiality,
        "x_years": x,
        "x_source": x_source,
        "y_years": y,
        "y_source": y_source,
        "z_years": z,
        "urgency_years": None,
        "action_class": None,
        "confidence": finding.confidence.value if finding.confidence else None,
    }

    def decided(wave: Wave, because: str, urgency_years: int | None) -> RiskDecision:
        rationale["urgency_years"] = urgency_years
        rationale["wave"] = wave.value
        rationale["because"] = because
        return RiskDecision(
            wave=wave,
            urgency_years=urgency_years,
            x_years=x,
            y_years=rationale["y_years"],
            z_years=z,
            rationale=rationale,
        )

    # Uncertainty first. The action a shaky observation needs is confirmation,
    # and calling it wave_0 would send someone after an algorithm that may not
    # be there at all.
    if finding.confidence is Confidence.LOW:
        return decided(Wave.VERIFY, "the observation is low confidence", None)
    if verdict is Verdict.UNKNOWN:
        return decided(Wave.VERIFY, "no policy entry matched, so the verdict is unknown", None)

    if verdict is Verdict.BROKEN_NOW:
        # Regardless of primitive: this is not a quantum deadline, it is a
        # today deadline, and Mosca has nothing to say about it.
        rationale["hndl_applicable"] = False
        return decided(Wave.WAVE_0, "the algorithm is broken today", None)

    if verdict is not Verdict.QUANTUM_VULNERABLE:
        # quantum_safe and hygiene are not migration items. §12's table does not
        # cover them, and inventing a wave would put things on the roadmap that
        # nobody has to do.
        return None

    if primitive is Primitive.UNKNOWN:
        # RSA from a key generator, an EC key with no recorded use: vulnerable,
        # certainly, but whether Mosca applies turns on what the key does, and
        # nothing observed that. Filing it as wave_3 would assume "not
        # harvestable"; filing it as wave_1 would assume the opposite. The
        # honest action is to find out.
        return decided(
            Wave.VERIFY,
            "the primitive was not observed, so whether Mosca applies cannot be decided; "
            "confirm what the key is used for",
            None,
        )

    # The action class, once, before the arithmetic. It carries Y as well as the
    # wave_1 / wave_2 split, so it is resolved for every row that can have one —
    # including the signatures Mosca never reaches, whose migration effort is no
    # less real for being undated.
    targets = pqc_targets_for(finding, policy, x)
    action_class, rule_id = cheapest_action_class(targets)
    y, y_source = policy.version.y_years_for(action_class.value if action_class else None)
    rationale["action_class"] = action_class.value if action_class else None
    rationale["action_class_rule"] = rule_id
    rationale["matched_pqc_targets"] = [target.id for target in targets]
    rationale["y_years"] = y
    rationale["y_source"] = y_source

    if not confidentiality:
        reason = (
            "an authentication primitive: forging a signature later does not "
            "retroactively forge a transaction now, so there is no harvest step"
            if primitive in AUTHENTICATION_PRIMITIVES
            else f"a {primitive.value} primitive is not confidentiality, so nothing "
            "recorded now becomes readable later"
        )
        return decided(Wave.WAVE_3, f"Mosca does not apply to {reason}", None)

    urgency = _urgency(x, y, z)
    if urgency is None:
        # X is the one input the user supplies, and without it the inequality
        # cannot be evaluated. Assuming a lifetime would be assuming an answer.
        return decided(
            Wave.VERIFY,
            "data_lifetime_years was not supplied, so (X + Y) - Z cannot be evaluated",
            None,
        )

    if urgency <= 0:
        return decided(
            Wave.WAVE_3,
            f"not overdue: (X {x} + Y {y}) - Z {z} = {urgency}",
            urgency,
        )

    if action_class in LOW_EFFORT_ACTION_CLASSES:
        return decided(
            Wave.WAVE_1,
            f"overdue by {urgency} year(s) and reachable by a {action_class.value}",
            urgency,
        )

    # Includes the case where no pqc_targets rule matched. An overdue migration
    # of unknown effort is planned as though it needs budgeting: filing it with
    # the config changes would let it slip a planning cycle on an assumption
    # nothing supports.
    because = (
        f"overdue by {urgency} year(s) and needs a {action_class.value}"
        if action_class
        else f"overdue by {urgency} year(s), and no pqc_targets rule names the effort — "
        "planned as budgeted work rather than assumed cheap"
    )
    return decided(Wave.WAVE_2, because, urgency)


# --------------------------------------------------------------------------- #
# Entry point
# --------------------------------------------------------------------------- #


def _file_lifetimes(session: Session, scan: Scan) -> dict[str, int]:
    """``{path: years}`` for the files the user gave a lifetime of their own.

    Only the overrides: a file with no value of its own is absent rather than
    present with the scan-wide number, so the row's ``x_source`` can say which
    of the two a finding was actually scored against.
    """
    rows = session.execute(
        sa.select(ScanFile.path, ScanFile.data_lifetime_years).where(
            ScanFile.scan_id == scan.id,
            ScanFile.data_lifetime_years.is_not(None),
        )
    ).all()
    return {path: years for path, years in rows}


def score_scan(
    session: Session,
    scan: Scan,
    policy: PolicyPack | None = None,
    z_years: int | None = None,
) -> list[RiskScore]:
    """Write a ``risk_scores`` row for every finding that needs migrating.

    Called by ``app/runner.py`` after the policy engine: a wave is a function of
    the verdict, so it cannot be computed before there is one. Re-running
    replaces this scan's rows, which is what makes the Z slider (§12) work — the
    same scan re-scored against a different assumption about when a quantum
    computer arrives.

    The per-file X values are read from ``scan_files``, not passed in: they are
    the user's description of their own estate, set when they approved the tree,
    and a re-score is a question about Z alone. Changing X under a slider would
    mean two different questions produced one wave chart.
    """
    pack = policy or get_policy()
    file_lifetimes = _file_lifetimes(session, scan)

    rows = session.execute(
        sa.select(Finding, VerdictRow)
        .join(VerdictRow, VerdictRow.finding_id == Finding.id)
        .where(Finding.scan_id == scan.id)
        .order_by(Finding.id)
    ).all()

    finding_ids = sa.select(Finding.id).where(Finding.scan_id == scan.id)
    session.execute(
        sa.delete(RiskScore).where(RiskScore.finding_id.in_(finding_ids)),
        execution_options={"synchronize_session": False},
    )

    scores: list[RiskScore] = []
    waves: Counter[str] = Counter()
    unscored = 0

    for finding, verdict_row in rows:
        decision = score_finding(
            finding,
            verdict_row.verdict,
            data_lifetime_years=scan.data_lifetime_years,
            policy=pack,
            z_years=z_years,
            file_lifetimes=file_lifetimes,
        )
        if decision is None:
            unscored += 1
            continue

        waves[decision.wave.value] += 1
        scores.append(
            RiskScore(
                finding_id=finding.id,
                x_years=decision.x_years,
                y_years=decision.y_years,
                z_years=decision.z_years,
                urgency_years=decision.urgency_years,
                wave=decision.wave,
                rationale=decision.rationale,
            )
        )

    session.add_all(scores)
    session.flush()

    logger.info(
        "scan %s: scored %d finding(s) into waves — %s; %d needed no migration",
        scan.id,
        len(scores),
        ", ".join(f"{wave} {count}" for wave, count in sorted(waves.items())) or "none",
        unscored,
    )
    return scores


def wave_counts(scores: Sequence[RiskScore]) -> dict[str, int]:
    """Findings per wave. Five keys, never one number — §12's whole point."""
    counts: dict[str, int] = {}
    for score in scores:
        counts[score.wave.value] = counts.get(score.wave.value, 0) + 1
    return counts
