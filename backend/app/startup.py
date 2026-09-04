"""Application startup.

Loads the policy pack once, before anything can serve a request. A pack that
fails validation must stop the process here rather than produce uncited verdicts
later — this is the enforcement point for the §6 citation rule.

It is also where the checks that are *not* pack validation live: the code
rules' language coverage (§7.1) is reported here, as a warning rather than a
failure, because a scanned extension with no rule behind it is a gap to see and
not a reason to refuse to start. So is the upload sweep, which is housekeeping
rather than a check — abandoned uploads are copied bytes nobody asked us to
keep.

``app/main.py`` (build step 2) calls :func:`initialise` on the FastAPI lifespan.
"""

from __future__ import annotations

import logging

from app.collectors.code import CODE_EXTENSIONS, validate_rule_coverage
from app.config import Settings, get_settings
from app.core.advisor import validate_targets
from app.core.normalizer import get_alias_index
from app.core.policy import validate_rules
from app.core.policy_loader import PolicyPack, get_policy
from app.intake.upload import sweep_uploads

logger = logging.getLogger(__name__)


def initialise() -> tuple[Settings, PolicyPack]:
    """Load settings and the policy pack. Raises ``PolicyError`` if the pack is bad."""
    settings = get_settings()
    policy = get_policy()
    # Built here rather than on first scan: a duplicate spelling or a missing
    # citation in the alias table is a pack defect, and a pack defect stops the
    # process at startup like every other one (§6).
    aliases = get_alias_index(policy)
    # A condition key the engine does not implement would not fail — it would
    # widen its rule to every finding of that family. Caught here, once.
    validate_rules(policy)
    # Same failure mode on the advisor's side: a `requires` clause the advisor
    # cannot test would not block, it would be skipped — and a prerequisite
    # skipped is a recommendation rounded in the optimistic direction (§11).
    validate_targets(policy)
    # Not a pack defect and not fatal: the scanned-extension list is wider than
    # the rule file by design (see app/collectors/code.py). What would be a
    # defect is nobody knowing which half is which, so the gap is named here,
    # once, beside the other two checks.
    uncovered = validate_rule_coverage()
    # Not a check and never fatal: an upload is bytes we copied and therefore
    # own, and one that nobody turned into a scan has no row pointing at it, so
    # nothing else would ever remove it. A failure here costs disk, not results.
    try:
        sweep_uploads(settings)
    except OSError as exc:
        logger.warning("could not sweep abandoned uploads: %s", exc)

    logger.info(
        "policy pack %s loaded from %s (published %s, %d algorithm rules, %d PQC targets, "
        "%d parameter-set rules, %d alias entries over %d spellings)",
        policy.version.version,
        policy.policy_dir,
        policy.version.published.isoformat(),
        len(policy.algorithms),
        len(policy.pqc_targets),
        len(policy.parameter_sets),
        len(aliases.entries),
        len(aliases.by_name),
    )
    if uncovered:
        logger.info(
            "code rules cover %d of %d scanned extension(s); see the warning above for the rest",
            len(CODE_EXTENSIONS) - len(uncovered),
            len(CODE_EXTENSIONS),
        )
    if policy.version.is_stale():
        logger.warning(
            "policy pack %s is %d days old (warning threshold %d). An air-gapped "
            "install cannot fetch updates — a newer pack must be carried in.",
            policy.version.version,
            policy.version.age_days(),
            policy.version.staleness_warning_days,
        )
    return settings, policy
