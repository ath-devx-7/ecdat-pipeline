"""Application startup.

Loads the policy pack once, before anything can serve a request. A pack that
fails validation must stop the process here rather than produce uncited verdicts
later — this is the enforcement point for the §6 citation rule.

``app/main.py`` (build step 2) calls :func:`initialise` on the FastAPI lifespan.
"""

from __future__ import annotations

import logging

from app.config import Settings, get_settings
from app.core.normalizer import get_alias_index
from app.core.policy import validate_rules
from app.core.policy_loader import PolicyPack, get_policy

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

    logger.info(
        "policy pack %s loaded from %s (published %s, %d algorithm rules, %d PQC targets, "
        "%d alias entries over %d spellings)",
        policy.version.version,
        policy.policy_dir,
        policy.version.published.isoformat(),
        len(policy.algorithms),
        len(policy.pqc_targets),
        len(aliases.entries),
        len(aliases.by_name),
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
