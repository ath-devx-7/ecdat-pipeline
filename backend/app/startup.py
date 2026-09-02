"""Application startup.

Loads the policy pack once, before anything can serve a request. A pack that
fails validation must stop the process here rather than produce uncited verdicts
later — this is the enforcement point for the §6 citation rule.

``app/main.py`` (build step 2) calls :func:`initialise` on the FastAPI lifespan.
"""

from __future__ import annotations

import logging

from app.config import Settings, get_settings
from app.core.policy_loader import PolicyPack, get_policy

logger = logging.getLogger(__name__)


def initialise() -> tuple[Settings, PolicyPack]:
    """Load settings and the policy pack. Raises ``PolicyError`` if the pack is bad."""
    settings = get_settings()
    policy = get_policy()

    logger.info(
        "policy pack %s loaded from %s (published %s, %d algorithm rules, %d PQC targets)",
        policy.version.version,
        policy.policy_dir,
        policy.version.published.isoformat(),
        len(policy.algorithms),
        len(policy.pqc_targets),
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
