"""The FastAPI application.

The policy pack loads on the lifespan startup hook, before the first request is
served. A pack that fails validation stops the process there rather than letting
the API answer with uncited verdicts later (§6).
"""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI

from app.api import scans
from app.startup import initialise

logger = logging.getLogger(__name__)

DESCRIPTION = (
    "Enterprise Cryptographic Discovery & Analysis Tool. Self-hosted and "
    "air-gapped: the only outbound connections are cloning a repo the user named "
    "and probing a host the user named."
)


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings, policy = initialise()
    app.state.settings = settings
    app.state.policy = policy
    yield


app = FastAPI(
    title="ECDAT",
    description=DESCRIPTION,
    version="0.7.0",  # build step 7 — network probe
    lifespan=lifespan,
)

app.include_router(scans.router)


@app.get("/api/health", tags=["meta"])
def health() -> dict:
    """Liveness plus the policy stamp the UI needs for its staleness banner (§6)."""
    policy = app.state.policy
    return {
        "status": "ok",
        "policy_version": policy.version.version,
        "policy_published": policy.version.published.isoformat(),
        "policy_age_days": policy.version.age_days(),
        "policy_stale": policy.version.is_stale(),
    }
