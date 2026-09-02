# ECDAT

**Enterprise Cryptographic Discovery & Analysis Tool** — SIH 2026, problem statement SIH26164 (NTRO).

Scans a codebase, container image or live endpoint for cryptography, classifies each
finding as broken / quantum-vulnerable / safe, and produces a **ranked migration plan**.
See [SPEC.md](SPEC.md) for the full specification.

The two differentiators: **drift detection** (what config declares vs. what a live server
actually negotiates) and **risk ranking via Mosca's inequality**.

## Non-negotiable properties

- **Air-gapped.** No external network calls in the scan path — no GitHub API, no deps.dev,
  no telemetry. The only outbound connections are cloning a repo the user gave us and
  probing a host the user gave us.
- **Never read private key material.** Key files are detected by metadata only.
- **Never auto-remediate.** Recommend and diff; a human applies it.
- **Explicit scan scope.** The prober refuses any host not in the scan's declared targets.

## Build status

Built one step at a time per `BUILD_PLAN.md`.

| Step | Component | State |
|---|---|---|
| 1 | DB schema, Alembic, policy loader | done |
| 2–14 | intake, collectors, analysis, UI, reports | not started |

## Backend — local setup

Requires Python 3.11+ and PostgreSQL 16.

```bash
python -m venv .venv
.venv/Scripts/python -m pip install -r backend/requirements.txt   # Windows
# source .venv/bin/activate && pip install -r backend/requirements.txt

cd backend
export ECDAT_DATABASE_URL="postgresql+psycopg://ecdat:ecdat@localhost:5432/ecdat"
alembic upgrade head
pytest
```

All settings are environment variables prefixed `ECDAT_` (see `backend/app/config.py`);
a `backend/.env` file is picked up if present. The migration also runs against SQLite
(`ECDAT_DATABASE_URL="sqlite+pysqlite:///ecdat.sqlite"`), which is how the test suite runs
without a database server. Postgres is the only supported store for real scans — the schema
uses `jsonb`, `uuid`, `timestamptz` and native enum types.

## Policy pack

`backend/policy/` holds five YAML files, loaded **read-only** at startup:
`version.yaml`, `algorithms.yaml`, `pqc_targets.yaml`, `algorithm_aliases.yaml`,
`named_groups.yaml`.

Nothing writes back to them, and no API endpoint exposes them for editing. Every entry in
`algorithms.yaml` and `pqc_targets.yaml` must carry a `source` citation — the loader
refuses to start otherwise, naming the offending entry.

Each scan stamps the pack version. Because an air-gapped install cannot fetch updates, a
pack older than `staleness_warning_days` raises a warning at startup and a banner in the UI:
a human has to carry a newer pack in deliberately.

## Execution model

**Scans run synchronously** — `POST /api/scans` blocks until the scan completes. This is a
deliberate prototype simplification, guarded by a file cap (5000), per-collector timeout
(120s), per-scan timeout (600s) and a probe-target cap (20).

**Async workers (Celery + Redis) are the production path.** `ScanRunner` is structured so
the collector loop can be swapped for a queue without touching collector code.

## Prior art

CBOMkit (PQCA / Linux Foundation) already does source and container scanning with a
CycloneDX store. SandboxAQ AQtive Guard and Keyfactor do live network discovery and risk
prioritisation commercially. ECDAT's claim is the **deployment model** — open source,
self-hostable, fully air-gapped, auditable — combined with drift detection and Mosca-based
ranking. The CBOM import path exists so CBOMkit is an input rather than a competitor.
