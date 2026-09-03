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
| 2 | Intake — staging, surface scan, approval gate | done |
| 3 | Demo environment — targets to scan | done |
| 4 | Certificate and config collectors | done |
| 5 | Normalizer — canonical identities, source layers | done |
| 6 | Policy engine — a cited verdict per finding | done |
| 7 | Network probe — live TLS observation | done |
| 8–14 | alignment, risk scorer, advisor, remaining collectors, UI, reports | not started |

## Demo environment

`demo/` holds the deliberately weak targets everything from step 4 onwards is tested
against — you cannot test a certificate parser without a bad certificate, or a drift
check without a server that contradicts its own config.

```bash
./demo/gen_certs.sh                                  # certificates only
docker compose -f demo/docker-compose.yml up --build # the full lab
```

`demo/README.md` lists the finding every target is expected to produce, and — as much
to the point — what must **not** be flagged. Later steps test against that document.

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

## Running the API

```bash
cd backend
uvicorn app.main:app --reload      # http://127.0.0.1:8000/docs
```

The policy pack loads on startup, before the first request is served; a pack that fails
validation stops the process there rather than answering with uncited verdicts later.

### Intake endpoints

| Endpoint | Does |
|---|---|
| `POST /api/scans` | Creates the scan, stamps the policy version, stages the source and enumerates it. Ends `awaiting_approval` — `probe_only` stages nothing and runs immediately. |
| `GET /api/scans/{id}/files` | The surface scan as a nested tree, with per-directory file counts and sizes for the checkbox UI. |
| `POST /api/scans/{id}/approve` | The permission gate, and the run it releases. Approval is set to *exactly* the submitted path list, so nothing stays in scope silently. Blocks until every collector has finished, then returns `complete` or `partial` with a per-collector breakdown. |

```bash
curl -X POST localhost:8000/api/scans -H 'content-type: application/json'   -d '{"mode":"files","source_type":"folder","source_ref":"/srv/app","data_lifetime_years":20}'
curl localhost:8000/api/scans/$ID/files
curl -X POST localhost:8000/api/scans/$ID/approve -H 'content-type: application/json'   -d '{"paths":["etc/nginx/nginx.conf","app/crypto.py"]}'
```

The surface scan records path and size only — no file is opened until its path has been
approved. `folder` sources are read where they live; `github` and `docker_image` sources
are staged under `ECDAT_WORK_ROOT/{scan_id}`, image layers merged in manifest order with
whiteouts skipped. `.git` is pruned from the walk (`ECDAT_SURFACE_EXCLUDE_DIRS`): packed
objects are not deployed artefacts and would consume the file cap before a single source
file reached the approval screen.

## Collectors

Six in the finished system (`SPEC.md` §7); three built so far. The two file collectors
read only what approval put in scope; the prober reaches only hosts the scan declared.

| Collector | Reads | `source_layer` |
|---|---|---|
| `certs` | `.pem .crt .cer .der` by extension, plus any file containing a `BEGIN CERTIFICATE` block | `artifact` |
| `config` | `openssl.cnf`, `nginx.conf`, `sshd_config`, `java.security`, matched by name anywhere in the tree | `config` |
| `network` | The `{host, port}` pairs in `scan.probe_targets`, and nothing else | `live` |

Three properties are worth stating because they are enforced in one place rather than
trusted to each collector:

- **Private key material is never parsed.** A file matching `BEGIN * PRIVATE KEY` yields
  path, size and POSIX permissions, and the read stops at that header line — so a bundle
  holding a certificate above its key still reports the certificate without the key's
  bytes ever entering the process. `.p12`/`.pfx` containers are never opened at all.
  No module in the codebase calls a private key loader.
- **An unapproved path is never opened.** `ScanContext.iter_files()` is the only way a
  collector reaches the filesystem, and nginx `include` directives are deliberately not
  followed for the same reason.
- **A collector that fails costs its own findings and nothing else.** The scan comes back
  `partial` naming the collector that died, rather than failing whole or — worse —
  reporting `complete` over a hole.

The prober adds a fourth, and it is a security control rather than a nicety: **it refuses
any host not in `scan.probe_targets`**, checked at the point of connection rather than
while iterating the list, so a caller that reaches past `collect()` still cannot make it
open a socket. An unbounded prober is an attack tool. Every target attempted is logged,
refusals included.

It also stores its silences. A server that refuses TLS 1.0 and a server that never
answered are indistinguishable if you only record successes, so "offered and refused",
"unreachable" and "the scan command errored" are three different findings. A refusal
deliberately does *not* carry the TLS family — the policy engine would otherwise match it
against `tls-legacy` and report a host for rejecting TLS 1.0 as though it offered it.

`source_layer` is the distinction the drift check (§9) runs on: `config` findings are
*claims* about what a service will negotiate, and `confidence: high` on one means "the
declaration was read correctly", never "the declaration is true". `live` findings are the
facts they get compared against.

## Analysis

Collector output becomes `findings` rows through the normalizer (§8), which collapses every
observed spelling of an algorithm onto one identity using `policy/algorithm_aliases.yaml` —
`SHA-1`, `sha1`, `SHA1withRSA` and `1.3.14.3.2.26` are one row, not four. A spelling the
table does not carry keeps its own name and is stamped `identity_resolved: false`; nothing
is guessed.

The policy engine (§10) then gives every finding a verdict traceable to a published
standard. It is a pure lookup against `algorithms.yaml`, and `broken_now` and
`quantum_vulnerable` are independent classifications rather than two points on one scale —
RSA-4096 is quantum-vulnerable and perfectly secure today. Anything with no matching entry
is `unknown`, and the row still says *why* no standard is cited.

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
