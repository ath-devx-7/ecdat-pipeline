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
| 8 | Alignment check — config against handshake | done |
| 9 | Risk scorer — Mosca's inequality, in waves | done |
| 10 | Advisor — targets, parameter sets, blocker chains | done |
| 11 | Code and binary collectors — Semgrep, pyelftools | done |
| 12 | CBOM import and CycloneDX 1.6 export | done |
| 13 | React dashboard — six screens | done |
| 14 | PDF report | not started |

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

### Results endpoints

Everything the dashboard shows is a query over the analysis tables, computed on request.

| Endpoint | Does |
|---|---|
| `GET /api/policy` | The loaded pack's version, publish date, staleness, and the Mosca defaults the Z slider starts from. |
| `GET /api/scans` | Recent scans, newest first. |
| `GET /api/scans/{id}/overview` | Readiness with its denominator and the unassessed count beside it, verdict and wave counts, all four recommendation statuses, the drift status, the policy stamp. |
| `GET /api/scans/{id}/findings` | Filterable by `verdict`, `wave`, `collector`, `confidence`, `source_layer` (OR within a field, AND across), plus `q`. Each row carries its verdict with citation, its wave with the Mosca inputs and rationale, its recommendations, and the raw evidence. |
| `GET /api/scans/{id}/alignment` | The drift notes, each with the declaring config finding and the observed live finding side by side — or `skipped` with the reason. Never an empty list without one. |
| `GET /api/scans/{id}/roadmap` | Findings grouped by wave with target, prerequisites and action class. |
| `POST /api/scans/{id}/rescore` | `{"z_years": N}` — re-scores the scan against a different quantum-computer arrival assumption. The Z slider. |
| `POST /api/scans/{id}/cbom` | Imports another tool's CycloneDX 1.6 CBOM, stored byte for byte as provenance. |
| `GET /api/scans/{id}/cbom` | This scan as a CycloneDX 1.6 document, validated before it is served. |

The surface scan records path and size only — no file is opened until its path has been
approved. `folder` sources are read where they live; `github` and `docker_image` sources
are staged under `ECDAT_WORK_ROOT/{scan_id}`, image layers merged in manifest order with
whiteouts skipped. `.git` is pruned from the walk (`ECDAT_SURFACE_EXCLUDE_DIRS`): packed
objects are not deployed artefacts and would consume the file cap before a single source
file reached the approval screen.

## Dashboard — local setup

`frontend/` is React + Vite + Tailwind with Recharts, built with Node 20+.

```bash
cd frontend
npm install
npm run dev        # http://localhost:5173, proxying /api to the backend on :8000
npm test           # vitest — the file-selection logic
npm run build      # tsc + vite build into frontend/dist
```

Six screens (`SPEC.md` §13): new scan, file selection, overview, findings, drift and
roadmap. Three rules from the spec are visible on them rather than buried: the readiness
percentage states its denominator and shows the unassessed count beside it; the
recommendation tiles are always four, `no_path` and `unknown` included, because reporting
only `recommended` hides the hard part; and the drift screen shows *why* it has nothing to
show when a scan could not be compared, instead of an empty panel. Z — years until a
cryptographically relevant quantum computer — is a slider on both the new-scan and the
overview screens, defaulting to the policy pack's value, and moving it re-scores the scan.

## Collectors

All six of `SPEC.md` §7. The file collectors read only what approval put in scope; the
prober reaches only hosts the scan declared; the importer reads only what was uploaded.

| Collector | Reads | `source_layer` |
|---|---|---|
| `certs` | `.pem .crt .cer .der` by extension, plus any file containing a `BEGIN CERTIFICATE` block | `artifact` |
| `config` | `openssl.cnf`, `nginx.conf`, `sshd_config`, `java.security`, matched by name anywhere in the tree | `config` |
| `code` | Source files, through Semgrep with the local rule file `backend/semgrep_rules/crypto.yaml` — no registry, no metrics | `source` |
| `binary` | ELF files: `DT_NEEDED`, `.dynsym` and `.rodata` via pyelftools; nothing is executed | `artifact` |
| `network` | The `{host, port}` pairs in `scan.probe_targets`, and nothing else | `live` |
| `cbom_import` | An uploaded CycloneDX 1.6 document, kept byte for byte in `provenance_blobs` | `source` |

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

Between the two sits the **drift check** (§9), which is the differentiator. It compares
what a service declares against what it actually negotiated, and reports that they differ
and exactly where — never which one is wrong. A note fires per probed service rather than
per config file, so a declaration covering five services that diverges at two produces two
notes and leaves the three that agree unmentioned. Every note ends with the same sentence
declining to say whether the difference is a misconfiguration or a deliberate exception:
that judgement belongs to whoever owns the server.

Its scope guard turns on precedence, not breadth. An nginx `ssl_protocols` outside a
`server` block is a default a vhost may override, so it is not compared to one probed
vhost. An `openssl.cnf` `MinProtocol` is a floor the library enforces, so a handshake
underneath it is a contradiction nothing above it explains — and that is the demo's
headline finding. When there is nothing to compare, the result is an explicit
`{"status": "skipped", "reason": ...}`: "no drift found" and "drift never checked" are
different statements about a host.

The policy engine (§10) then gives every finding a verdict traceable to a published
standard.

Finally the **risk scorer** (§12) turns verdicts into a plan. It applies Mosca's
inequality — `(X + Y) − Z`, where X is how long the data must stay secret — but only
to confidentiality primitives, because harvest-now-decrypt-later needs something to
harvest. A signature is not harvestable: forging one in 2035 does not retroactively
forge a 2026 transaction, so X is irrelevant, `urgency_years` is null and it goes to
`wave_3`. Skipping that gate ranks a certificate's signing key as urgently as the key
exchange protecting the traffic, which would reorder an entire migration budget.

The output is waves rather than a sorted list, because a ranked list that puts a
three-year rewrite at position one is operationally useless. All three Mosca inputs
are stored on every row alongside a `rationale` object naming every factor, so any
wave can be reconstructed by an auditor. A verdict that needs no migration —
`quantum_safe`, `hygiene` — gets no wave at all rather than a reassuring one. It is a pure lookup against `algorithms.yaml`, and `broken_now` and
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
