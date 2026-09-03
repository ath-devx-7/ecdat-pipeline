# ECDAT

**Enterprise Cryptographic Discovery & Analysis Tool** — SIH 2026, problem statement SIH26164 (NTRO).

Scans a codebase, container image or live endpoint for cryptography, classifies each
finding as broken / quantum-vulnerable / safe against a cited policy pack, and produces a
**ranked migration plan** — waves, not a sorted list — with a replacement target for each
finding or the chain of prerequisites standing in its way. See [SPEC.md](SPEC.md) for the
full specification and [BUILD_PLAN.md](BUILD_PLAN.md) for the order it was built in.

The two differentiators: **drift detection** (what a configuration declares vs. what the
live server actually negotiates) and **risk ranking via Mosca's inequality**, applied only
where harvest-now-decrypt-later applies.

## Contents

- [Non-negotiable properties](#non-negotiable-properties)
- [Quick start](#quick-start)
- [Running a scan](#running-a-scan)
- [How it works](#how-it-works)
- [Collectors](#collectors)
- [API](#api)
- [Policy pack](#policy-pack)
- [Configuration](#configuration)
- [Testing](#testing)
- [Repository layout](#repository-layout)
- [Demo environment](#demo-environment)
- [Execution model](#execution-model)
- [Troubleshooting](#troubleshooting)
- [Build status](#build-status)
- [Prior art](#prior-art)

## Non-negotiable properties

- **Air-gapped.** No external network calls in the scan path — no GitHub API, no deps.dev,
  no Semgrep registry, no telemetry. The only outbound connections are cloning a repo the
  user named and probing a host the user named.
- **Never read private key material.** Key files are detected by metadata only — path,
  size, permissions. No module in the codebase calls a private key loader.
- **Never auto-remediate.** Recommend and diff; a human applies it.
- **Explicit scan scope.** No file is opened until its path has been approved, and the
  prober refuses any host not in the scan's declared targets.
- **Every verdict is cited.** The policy pack refuses to load an entry without a `source`.
  A finding no entry matches is `unknown` — never guessed, never assumed safe.

## Quick start

### Prerequisites

| Need | For |
|---|---|
| Python 3.11+ | backend |
| Node 20+ and npm | dashboard |
| PostgreSQL 16 | the real store; SQLite works for a local trial and for the tests |
| Docker with Compose | the demo lab (live TLS targets, the compiled binary) — optional |
| Git and Docker CLI on `PATH` | `github` and `docker_image` scan sources — optional |
| Pango, GObject, HarfBuzz | the PDF report — see [Troubleshooting](#troubleshooting) |

Semgrep and pyelftools are ordinary pip dependencies and come with the requirements file.

### 1. Backend

```bash
git clone https://github.com/ath-devx-7/ecdat-pipeline.git
cd ecdat-pipeline
python -m venv .venv
.venv/Scripts/python -m pip install -r backend/requirements.txt    # Windows
# source .venv/bin/activate && pip install -r backend/requirements.txt   # Linux / macOS
```

Point the backend at a database and create the schema. Postgres is the supported store for
real scans; SQLite is enough to try the tool on one machine.

For Postgres, create the role and database once (you will be asked for the `postgres`
superuser password; the role name and password below are the defaults in the URL and can be
anything as long as the URL matches):

```bash
psql -U postgres -h localhost -c "CREATE ROLE ecdat WITH LOGIN PASSWORD 'ecdat';"
psql -U postgres -h localhost -c "CREATE DATABASE ecdat OWNER ecdat;"
# Windows, if psql is not on PATH:  & "C:\Program Files\PostgreSQL\18\bin\psql.exe" -U postgres -h localhost -c "..."
```

```bash
cd backend
export ECDAT_DATABASE_URL="postgresql+psycopg://ecdat:ecdat@localhost:5432/ecdat"   # bash
# or, for a local trial:  export ECDAT_DATABASE_URL="sqlite+pysqlite:///ecdat.sqlite"
alembic upgrade head
```

```powershell
cd backend
$env:ECDAT_DATABASE_URL = "postgresql+psycopg://ecdat:ecdat@localhost:5432/ecdat"   # PowerShell
alembic upgrade head
```

Either form lasts for that terminal session. Settings can also live in `backend/.env`
(ignored by git), one `ECDAT_...=value` per line, which the backend reads on every start.

Start the API:

```bash
uvicorn app.main:app --reload        # http://127.0.0.1:8000/docs
```

The policy pack loads on startup, before the first request is served. A pack that fails
validation — an entry without a citation, a condition the engine cannot evaluate — stops
the process there rather than answering with uncited verdicts later.

### 2. Dashboard

```bash
cd frontend
npm install
npm run dev                          # http://localhost:5173
```

The dev server proxies `/api` to the backend on port 8000 (set `ECDAT_API` to point it
elsewhere). For a deployment, `npm run build` writes static files to `frontend/dist`; serve
them from any web server with `/api` reverse-proxied to uvicorn.

### 3. Demo lab (optional, recommended for a first run)

```bash
docker compose -f demo/docker-compose.yml up --build
```

This builds six images and generates the demo certificates. It publishes three services:
`localhost:8443` (nginx accepting TLS 1.0 with an RSA-1024 SHA-1 certificate — the drift
target), `localhost:8444` (nginx on TLS 1.3 only with ECDSA — the clean host) and
`localhost:8081` (the weak Python service). Without Docker, `./demo/gen_certs.sh` generates
the certificates alone and a `files` scan of `demo/` still exercises every file collector.

### 4. Your first scan

Open http://localhost:5173 and:

1. **New scan.** Choose *Files and probe*, source type *Local folder*, path
   `/absolute/path/to/ecdat-pipeline/demo`, probe targets `localhost:8443` and
   `localhost:8444`, data lifetime *20+ years*. Leave Z at the policy default.
2. **File selection.** *Select all*, then *Approve and scan*. The request blocks while the
   collectors run — a few seconds for the demo tree.
3. **Overview.** Readiness with its denominator, all four recommendation statuses, verdicts,
   waves, drift, policy stamp. Drag the Z slider to see the waves move.
4. **Findings.** Filter by verdict, wave, collector, confidence or layer; click a row for
   the verdict's citation, the Mosca inputs, the recommendation chain and raw evidence.
5. **Drift.** The weak host's `openssl.cnf` declares a TLS 1.2 floor and the server accepts
   TLS 1.0, side by side, with the note that reports the difference without judging it.
6. **Roadmap.** Findings by wave, each with target, prerequisites and action class.

From the overview, *PDF report* downloads the report, *Export CycloneDX* the CBOM, and
*Import CBOM* accepts another tool's inventory — try `demo/sample_cbom.json`.

`demo/README.md` lists what every demo target must produce and, as much to the point, what
must **not** be flagged.

## Running a scan

The same flow from the command line. Scan creation and approval block until done (§2).

```bash
# 1. Create a scan — stages the source and enumerates it, nothing is read yet
ID=$(curl -s -X POST localhost:8000/api/scans -H 'content-type: application/json' -d '{
  "mode": "files_and_probe",
  "source_type": "folder",
  "source_ref": "/absolute/path/to/ecdat-pipeline/demo",
  "probe_targets": [{"host": "localhost", "port": 8443}, {"host": "localhost", "port": 8444}],
  "data_lifetime_years": 20
}' | python -c 'import json,sys; print(json.load(sys.stdin)["id"])')

# 2. See the file tree, then approve exactly the paths the collectors may open
curl -s localhost:8000/api/scans/$ID/files
curl -s -X POST localhost:8000/api/scans/$ID/approve -H 'content-type: application/json' \
  -d '{"paths": ["weak-nginx/nginx.conf", "weak-nginx/openssl.cnf", "pyapp/app.py"]}'

# 3. Read the results
curl -s localhost:8000/api/scans/$ID/overview
curl -s "localhost:8000/api/scans/$ID/findings?verdict=broken_now&collector=code"
curl -s localhost:8000/api/scans/$ID/alignment
curl -s localhost:8000/api/scans/$ID/roadmap

# 4. Test the plan against a sooner quantum computer
curl -s -X POST localhost:8000/api/scans/$ID/rescore -H 'content-type: application/json' -d '{"z_years": 5}'

# 5. Add another tool's inventory, export, report
curl -s -X POST localhost:8000/api/scans/$ID/cbom -H 'content-type: application/json' \
  -H 'x-filename: sample_cbom.json' --data-binary @demo/sample_cbom.json
curl -s localhost:8000/api/scans/$ID/cbom        -o ecdat-$ID.cdx.json
curl -s localhost:8000/api/scans/$ID/report.pdf  -o ecdat-$ID.pdf
```

Scan modes: `files` (a folder, a git URL or a Docker image tag), `probe_only` (host:port
targets, no files, runs immediately with no approval step) and `files_and_probe` (both —
the only mode in which drift detection has anything to compare). Data lifetime is X in
Mosca's inequality: how long the data this system protects must stay confidential.

`folder` sources are read where they live and never copied. `github` sources are cloned
with `--depth 1` under `ECDAT_WORK_ROOT/{scan_id}`; `docker_image` sources are `docker save`d
and their layers merged in manifest order, whiteouts skipped. `.git` is pruned from the
surface scan: packed objects are not deployed artefacts and would consume the file cap
before a single source file reached the approval screen.

## How it works

```
POST /scans  →  stage  →  surface scan  →  approve  →  collect  →  normalize
             →  align (drift)  →  policy engine  →  risk scorer + advisor  →  results
```

**Collectors** observe and report what they saw, in the artefact's own words. They never
judge. Six of them — see [Collectors](#collectors).

**Normalizer** (§8) collapses every observed spelling of an algorithm onto one identity
using `policy/algorithm_aliases.yaml`: `SHA-1`, `sha1`, `SHA1withRSA` and `1.3.14.3.2.26`
are one row, not four. A spelling the table does not carry keeps its own name and is stamped
`identity_resolved: false`; nothing is guessed. Every finding carries a `source_layer` —
`live`, `artifact`, `config`, `source` — ordered by closeness to execution.

**Drift check** (§9) — the differentiator. It compares what a configuration declares against
what the probed service negotiated, per service, and reports that they differ and exactly
where, never which one is wrong. Every note ends with the same sentence declining to say
whether the difference is a misconfiguration or a deliberate exception; that judgement
belongs to whoever owns the server. Its scope guard turns on precedence: an nginx
`ssl_protocols` outside a `server` block is a default a vhost may override and is not
compared to one probed vhost; an `openssl.cnf` `MinProtocol` is a floor the library
enforces, so a handshake underneath it is a contradiction nothing above it explains — the
demo's headline finding. When there is nothing to compare the result is an explicit
`{"status": "skipped", "reason": ...}`: "no drift found" and "drift never checked" are
different statements about a host.

**Policy engine** (§10) gives every finding a verdict by lookup against `algorithms.yaml`,
each traceable to a published standard. `broken_now` and `quantum_vulnerable` are
independent classifications, not two points on one scale: RSA-4096 is quantum-vulnerable
and perfectly secure today; MD5 is broken today and irrelevant to quantum. AES and SHA-256
are `quantum_safe` — Grover weakens symmetric crypto, it does not break it.

**Risk scorer** (§12) applies Mosca's inequality, `(X + Y) − Z`, where X is the data
lifetime, Y the migration duration and Z the years until a cryptographically relevant
quantum computer — but only to confidentiality primitives, because harvest-now-decrypt-later
needs something to harvest. A signature is not harvestable: forging one in 2035 does not
retroactively forge a 2026 transaction, so X is irrelevant, `urgency_years` is null and it
goes to wave 3. The output is waves rather than a sorted list, because a ranked list that
puts a three-year rewrite at position one is operationally useless:

| Wave | Members |
|---|---|
| `wave_0` | Broken today. A now deadline, not a quantum one. |
| `wave_1` | Overdue under Mosca and reachable by a config change or library upgrade. |
| `wave_2` | Overdue, but a code change or hardware swap — needs budgeting, not deferring. |
| `wave_3` | Quantum-vulnerable but not overdue at this data lifetime, or an authentication primitive. |
| `verify` | Low-confidence observations and unclassified algorithms. Confirm before planning. |

Every input and every factor is stored on the row so an auditor can reconstruct any wave.
Z is exposed as a slider: it is an assumption, and testing a plan against a sooner arrival
is more honest than hardcoding one date.

**Advisor** (§11) picks a replacement target by primitive plus family — RSA maps to ML-KEM
for key exchange and ML-DSA for signatures — selects the parameter set from the data
lifetime, tests each prerequisite against what the collectors observed on that asset, and
applies the pack's hybrid preference. Four statuses, all always shown: `recommended`,
`blocked` (with the ordered prerequisite chain — "upgrade OpenSSL, then enable TLS 1.3,
then adopt ML-KEM" is a work plan where "adopt ML-KEM" is a wish), `no_path` (a
compensating control from the pack) and `unknown` (no rule matched; no generic target is
guessed). A prerequisite nothing observed is not presumed met.

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

Three properties are enforced in one place rather than trusted to each collector:

- **Private key material is never parsed.** A file matching `BEGIN * PRIVATE KEY` yields
  path, size and POSIX permissions, and the read stops at that header line — so a bundle
  holding a certificate above its key still reports the certificate without the key's
  bytes ever entering the process. `.p12`/`.pfx` containers are never opened at all. A
  CBOM's `value` field for key material is never copied into a finding.
- **An unapproved path is never opened.** `ScanContext.iter_files()` is the only way a
  collector reaches the filesystem, and nginx `include` directives are deliberately not
  followed for the same reason.
- **A collector that fails costs its own findings and nothing else.** The scan comes back
  `partial` naming the collector that died — or, when Semgrep runs out of memory on one
  file, keeps everything it found and still reports `partial` — rather than failing whole
  or reporting `complete` over a hole.

The prober adds a fourth, and it is a security control: **it refuses any host not in
`scan.probe_targets`**, checked at the point of connection rather than while iterating the
list. An unbounded prober is an attack tool. Every target attempted is logged, refusals
included. It also stores its silences: "offered and refused", "unreachable" and "the scan
command errored" are three different findings, because a server that refuses TLS 1.0 and a
server that never answered are indistinguishable if you record only successes.

## API

Interactive documentation is at http://127.0.0.1:8000/docs when the backend is running.

### Intake

| Endpoint | Does |
|---|---|
| `POST /api/scans` | Creates the scan, stamps the policy version, stages the source and enumerates it. Ends `awaiting_approval` — `probe_only` stages nothing and runs immediately. |
| `GET /api/scans` | Recent scans, newest first. |
| `GET /api/scans/{id}` | The scan row. |
| `GET /api/scans/{id}/files` | The surface scan as a nested tree with per-directory counts and sizes. Path and size only — nothing has been read. |
| `POST /api/scans/{id}/approve` | The permission gate and the run it releases. Approval is set to *exactly* the submitted path list. Blocks until every collector has finished, then returns `complete` or `partial` with a per-collector breakdown and the analysis counts. |

### Results

Everything the dashboard shows is a query over the analysis tables, computed on request.

| Endpoint | Does |
|---|---|
| `GET /api/health` | Liveness plus the policy stamp. |
| `GET /api/policy` | The loaded pack's version, publish date, staleness, and the Mosca defaults the Z slider starts from. |
| `GET /api/scans/{id}/overview` | Readiness with its denominator and the unassessed count beside it, verdict and wave counts, all four recommendation statuses, drift status, policy stamp. |
| `GET /api/scans/{id}/findings` | Filterable by `verdict`, `wave`, `collector`, `confidence`, `source_layer` (OR within a field, AND across), plus `q`, `offset`, `limit`. Each row carries its verdict with citation, its wave with the Mosca inputs and rationale, its recommendations, and the raw evidence. |
| `GET /api/scans/{id}/findings/{fid}` | One finding with everything the analysis said about it. |
| `GET /api/scans/{id}/alignment` | The drift notes, each with the declaring config finding and the observed live finding side by side — or `skipped` with the reason. |
| `GET /api/scans/{id}/roadmap` | Findings grouped by wave with target, prerequisites and action class. |
| `POST /api/scans/{id}/rescore` | `{"z_years": N}` — re-scores the scan against a different arrival assumption. |
| `POST /api/scans/{id}/cbom` | Imports a CycloneDX 1.6 CBOM (request body is the document), stored byte for byte as provenance, then re-runs the analysis. |
| `GET /api/scans/{id}/cbom` | This scan as a CycloneDX 1.6 document, generated from a query and validated before it is served. |
| `GET /api/scans/{id}/report.pdf` | The report: scan and policy, executive summary, findings by wave, drift, blocked prerequisites, unknown findings, methodology with every standard cited. |
| `GET /api/scans/{id}/report.html` | The same document before WeasyPrint renders it — and the fallback when it cannot. |

## Policy pack

`backend/policy/` holds five YAML files, loaded **read-only** at startup:

| File | Holds |
|---|---|
| `version.yaml` | Pack version and publish date; `z_years_default`, `y_years_default`, `staleness_warning_days` |
| `algorithms.yaml` | The verdict rules — family, primitive, conditions, verdict, citation |
| `pqc_targets.yaml` | Migration targets with prerequisites, action classes and the hybrid preference; the parameter-set rule by data lifetime |
| `algorithm_aliases.yaml` | Every observed spelling of an algorithm → canonical family and OID, each entry cited |
| `named_groups.yaml` | TLS named-group code points, including the hybrid PQC groups |

Nothing writes back to them and no API endpoint exposes them for editing. Every entry in
`algorithms.yaml`, `pqc_targets.yaml` and the alias table must carry a `source` citation;
the loader refuses to start otherwise, naming the offending entry. A condition key or a
`requires` clause the engine cannot evaluate is also refused at startup — a typo there
would not fail, it would silently widen a rule or drop a prerequisite.

Closing a gap is a policy edit with a citation, not a code change. `demo/README.md` lists
the gaps the shipped pack deliberately leaves open. Each scan stamps the pack version, and
because an air-gapped install cannot fetch updates, a pack older than
`staleness_warning_days` raises a warning at startup and a banner in the dashboard: a human
has to carry a newer pack in deliberately.

## Configuration

All settings are environment variables prefixed `ECDAT_`, or lines in `backend/.env`.

| Variable | Default | Meaning |
|---|---|---|
| `ECDAT_DATABASE_URL` | `postgresql+psycopg://ecdat:ecdat@localhost:5432/ecdat` | SQLAlchemy URL. SQLite works for a trial and the tests. |
| `ECDAT_POLICY_DIR` | `backend/policy` | The policy pack. |
| `ECDAT_MAX_FILES_PER_SCAN` | `5000` | A source over this is rejected at creation. |
| `ECDAT_COLLECTOR_TIMEOUT_SECONDS` | `120` | Per-collector budget; exceeding it costs that collector, not the scan. |
| `ECDAT_SCAN_TIMEOUT_SECONDS` | `600` | Per-scan budget. |
| `ECDAT_MAX_PROBE_TARGETS` | `20` | Probe targets per scan. |
| `ECDAT_PROBE_TIMEOUT_SECONDS` | `10` | Network timeout per target handed to sslyze. |
| `ECDAT_WORK_ROOT` | `/tmp/ecdat` | Where cloned repos and unpacked images land. |
| `ECDAT_GIT_CLONE_TIMEOUT_SECONDS` | `300` | |
| `ECDAT_DOCKER_SAVE_TIMEOUT_SECONDS` | `600` | |
| `ECDAT_SEMGREP_RULES_PATH` | `backend/semgrep_rules/crypto.yaml` | The only rule set Semgrep is given. |
| `ECDAT_SEMGREP_MAX_MEMORY_MB` | `2000` | `--max-memory`. |
| `ECDAT_SEMGREP_EXECUTABLE` | *(the one beside the interpreter, then `PATH`)* | Override. |
| `ECDAT_WEASYPRINT_DLL_DIRECTORIES` | *(unset)* | Directory holding Pango/GObject DLLs when they are not on the loader path. |
| `ECDAT_SURFACE_EXCLUDE_DIRS` | `[".git"]` | Directory names pruned from the surface scan, as a JSON list — e.g. `'[".git", "node_modules", ".venv"]'`. Excluding vendored dependencies hides any crypto they ship, so it is a choice, not the default. |

## Testing

```bash
cd backend
../.venv/Scripts/python -m pytest                  # Windows; `pytest` inside an activated venv elsewhere
../.venv/Scripts/python -m pytest --cov=app        # with coverage (pytest-cov is in the requirements)
cd ../frontend && npm test                          # vitest — the file-selection logic
npm run typecheck && npm run build
```

The suite runs on SQLite with no database server: 330-odd tests over every step, including
the checks `SPEC.md` §16 requires — AES-256 and SHA-256 never quantum-vulnerable, RSA-4096
quantum-vulnerable but not broken, RSA-1024 broken, signatures in wave 3 with no urgency,
identity resolution, the prober's refusal, private keys never parsed, unapproved paths
never opened, alignment skipped in `probe_only`, the exported CycloneDX validating against
the 1.6 schema, and an uncited policy entry refused.

Some tests depend on the environment and skip with a message when it is absent:

- the live-lab probes of `localhost:8443` and `8444` need the Docker demo running;
- the compiled-binary demo test needs `demo/cbin/build/cryptodemo`, which the compose
  stack produces (a committed copy under `backend/tests/data/` covers the collector itself);
- the world-readable key-file test needs a POSIX file mode, which NTFS does not carry;
- the PDF tests need WeasyPrint's native libraries.

The demo scan fixture does real Semgrep runs, so a full suite takes a few minutes.

## Repository layout

```
backend/
  app/
    api/            scans.py (intake, CBOM, report)  findings.py (results)
    collectors/     base, certs, config, code, binary, binary_yara (stub), network, cbom_import
    core/           normalizer, alignment, policy, advisor, risk, policy_loader
    export/         cyclonedx.py, pdf.py, templates/report.html
    intake/         stage (folder / git / image), surface (enumeration), selection (approval)
    models/         the eight tables            schemas/   request and response bodies
    runner.py       one scan end to end         startup.py, config.py, db.py, main.py
  policy/           the five YAML files, read-only at runtime
  semgrep_rules/    crypto.yaml
  alembic/          migrations
  tests/            one module per step, plus committed fixtures under tests/data/
frontend/           React + Vite + Tailwind + Recharts; src/pages holds the six screens
demo/               the deliberately weak targets and their compose file; demo/README.md
SPEC.md             what to build         BUILD_PLAN.md   in what order
```

## Demo environment

`demo/` holds the deliberately weak targets everything from step 4 onwards is tested
against — you cannot test a certificate parser without a bad certificate, or a drift check
without a server that contradicts its own config. Everything in it is broken on purpose
except `nginx-strong`, which is correct on purpose: the report needs green as well as red,
and the uncomfortable third case of a host that is hygienically perfect and still
quantum-vulnerable.

| Target | What it is for |
|---|---|
| `weak-nginx` (8443) | TLS 1.0/1.1/1.2 with an `openssl.cnf` that declares a TLS 1.2 floor and is never activated — the drift demo |
| `strong-nginx` (8444) | TLS 1.3 only, ECDSA P-256 — zero notes, still quantum-vulnerable |
| `pyapp`, `javaapp` | MD5, SHA-1, RSA-1024, DES/3DES, ECB, hardcoded keys — the code-scan targets |
| `oldssl`, `cbin` | OpenSSL 1.1.1 and a binary linked against it — what makes ML-KEM come back `blocked` |
| `certs/` | RSA-1024 SHA-1, ECDSA, expiring, a PKCS#12 bundle — generated, never committed |
| `sshd/sshd_config` | Weak SSH algorithm lists, with no live counterpart — must produce no drift note |
| `sample_cbom.json` | A CycloneDX 1.6 inventory from a stand-in external tool — the import path |

```bash
./demo/gen_certs.sh                                  # certificates only, no Docker
docker compose -f demo/docker-compose.yml up --build # the full lab
docker compose -f demo/docker-compose.yml down -v    # tear it down
```

Every deliberate weakness carries an `ECDAT-EXPECT:` marker on the line a collector should
anchor to, and the tests assert against the markers rather than line numbers.

## Execution model

**Scans run synchronously** — creation and approval block until done. This is a deliberate
prototype simplification, guarded by the file cap, the per-collector and per-scan timeouts
and the probe-target cap above. **Async workers (Celery + Redis) are the production path.**
The runner's collector loop is a plain `for collector in collectors`, so swapping it for a
queue touches no collector code.

## Troubleshooting

- **`semgrep is not installed`** — it is a pip requirement; check it installed into the same
  environment as the backend, or set `ECDAT_SEMGREP_EXECUTABLE`. Semgrep runs with
  `--metrics=off` and never fetches a registry ruleset.
- **`report.pdf` answers 503** — WeasyPrint's native libraries are missing. On Debian/Ubuntu:
  `apt install libpango-1.0-0 libpangoft2-1.0-0`. On Windows: the GTK3 runtime, or MSYS2's
  `mingw-w64-ucrt-x86_64-pango`, then `ECDAT_WEASYPRINT_DLL_DIRECTORIES` pointing at the
  `bin` directory holding the DLLs. `report.html` serves the report meanwhile.
- **A small repository is rejected for exceeding the 5000-file cap** — it almost always
  commits `node_modules`, a virtualenv or a build directory; the error names the heaviest
  directories. Exclude them with `ECDAT_SURFACE_EXCLUDE_DIRS` (knowing that vendored
  dependencies then go unscanned), scan a narrower path, or raise
  `ECDAT_MAX_FILES_PER_SCAN`.
- **The lab's image builds fail with `dial tcp 192.0.2.1:443`** — a DNS resolver is
  blackholing the registry; `demo/README.md` explains the check.
- **The drift test skips** — it needs both `localhost:8443` and `8444` reachable; bring the
  compose stack up.
- **Three drift notes instead of one on the demo** — both hosts' configs were approved in
  one scan, so the strong host's TLS 1.3 floor is also held against the weak host. Nothing
  infers which config governs which host (§9); scope the scan to one host's files to see the
  single note the demo README describes.
- **The world-readable key finding does not appear on Windows** — NTFS carries no POSIX
  mode, so the collector records permissions as unavailable rather than inventing `0644`.

## Build status

Built one step at a time per `BUILD_PLAN.md`. All fourteen steps are done.

| Step | Component |
|---|---|
| 1 | DB schema, Alembic, policy loader |
| 2 | Intake — staging, surface scan, approval gate |
| 3 | Demo environment — targets to scan |
| 4 | Certificate and config collectors |
| 5 | Normalizer — canonical identities, source layers |
| 6 | Policy engine — a cited verdict per finding |
| 7 | Network probe — live TLS observation |
| 8 | Alignment check — config against handshake |
| 9 | Risk scorer — Mosca's inequality, in waves |
| 10 | Advisor — targets, parameter sets, blocker chains |
| 11 | Code and binary collectors — Semgrep, pyelftools |
| 12 | CBOM import and CycloneDX 1.6 export |
| 13 | React dashboard — six screens |
| 14 | PDF report |

## Prior art

CBOMkit (PQCA / Linux Foundation) already does source and container scanning with a
CycloneDX store. SandboxAQ AQtive Guard and Keyfactor do live network discovery and risk
prioritisation commercially. ECDAT's claim is the **deployment model** — open source,
self-hostable, fully air-gapped, auditable — combined with drift detection and Mosca-based
ranking. The CBOM import path exists so CBOMkit is an input rather than a competitor.
