# ECDAT — Build Specification

**Enterprise Cryptographic Discovery & Analysis Tool**
Smart India Hackathon 2026 · Problem Statement SIH26164 · NTRO

---

## 1. What this is

A self-hosted tool that scans a codebase, container image, or live endpoint to find every use of cryptography, classifies each finding as broken / quantum-vulnerable / safe, recommends replacements, and produces a **ranked migration plan** rather than a flat list of problems.

The differentiator is not detection. It is two things nothing else does together:

1. **Drift detection** — compare what config files declare against what a live server actually negotiates.
2. **Risk ranking via Mosca's inequality** — order findings by real urgency, not by algorithm name.

Everything else exists to feed those two.

### Non-negotiable properties

- **Air-gapped.** No external network calls anywhere in the scan path. No GitHub API for metadata, no deps.dev, no telemetry. The only outbound connections are: cloning a repo the user explicitly gave us, and probing a host the user explicitly gave us.
- **Never read private key material.** Detect key files by metadata (path, size, permissions) only. Never load private key bytes into memory. This is a hard rule, not a preference.
- **Never auto-remediate.** Recommend and show a diff. A human applies it.
- **Explicit scan scope.** The prober refuses any host not in the scan's declared target list.

---

## 2. Stack

| Layer | Choice |
|---|---|
| Backend | Python 3.11+, FastAPI |
| DB | PostgreSQL 16 |
| ORM | SQLAlchemy 2.x + Alembic |
| Frontend | React + Vite, Tailwind |
| Charts | Recharts |
| PDF | WeasyPrint (HTML → PDF) |
| CBOM | `cyclonedx-python-lib` |
| Packaging | Docker Compose |

### Execution model

**Scans run synchronously** — the POST request blocks until the scan completes.

This is a deliberate prototype simplification. Guard it:

- Hard cap on files per scan (default 5000) — reject with a clear error above it.
- Per-collector timeout (default 120s), per-scan timeout (default 600s).
- Cap probe targets per scan (default 20 host:port pairs).
- Return partial results with `status: partial` if a collector times out — never fail the whole scan because one collector hung.

Note in the README that async workers (Celery + Redis) are the production path. Structure `ScanRunner` so the collector loop could be swapped to a queue without touching collector code.

---

## 3. Repository layout

```
ecdat/
├── backend/
│   ├── app/
│   │   ├── main.py                 FastAPI app, router mounting
│   │   ├── config.py               settings via pydantic-settings
│   │   ├── db.py                   engine, session
│   │   ├── models/                 SQLAlchemy models
│   │   ├── schemas/                pydantic request/response
│   │   ├── api/
│   │   │   ├── scans.py
│   │   │   ├── findings.py
│   │   │   ├── reports.py
│   │   │   └── policy.py
│   │   ├── intake/
│   │   │   ├── stage.py            folder / repo / image → directory
│   │   │   ├── surface.py          file enumeration
│   │   │   └── selection.py        permission gate
│   │   ├── collectors/
│   │   │   ├── base.py             Collector ABC
│   │   │   ├── code.py             Semgrep
│   │   │   ├── binary.py           pyelftools
│   │   │   ├── certs.py            cryptography lib
│   │   │   ├── config.py           format parsers
│   │   │   ├── network.py          sslyze
│   │   │   └── cbom_import.py      CycloneDX in
│   │   ├── core/
│   │   │   ├── normalizer.py
│   │   │   ├── alignment.py
│   │   │   ├── policy.py
│   │   │   ├── advisor.py
│   │   │   └── risk.py
│   │   ├── export/
│   │   │   ├── cyclonedx.py
│   │   │   └── pdf.py
│   │   └── runner.py               orchestrates a scan end to end
│   ├── policy/                     versioned YAML — see §6
│   ├── semgrep_rules/              custom crypto rules
│   ├── tests/
│   └── alembic/
├── frontend/
├── demo/                           deliberately weak targets — see §13
├── docker-compose.yml
└── README.md
```

---

## 4. Scan lifecycle

```
1. POST /api/scans                 create scan, mode + inputs + data_lifetime
2. Stage                           folder / clone / unpack image → work dir
3. Surface scan                    enumerate every file, no parsing
4. GET  /api/scans/{id}/files      return file tree to UI
5. POST /api/scans/{id}/approve    user submits approved path list
6. Run collectors                  approved paths + probe targets only
7. Normalize                       all collector output → findings table
8. Alignment check                 live vs config, per usage site
9. Policy engine                   verdict + primitive per finding
10. Advisor + Risk scorer          parallel; recommendations + waves
11. GET results                    dashboard / CycloneDX / PDF
```

### Scan modes

- **`probe_only`** — one or more `host:port` targets. Steps 2–6 skipped entirely except the network collector. Alignment check is a **no-op**; the API must return `alignment: {status: "skipped", reason: "no config findings to compare"}` so the UI can say so explicitly rather than showing an empty panel.
- **`files`** — folder / repo / image upload. Full flow, no probe.
- **`files_and_probe`** — both. This is the only mode where alignment produces output.

Probe host is **entered explicitly by the user**. Never inferred from scanned files. (Inference is a roadmap item.)

---

## 5. Data model

Seven tables. Findings and assets are observations; algorithms and pqc_targets are loaded read-only from YAML at startup.

### `scans`
| column | type | notes |
|---|---|---|
| id | uuid PK | |
| mode | enum | probe_only \| files \| files_and_probe |
| source_type | enum | folder \| github \| docker_image \| none |
| source_ref | text | path, repo URL, or image tag |
| probe_targets | jsonb | list of `{host, port}` |
| data_lifetime_years | int | X in Mosca — from intake form |
| policy_version | text | stamped from loaded YAML |
| status | enum | staging \| awaiting_approval \| running \| complete \| partial \| failed |
| file_count | int | |
| approved_count | int | |
| created_at, completed_at | timestamptz | |

### `scan_files`
Surface-scan output, presented to the UI for approval.

| column | type | notes |
|---|---|---|
| id, scan_id | | |
| path | text | relative to work dir |
| size_bytes | bigint | |
| approved | bool | default false |

### `findings`
The core table. One row per observed crypto use.

| column | type | notes |
|---|---|---|
| id, scan_id | | |
| collector | enum | code \| binary \| certs \| config \| network \| cbom_import |
| algorithm_name | text | as observed |
| algorithm_oid | text | resolved by normalizer, nullable |
| algorithm_family | text | RSA, AES, SHA, ECDSA… |
| primitive | enum | key_exchange \| signature \| hash \| cipher \| protocol \| unknown |
| key_size | int | nullable |
| mode | text | GCM, ECB, CBC — nullable |
| protocol_version | text | TLS 1.0 etc — nullable |
| evidence_location | text | `path:line` or `host:port` |
| evidence_raw | jsonb | original collector output for this finding |
| confidence | enum | high \| medium \| low |
| source_layer | enum | live \| artifact \| config \| source — see §8 |
| created_at | timestamptz | |

### `alignment_notes`
| column | type | notes |
|---|---|---|
| id, scan_id | | |
| live_finding_id | fk findings | |
| config_finding_id | fk findings | |
| asset_key | text | what matched them — see §8 |
| note | text | human-readable divergence description |

### `verdicts`
| column | type |
|---|---|
| id, finding_id | |
| verdict | enum: broken_now \| quantum_vulnerable \| quantum_safe \| hygiene \| unknown |
| rule_id | text — which YAML entry fired |
| source_citation | text — e.g. "NIST SP 800-131A Rev.2" |
| policy_version | text |

### `recommendations`
| column | type |
|---|---|
| id, finding_id | |
| status | enum: recommended \| blocked \| no_path \| unknown |
| target | text — e.g. ML-KEM-768, nullable |
| hybrid_target | text, nullable |
| action_class | enum: config \| library_upgrade \| code_change \| hardware |
| prerequisites | jsonb — ordered list of unmet requirements |
| side_effects | text, nullable |
| source_citation | text |

### `risk_scores`
| column | type |
|---|---|
| id, finding_id | |
| x_years, y_years, z_years | int — the three Mosca inputs, stored for auditability |
| urgency_years | int — (X + Y) − Z, null for authentication primitives |
| wave | enum: wave_0 \| wave_1 \| wave_2 \| wave_3 \| verify |
| rationale | jsonb — every factor that produced the wave |

**Store the inputs, not just the output.** An auditor must be able to reconstruct any wave assignment from the row.

---

## 6. Policy files

Live in `backend/policy/`, versioned in git, loaded **read-only** into Postgres at startup. No API endpoint writes to them. Every entry carries a `source` citation — reject any entry without one at load time.

### `policy/version.yaml`
```yaml
version: "2026.09"
published: "2026-09-01"
z_years_default: 12       # years until a cryptographically relevant quantum computer
y_years_default: 1        # default migration duration
staleness_warning_days: 180
```

### `policy/algorithms.yaml`
```yaml
entries:
  - id: md5-hash
    family: MD5
    oid: "1.2.840.113549.2.5"
    primitive: hash
    verdict: broken_now
    source: "NIST SP 800-131A Rev.2"

  - id: sha1-signature
    family: SHA-1
    primitive: signature
    verdict: broken_now
    source: "NIST SP 800-131A Rev.2"

  - id: rsa-weak-key
    family: RSA
    condition: { key_size_lt: 2048 }
    verdict: broken_now
    source: "NIST SP 800-131A Rev.2"

  - id: rsa-quantum
    family: RSA
    primitive: [key_exchange, signature]
    verdict: quantum_vulnerable
    source: "NIST IR 8547"

  - id: ecc-quantum
    family: [ECDSA, ECDH, EdDSA]
    verdict: quantum_vulnerable
    source: "NIST IR 8547"

  - id: aes-safe
    family: AES
    condition: { key_size_gte: 128 }
    verdict: quantum_safe
    source: "NIST IR 8547"

  - id: aes-ecb
    family: AES
    condition: { mode: ECB }
    verdict: broken_now
    source: "OWASP Cryptographic Storage Cheat Sheet"

  - id: tls-legacy
    family: TLS
    condition: { protocol_version_lt: "1.2" }
    verdict: broken_now
    source: "RFC 8996"
```

**Critical:** AES and SHA-256 must resolve to `quantum_safe`, never `quantum_vulnerable`. Grover's algorithm weakens symmetric crypto but does not break it. Add a unit test asserting this — a tool that flags AES as quantum-vulnerable is wrong in a way a cryptographer spots in thirty seconds.

Anything with no matching entry → `verdict: unknown`. Never guess.

### `policy/pqc_targets.yaml`
```yaml
prefer_hybrid: true
targets:
  - id: kex-to-mlkem
    match: { primitive: key_exchange, family: [RSA, ECDH, DH] }
    target: ML-KEM-768
    hybrid: X25519MLKEM768
    requires:
      protocol_min: "TLS 1.3"
      library: "openssl>=3.5"
    action_class: config
    source: "NIST FIPS 203"

  - id: sig-to-mldsa
    match: { primitive: signature, family: [RSA, ECDSA, EdDSA] }
    target: ML-DSA-65
    requires:
      library: "openssl>=3.5"
    action_class: library_upgrade
    side_effects: "ML-DSA signatures ~2.4 KB vs ~64 B for ECDSA. Check cert chains and constrained devices."
    source: "NIST FIPS 204"

  - id: sig-longlived-root
    match: { primitive: signature, asset_lifetime_gt: 10 }
    target: SLH-DSA-SHA2-128s
    action_class: hardware
    note: "Hash-based fallback for long-lived roots of trust."
    source: "NIST FIPS 205"

  - id: hash-upgrade
    match: { primitive: hash, family: [MD5, SHA-1] }
    target: SHA-256
    action_class: code_change
    source: "NIST SP 800-131A Rev.2"

  - id: cipher-upgrade
    match: { primitive: cipher, family: [DES, 3DES, RC4] }
    target: AES-256-GCM
    action_class: code_change
    source: "NIST SP 800-131A Rev.2"
```

### Staleness

Every scan stamps `policy_version`. Dashboard shows the version and its publish date, and displays a warning banner when older than `staleness_warning_days`. This matters because an air-gapped install cannot fetch updates — a human must carry the policy pack in deliberately.

---

## 7. Collectors

All six are built. Common interface:

```python
class Collector(ABC):
    name: str
    @abstractmethod
    def collect(self, ctx: ScanContext) -> list[RawFinding]: ...
```

`ScanContext` carries: work dir, approved file paths, probe targets, timeouts. A collector that raises returns an empty list and marks the scan `partial` — never kills the run.

### 7.1 Code scan — Semgrep

Run Semgrep over approved paths only, with `--json`. Ship custom rules in `semgrep_rules/crypto.yaml` plus pull relevant public rules.

Detect:
- Weak hashes: `hashlib.md5(...)`, `hashlib.sha1(...)`, Java `MessageDigest.getInstance("MD5")`
- Weak ciphers: DES, 3DES, RC4 constructors
- ECB mode: `Cipher($ALGO, modes.ECB(...), ...)` — capture `$ALGO` as a metavariable so the finding records which algorithm
- Weak key sizes using `metavariable-comparison`:
  ```yaml
  patterns:
    - pattern: rsa.generate_private_key(..., key_size=$N, ...)
    - metavariable-comparison:
        metavariable: $N
        comparison: $N < 2048
  ```
- Hardcoded key material: byte-string literals passed to `algorithms.AES(...)`
- High-entropy string literals (Shannon entropy > 4.5, length > 20)

Map Semgrep's `path` + `start.line` → `evidence_location`. `confidence: high`. `source_layer: source`.

### 7.2 Binary scan — pyelftools

For each approved file, sniff the ELF magic (`\x7fELF`). Skip non-ELF silently.

Extract:
- **Dynamic dependencies** (`DT_NEEDED`) → `libcrypto.so.3` means OpenSSL 3.x present. This drives the advisor's `requires` check.
- **Dynamic symbols** → `MD5_Init`, `RSA_generate_key`, `EVP_sha1` etc. Maintain a symbol→algorithm map.
- **Strings** in `.rodata` matching known cipher suite or algorithm names.

`confidence`: `high` for symbols and dependencies (proves capability), `medium` for strings. `source_layer: artifact`.

**YARA is out of scope for the prototype.** Leave a `binary_yara.py` stub implementing `Collector` that returns `[]`, so the plugin interface visibly supports it.

### 7.3 Certificates — `cryptography`

Walk approved paths. Identify candidates by extension (`.pem .crt .cer .der .p12 .pfx`) **and** by content sniffing for `-----BEGIN CERTIFICATE-----` inside other files (configs frequently embed them).

Parse and record: public key algorithm and size, `signature_algorithm_oid`, `not_valid_before` / `not_valid_after`, issuer, subject, self-signed flag, SAN list.

Emit findings for: SHA-1 signature algorithm, RSA key < 2048, expired or expiring within 90 days, self-signed in a non-dev path.

**Private keys:** if a file matches `-----BEGIN * PRIVATE KEY-----`, record **only** path, size, and POSIX permissions. Do **not** parse it. Do not load its bytes beyond the header check. Emit a hygiene finding if world-readable.

`confidence: high`. `source_layer: artifact`.

### 7.4 Config parsers

Format-specific parsers, each returning findings with `source_layer: config`:

| File | Keys | Emit |
|---|---|---|
| `openssl.cnf` | `MinProtocol`, `MaxProtocol`, `CipherString`, `Ciphersuites` | declared protocol floor, declared suites |
| `nginx.conf` | `ssl_protocols`, `ssl_ciphers`, `ssl_certificate*` | declared protocols, suites, cert paths |
| `sshd_config` | `Ciphers`, `KexAlgorithms`, `MACs`, `HostKeyAlgorithms` | declared SSH crypto |
| `java.security` | `jdk.tls.disabledAlgorithms`, `jdk.certpath.disabledAlgorithms` | declared disabled set |
| Apache `ssl.conf` | `SSLProtocol`, `SSLCipherSuite`, `SSLCertificateFile`, `SSLCertificateKeyFile` | declared protocols, suites, cert paths |
| `ssh_config` | `Ciphers`, `KexAlgorithms`, `MACs`, `HostKeyAlgorithms` | declared client-side SSH crypto |

Use `crossplane` for nginx rather than regex. `configparser` handles openssl.cnf adequately. The other two are plain key-value.

Detect these files by name pattern anywhere in the approved tree, not by fixed path.

`confidence: high` for what is declared — but note this is a *claim*, not a fact. That distinction is what §8 exploits.

### 7.5 Network probe — sslyze

Import sslyze **as a library**, not via CLI + JSON parsing. You get typed `ServerScanResult` objects and skip a serialisation round-trip.

**Hard allowlist:** the collector must refuse any target not in `scan.probe_targets`. Log every target attempted. This is a security control, not a nicety — an unbounded prober is an attack tool.

Run these scan commands per target: all `*_cipher_suites` (SSL 2.0 through TLS 1.3), `certificate_info`, `elliptic_curves`, `session_renegotiation`, `tls_compression`.

Emit findings for:
- Each **accepted** protocol version (a finding in itself if < TLS 1.2)
- Each accepted cipher suite, with its protocol version
- Whether the server enforces its own suite preference
- The negotiated group / curve
- Certificate details (same fields as §7.3)

**Also emit explicit negative findings.** "TLS 1.0 offered: false" is information. Absence of a result is not — it could mean unreachable. Store attempted-and-rejected explicitly.

**PQC group handling:** sslyze may not recognise hybrid PQC groups such as `X25519MLKEM768` (code point `0x11EC`) and may report an unknown group or error. Before building on it, **test against a known hybrid-capable endpoint** and record the behaviour. If it returns the raw code point, map it in the normalizer via a lookup table in `policy/named_groups.yaml`. If it errors, catch it and emit a `confidence: low` finding noting PQC support could not be determined. Do not let the dashboard's PQC-readiness number silently depend on unverified tool behaviour.

`confidence: high`. `source_layer: live`.

### 7.6 CBOM import

Accept an uploaded CycloneDX 1.6 JSON. Parse with `cyclonedx-python-lib`. Map each `cryptographic-asset` component into a finding, taking algorithm, primitive, OID and `evidence.occurrences` where present.

Store the raw uploaded document unparsed in a `provenance_blobs` table. Never re-parse it — it exists so a disputed finding can be traced to exactly what the source tool said.

`confidence`: inherit from the source if declared, else `medium`. `source_layer`: `source` unless the document says otherwise.

---

## 8. Normalizer

Maps six incompatible output shapes onto the `findings` schema. Two jobs beyond field mapping.

### Identity resolution

`SHA-1`, `sha1`, `SHA1WithRSA`, and OID `1.3.14.3.2.26` must collapse to one algorithm identity. Maintain `policy/algorithm_aliases.yaml` mapping every observed spelling → canonical family + OID. Without this the dashboard counts the same algorithm four times.

This is the single fiddliest part of the build. Budget a day.

### Source layer tagging

Every finding gets `source_layer`, ordered by closeness to execution:

1. `live` — observed handshake. Ground truth.
2. `artifact` — deployed cert, linked library. What is installed.
3. `config` — what is declared.
4. `source` — what was intended.

This ordering is the precedence rule when sources disagree, and it drives §9.

---

## 9. Alignment check

Runs after the store, **before** the policy engine, so downstream stages see findings that already carry their alignment note.

### Rule

Compare `source_layer: live` findings against `source_layer: config` findings covering the same asset. Where they diverge:

- **The reported result is what the live scan observed.** Live is fact; config is a claim.
- **Attach a note** stating the observed value does not align with the config specification for that asset.
- **Flag per usage site, not per config declaration.** If a single config line covers five usage sites and two diverge, flag only those two. The three that match are not flagged.
- **Do not classify the divergence.** Whether it is a misconfiguration or a legitimate per-site exception is left to the user. The tool reports *that* it differs and *exactly where*.

### Asset key

Matching requires a correlation key. For the prototype, use the **user-supplied probe host** joined against config findings from the same scan. Since the user explicitly entered the host alongside the upload, the join is `scan_id` + service, not inferred.

Record what matched in `alignment_notes.asset_key`. If no config finding covers a live finding's service, emit no note — do not guess.

### Scope guard

Two mismatches are **not** drift and must not be flagged:

- **Different scope.** Config sets a server-wide floor; the probe tested one virtual host. Record scope on findings and only compare like with like.
- **Unreachable code.** A `source_layer: source` MD5 call in an unimported module is a low-priority finding, not a config conflict. Alignment only compares `live` against `config`.

### Mode behaviour

In `probe_only` and `files` modes there is nothing to compare. Return `{status: "skipped", reason: ...}`. The UI must display this, not an empty panel.

---

## 10. Policy engine

Pure lookup. No computation, no heuristics.

For each finding, match against `algorithms.yaml` on family / OID / primitive, applying any `condition`. Emit a `verdict` row with the matching `rule_id` and its `source` citation.

Five outcomes: `broken_now`, `quantum_vulnerable`, `quantum_safe`, `hygiene`, `unknown`.

**Must also emit `primitive`** — normalising to `key_exchange`, `signature`, `hash`, `cipher`, `protocol`, or `unknown`. The risk scorer depends on this to decide whether Mosca applies at all. Without it, signature keys get ranked as urgently as key-exchange keys, which is wrong.

Note that `broken_now` and `quantum_vulnerable` are **independent**, not points on one scale. RSA-4096 is quantum-vulnerable and perfectly secure today. MD5 is broken today and irrelevant to quantum. Do not collapse them into a single severity number.

---

## 11. Advisor

Four steps, in order.

**1. Match on primitive + family** against `pqc_targets.yaml`. Never on algorithm name alone — RSA maps to ML-KEM for key exchange and ML-DSA for signatures, and only the primitive distinguishes them.

**2. Select the parameter set** from the scan's `data_lifetime_years`. Higher classification → ML-KEM-1024 / ML-DSA-87. Long-lived roots of trust (>10 years) → SLH-DSA per the `sig-longlived-root` rule.

**3. Feasibility check.** Test each `requires` clause against what the collectors observed on that asset — the OpenSSL version from §7.2, the protocol version from §7.5.

If unmet, **emit the blocker chain, not the target**:

```json
{
  "status": "blocked",
  "target": "ML-KEM-768",
  "prerequisites": [
    {"unmet": "openssl>=3.5", "observed": "openssl 1.1.1"},
    {"unmet": "TLS 1.3", "observed": "TLS 1.2"}
  ]
}
```

This is the highest-value output in the system. It turns a wish into an ordered work plan and surfaces long-lead procurement items early.

**4. Apply hybrid policy.** If `prefer_hybrid: true` and the primitive is key exchange, the target becomes the `hybrid` value. Configurable, never hardcoded — different national guidance differs on this.

### Tie-breaking

1. Feasible now beats theoretically better
2. Interoperable (hybrid negotiation) beats unilateral switch
3. Lower action class wins: config < library_upgrade < code_change < hardware
4. Explicitly standardised (FIPS 203/204/205) beats draft

If still tied, emit both with the tradeoff stated. Do not manufacture a preference.

### Statuses

- `recommended` — target found, prerequisites met
- `blocked` — target found, prerequisites unmet (chain populated)
- `no_path` — no upgrade possible; emit a compensating control (network isolation, tunnelling, system replacement)
- `unknown` — no rule matched. **Do not fall back to a generic suggestion.** A wrong recommendation is worse than an absent one.

The dashboard must show counts of all four. Reporting only `recommended` hides the hard part.

---

## 12. Risk scorer — Mosca's inequality

### The formula

```
urgency_years = (X + Y) - Z
```

- **X** = `scan.data_lifetime_years` — from the intake form
- **Y** = `y_years_default` from policy (roadmap: derive from advisor's `action_class`)
- **Z** = `z_years_default` from policy, **exposed as a UI slider**

Positive means overdue. Store all three inputs plus the result on every row.

### The primitive gate

**Apply Mosca only to confidentiality primitives** — `key_exchange`, `cipher`. These are recordable today and decryptable later (harvest-now-decrypt-later).

**Do not apply it to authentication primitives** — `signature`. Forging a signature in 2035 does not retroactively forge a 2026 transaction. There is no harvest step, so X is irrelevant; the deadline is Z alone.

Set `urgency_years = null` for authentication findings and route them to `wave_3`.

This distinction is the thing that separates a correct implementation from a naive one. Add a test for it.

### Waves

Output waves, not a sorted list. A ranked list that puts a three-year rewrite at position one is operationally useless.

| Wave | Condition |
|---|---|
| `wave_0` | `verdict = broken_now` |
| `wave_1` | `quantum_vulnerable`, confidentiality, `urgency_years > 0`, `action_class` in (config, library_upgrade) |
| `wave_2` | `quantum_vulnerable`, confidentiality, `urgency_years > 0`, `action_class` in (code_change, hardware) |
| `wave_3` | `quantum_vulnerable`, authentication primitive, or `urgency_years <= 0` |
| `verify` | `confidence = low` or `verdict = unknown` |

`wave_2` is deliberately separated from `wave_1`: high effort is *why* it is urgent, and it needs budgeting now even though it finishes later.

### Rationale

Populate `rationale` with every factor:

```json
{
  "verdict": "quantum_vulnerable",
  "primitive": "key_exchange",
  "hndl_applicable": true,
  "x_years": 10, "y_years": 1, "z_years": 10,
  "urgency_years": 1,
  "action_class": "config",
  "confidence": "high",
  "wave": "wave_1"
}
```

An auditor must be able to reconstruct any wave from this object. If it cannot be decomposed, it will not be trusted.

**No machine learning anywhere in this component.** There is no labelled training data for correct migration order, and the output must be explainable. A transparent weighted model you can defend beats a model you cannot.

---

## 13. Outputs

### Dashboard (React)

Six screens:

1. **New scan** — mode selector, source input, probe host field, data-lifetime dropdown (`<1 year` / `5–10 years` / `20+ years`), Z slider
2. **File selection** — checkbox tree with select-all, expand/collapse, per-directory toggle, count of selected. Blocks until submitted.
3. **Overview** — PQC readiness percentage, verdict distribution, wave breakdown, recommendation status counts (recommended / blocked / no_path / unknown), policy version + staleness banner
4. **Findings** — filterable table: verdict, wave, collector, confidence, source layer. Drill into any row for full rationale and evidence.
5. **Drift** — alignment notes side by side: what config declares, what the probe observed, the note. Shows the skipped state when not applicable.
6. **Roadmap** — findings grouped by wave, each with target, prerequisites, action class.

### CycloneDX export

`GET /api/scans/{id}/cbom` → CycloneDX 1.6 JSON generated on demand from a query. Do **not** store CycloneDX as the internal format — Postgres with proper columns is the store; CycloneDX is the wire format at both boundaries.

### PDF report

`GET /api/scans/{id}/report.pdf`. Render an HTML template through WeasyPrint. Sections: scan metadata + policy version, executive summary (readiness %, wave counts), wave-by-wave findings, drift notes, blocked prerequisites, unknown findings, methodology and citations.

---

## 14. Demo environment

`demo/docker-compose.yml` with deliberately weak targets. **Build this early** — it is what makes the demo work.

- **nginx** on 8443 with `ssl_protocols TLSv1 TLSv1.1 TLSv1.2;` and a weak cipher list, plus an `openssl.cnf` that declares `MinProtocol = TLSv1.2`. **This is the drift demo:** the config claims 1.2 minimum, the server accepts 1.0.
- A **self-signed cert** with an RSA-1024 key and a SHA-1 signature.
- A **Python service** using `hashlib.md5()`, `rsa.generate_private_key(key_size=1024)`, and AES in ECB mode.
- A **Java service** with `MessageDigest.getInstance("MD5")` and a `java.security` file.
- An **old OpenSSL** image (1.1.1) so the advisor emits a `blocked` recommendation with a prerequisite chain.
- A **compiled C binary** linked against libcrypto, with symbols intact.
- A **CycloneDX file** from an external tool for the import path.

Also include a host that *is* correctly configured, so the report shows both green and red.

---

## 15. Build order

1. DB schema + Alembic + policy YAML loader + validation tests
2. Intake: stage → surface scan → approval API. Test with a local folder.
3. Demo environment (§14) — you need targets before collectors
4. Certificate + config collectors (simplest, immediate visible output)
5. Normalizer with alias resolution
6. Policy engine + the AES-is-quantum-safe test
7. Network probe, including the sslyze PQC-group behaviour test
8. Alignment check
9. Risk scorer with the primitive gate
10. Advisor with prerequisite chaining
11. Code + binary collectors
12. CBOM import/export
13. React dashboard
14. PDF report

**If time runs short, cut in this order:** PDF, CBOM import, binary collector, code collector. Never cut the network probe, alignment check, or risk scorer — those three are the entire differentiation.

---

## 16. Tests that must exist

- AES-256 and SHA-256 resolve to `quantum_safe`, never `quantum_vulnerable`
- RSA-4096 resolves to `quantum_vulnerable` and **not** `broken_now`
- RSA-1024 resolves to `broken_now`
- A signature-primitive finding gets `urgency_years = null` and lands in `wave_3`
- A key-exchange finding with X=20 lands in `wave_1` or `wave_2`
- The same key-exchange finding with X=1 lands in `wave_3`
- Identity resolution: `SHA-1`, `sha1`, `1.3.14.3.2.26` collapse to one algorithm
- The probe refuses a host not in `scan.probe_targets`
- A private key file produces a metadata-only finding and its bytes are never parsed
- An unapproved file path is never opened by any collector
- Alignment returns `skipped` in `probe_only` mode
- Exported CycloneDX validates against the 1.6 schema
- A policy entry without a `source` field fails to load

---

## 17. Out of scope for the prototype

State these on the roadmap slide rather than pretending they exist:

- CI/CD build gate (the policy engine already returns the verdict one would need)
- YARA byte-signature scanning
- Async workers, distributed scanning
- Asset registry with per-host owner and exposure
- Deriving Y from action class
- Inferring probe host from scanned files
- Passive network capture (Zeek-style)
- Kubernetes deployment correlation
- Signed offline policy-pack distribution
- Multi-user auth and RBAC — prototype is single-user, no login

---

## 18. Prior art — be honest about it

CBOMkit (PQCA / Linux Foundation) already does source scanning for Java, Python and Go, plus container and filesystem scanning via `cbomkit-theia`, with a CycloneDX store and web UI. SandboxAQ AQtive Guard and Keyfactor do live network discovery, correlation and risk prioritisation commercially.

ECDAT's position is the **intersection nobody occupies**: open source, self-hostable, fully air-gapped, auditable, free — with drift detection and Mosca-based risk ranking. The CBOM import path exists specifically so CBOMkit becomes an input rather than a competitor.

Do not claim live network discovery or risk prioritisation as novel capabilities. Claim the deployment model.
