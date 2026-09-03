# ECDAT demo environment

Targets to scan. Built before any collector, because a certificate parser cannot be
tested without a bad certificate and a drift check cannot be tested without a server
that contradicts its own config (`SPEC.md` §14, build step 3).

Everything here is deliberately broken except `nginx-strong`, which is deliberately
correct — the report needs green as well as red, and it needs the more uncomfortable
third case: a host that is hygienically perfect and still quantum-vulnerable.

**This directory is also the scan target itself.** Point a `files` scan at `demo/` and
the code, config and certificate collectors have everything they need without Docker
running at all. Docker is only required for the live probe and the compiled binary.

---

## Running it

```bash
docker compose -f demo/docker-compose.yml up --build
```

First run takes a few minutes: it builds six images and generates certificates. Build
time needs network access — the air-gap rule in §1 governs the *scan path*, not the
construction of the lab.

| Published | Service | What it is |
|---|---|---|
| `localhost:8443` | `nginx-weak` | TLS 1.0/1.1/1.2, RSA-1024 SHA-1 cert — the drift target |
| `localhost:8444` | `nginx-strong` | TLS 1.3 only, ECDSA P-256 cert — the clean host |
| `localhost:8081` | `pyapp` | Billing service, keeps its container up |

Certificates alone, without Docker:

```bash
./demo/gen_certs.sh          # writes demo/certs/, skips what already exists
./demo/gen_certs.sh --force  # regenerate
```

### Proving the drift target actually works

The whole demo rests on 8443 genuinely accepting TLS 1.0. A mocked answer proves
nothing about the probe, so check it on the wire:

```bash
docker compose -f demo/docker-compose.yml exec -e OPENSSL_CONF=/dev/null oldssl \
  openssl s_client -connect nginx-weak:8443 -tls1 -cipher 'DEFAULT@SECLEVEL=0' -brief </dev/null
```

Expect `Protocol version: TLSv1` and `Peer certificate: ... CN = legacy.ecdat.demo`.

**Both client-side flags are load-bearing, and why is worth understanding**, because
a client that refuses to speak TLS 1.0 produces the same failure as a server that
refuses to serve it:

- `OPENSSL_CONF=/dev/null` — Ubuntu 20.04's own `/etc/ssl/openssl.cnf` sets
  `MinProtocol = TLSv1.2` in an *activated* `system_default` section, so without this
  the client aborts with `no protocols available` before a packet is sent. That file
  is the exact configuration `weak-nginx/openssl.cnf` imitates, with the one
  difference that Ubuntu's is wired up and ours is not.
- `-cipher 'DEFAULT@SECLEVEL=0'` — security level 1 rejects the peer's 1024-bit key.

The same works from the host with an OpenSSL 3.5 client, which still speaks TLS 1.0 at
security level 0:

```bash
openssl s_client -connect localhost:8443 -tls1 -cipher 'DEFAULT@SECLEVEL=0' </dev/null
```

(`curl --tlsv1.0` against 8443 is not a substitute — it fails on some builds for
client-side reasons, which is precisely the ambiguity `s_client` avoids.)

And the negative controls, which must fail with
`tlsv1 alert protocol version ... SSL alert number 70` — a rejection *by the server*,
not by the client:

```bash
docker compose -f demo/docker-compose.yml exec -e OPENSSL_CONF=/dev/null oldssl \
  openssl s_client -connect nginx-strong:8444 -tls1 -cipher 'DEFAULT@SECLEVEL=0' -brief </dev/null
docker compose -f demo/docker-compose.yml exec -e OPENSSL_CONF=/dev/null oldssl \
  openssl s_client -connect nginx-weak:8443 -tls1_3 -brief </dev/null
```

The second one matters as much as the first: 8443 refusing TLS 1.3 is what makes the
advisor's `TLS 1.3` prerequisite genuinely unmet rather than assumed.

And the positive control on the modern host:

```bash
docker compose -f demo/docker-compose.yml exec oldssl \
  openssl s_client -connect nginx-strong:8444 -tls1_3 -brief </dev/null
```

Expect `TLSv1.3`, `TLS_AES_256_GCM_SHA384`, `Signature type: ECDSA`,
`Server Temp Key: X25519`.

### If image pulls fail

`dial tcp 192.0.2.1:443` during `docker compose build` means your DNS resolver is
blackholing the registry — 192.0.2.1 is a documentation address, not a real host.
Check with `nslookup registry-1.docker.io 8.8.8.8`: if a public resolver returns real
addresses and your default one returns 192.0.2.1, the resolver is the problem, not
your connection. Point the machine's DNS at a public resolver, or use a network that
does not filter it.

### Pointing a scan at it

```bash
ID=$(curl -s -X POST localhost:8000/api/scans -H 'content-type: application/json' -d '{
  "mode": "files_and_probe",
  "source_type": "folder",
  "source_ref": "/absolute/path/to/ecdat_pipeline/demo",
  "probe_targets": [{"host": "localhost", "port": 8443}, {"host": "localhost", "port": 8444}],
  "data_lifetime_years": 20
}' | python -c 'import json,sys; print(json.load(sys.stdin)["id"])')

curl -s localhost:8000/api/scans/$ID/files
curl -X POST localhost:8000/api/scans/$ID/approve -H 'content-type: application/json' \
  -d '{"paths": ["..."]}'
```

**Use `data_lifetime_years: 20`.** With the shipped policy pack (Z=12, Y=1) the Mosca
inequality is `X + 1 - 12 > 0`, so anything under X=12 is not overdue and every
quantum-vulnerable finding lands in `wave_3`. At X=20 the urgency is +9 years and
`wave_1` and `wave_2` populate. Re-running at X=1 and watching findings move to
`wave_3` is the clearest demonstration of why the scorer is not just a severity sort.

---

## The `ECDAT-EXPECT:` marker convention

Every deliberate weakness carries a marker comment on the line a collector should
anchor its finding to:

```python
return hashlib.md5(record.encode("utf-8")).hexdigest()  # ECDAT-EXPECT: weak-hash-md5
```

```bash
grep -rn 'ECDAT-EXPECT' demo/          # every expectation, with its line number
```

Tests assert against the markers rather than against hardcoded line numbers, so
editing a demo file cannot silently invalidate a test. A marker means *at least one
finding must reference this line*; it does not cap how many.

---

## Expected findings, target by target

Verdicts below are what the **shipped policy pack** produces, not what a cryptographer
would ideally say. Where the pack has no rule the answer is `unknown` — never a guess
(§10) — and those gaps are listed honestly in their own section at the end.

Waves assume `data_lifetime_years = 20`, Z=12, Y=1.

### A — `nginx-weak`, the drift target (`weak-nginx/`)

| Source | Collector | Observation | `source_layer` | Verdict |
|---|---|---|---|---|
| `nginx.conf` | config | `ssl_protocols TLSv1 TLSv1.1 TLSv1.2` declared | `config` | `broken_now` (TLS < 1.2) |
| `nginx.conf` | config | weak `ssl_ciphers` list, 3DES and CBC-SHA1 | `config` | see gaps |
| `nginx.conf` | config | `ssl_prefer_server_ciphers off` | `config` | see gaps |
| `openssl.cnf` | config | `MinProtocol = TLSv1.2` | `config` | n/a — a declaration |
| `openssl.cnf` | config | `MaxProtocol = TLSv1.2` | `config` | n/a — a declaration |
| probe 8443 | network | TLS 1.0 accepted | `live` | `broken_now` |
| probe 8443 | network | TLS 1.1 accepted | `live` | `broken_now` |
| probe 8443 | network | TLS 1.2 accepted | `live` | — |
| probe 8443 | network | TLS 1.3 **offered and refused** | `live` | — |
| probe 8443 | network | accepted suites incl. `TLS_RSA_WITH_3DES_EDE_CBC_SHA` | `live` | see gaps |
| probe 8443 | network | server does not enforce suite preference | `live` | see gaps |
| probe 8443 | network | RSA-1024 key in served cert | `live` | `broken_now` |
| probe 8443 | network | SHA-1 signature on served cert | `live` | `broken_now` |

**The alignment note.** Exactly one, and it is the reason this host exists:

- `config` says the floor is TLS 1.2. `live` says TLS 1.0 negotiates.
- Asset key: the probe target the user typed (`localhost:8443`) joined against the
  config finding from the same scan. Not inferred from file contents (§9).
- The reported result is the live one. Config is a claim; the handshake is a fact.
- The note says the observed value does not align with the declared specification for
  this asset. It does **not** say whether that is a misconfiguration or a deliberate
  exception for one host — that judgement is the user's (§9 rule 4).

**`MaxProtocol = TLSv1.2` must produce no note.** The server also tops out at TLS 1.2,
so that declaration agrees with reality. §9 rule 3 flags diverging usage sites, not
whole files, and a check that flags the file because one line in it diverges is wrong.

**Why the declaration has no effect.** `weak-nginx/openssl.cnf` omits the top-level
`openssl_conf = default_conf` pointer, so OpenSSL never activates the
`system_default` section. The file parses, it reads as hardened, and it changes
nothing. `strong-nginx/openssl.cnf` is the same configuration with that one line
present — `diff` the two for the shortest possible explanation of the demo.

### B — `nginx-strong`, the clean host (`strong-nginx/`)

| Source | Collector | Observation | `source_layer` | Verdict |
|---|---|---|---|---|
| `nginx.conf` | config | `ssl_protocols TLSv1.3` | `config` | — |
| `openssl.cnf` | config | `MinProtocol`/`MaxProtocol = TLSv1.3`, `Ciphersuites`, `CipherString` | `config` | — |
| probe 8444 | network | TLS 1.3 accepted | `live` | — |
| probe 8444 | network | TLS 1.0/1.1/1.2 **offered and refused** | `live` | — |
| probe 8444 | network | `TLS_AES_256_GCM_SHA384`, `TLS_CHACHA20_POLY1305_SHA256` | `live` | `quantum_safe` (AES) |
| probe 8444 | network | negotiated group X25519 | `live` | `quantum_vulnerable` |
| probe 8444 | network | ECDSA P-256 / SHA-256 certificate | `live` | `quantum_vulnerable` |

**Zero alignment notes.** Every declaration matches what is negotiated.

**Explicit negatives matter here.** "TLS 1.0 offered: false" must be stored as a
finding, not as an absence. Absence is indistinguishable from "host unreachable", and
a readiness number that cannot tell those apart is not a number anyone should act on
(§7.5).

**Still quantum-vulnerable.** X25519 is a `key_exchange`, so Mosca applies: at X=20 it
is overdue by 9 years. The ECDSA certificate is a `signature`, so Mosca does **not**
apply and it goes to `wave_3` with `urgency_years = null`. Those two findings sitting
side by side on one clean host, in different waves, is the single best illustration of
the primitive gate in the whole demo.

### C — `pyapp`, weak crypto in Python (`pyapp/app.py`)

| Marker | Observation | Primitive | Verdict | Wave |
|---|---|---|---|---|
| `weak-hash-md5` | `hashlib.md5(...)` | `hash` | `broken_now` | `wave_0` |
| `weak-hash-sha1` | `hashlib.sha1(...)` | `hash` | see gaps | `verify` |
| `rsa-weak-key` | `rsa.generate_private_key(key_size=1024)` | `signature` | `broken_now` | `wave_0` |
| `aes-ecb` | `Cipher(algorithms.AES(...), modes.ECB())` | `cipher` | `broken_now` | `wave_0` |
| `weak-cipher-3des` | `algorithms.TripleDES(...)` | `cipher` | see gaps | `verify` |
| `hardcoded-key` ×2 | byte-literal key material | — | see gaps | — |
| `high-entropy-literal` | 32-char literal, Shannon entropy > 4.5 | — | see gaps | — |

`source_layer: source`, `confidence: high` for the pattern matches. The entropy match
is a *shape*, not a fact about the value — it belongs at `medium` at best, and this is
where a scanner has to resist claiming more than it knows.

Note `requirements.txt` pins `cryptography==42.0.8`, because 43 moved `TripleDES` and
`ARC4` into `hazmat.decrepit`. A service pinned to an old release in order to keep a
deprecated algorithm working is itself exactly the situation this tool reports.

### D — `javaapp`, weak crypto in Java (`javaapp/`)

| Marker | Observation | Primitive | Verdict |
|---|---|---|---|
| `weak-hash-md5` | `MessageDigest.getInstance("MD5")` | `hash` | `broken_now` |
| `weak-hash-sha1` | `MessageDigest.getInstance("SHA-1")` | `hash` | see gaps |
| `rsa-weak-key` | `kpg.initialize(1024)` | `signature` | `broken_now` |
| `weak-cipher-des` | `Cipher.getInstance("DES/ECB/PKCS5Padding")` | `cipher` | see gaps |
| `hardcoded-key` | key material as a `String` literal | — | see gaps |
| `config-java-tls-disabled` | `jdk.tls.disabledAlgorithms` | — | `config` layer |
| `config-java-certpath-disabled` | `jdk.certpath.disabledAlgorithms` | — | `config` layer |

`java.security` is the JDK 8-era default carried onto a JDK 17 runtime. What it
*permits by omission* is the finding: TLSv1 and TLSv1.1 are absent from the disabled
list, SHA-1 signatures are absent, and the RSA floor is 1024 rather than 2048. It is
loaded with `-Djava.security.properties=`, so it is live configuration, not a prop.

**The cross-language check.** MD5 here and `hashlib.md5` in `pyapp` must collapse to
one algorithm identity in the normalizer (§8). Two rows on the dashboard for the same
algorithm is the failure mode identity resolution exists to prevent.

### E — certificates (`certs/`, generated)

| File | Material | Expected findings |
|---|---|---|
| `weak.crt` | RSA-1024, SHA-1 self-signed, 825 days | RSA < 2048 → `broken_now`; SHA-1 signature → `broken_now`; self-signed |
| `weak.key` | RSA-1024 private key, mode 0644 | **Metadata only.** Path, size, POSIX mode. Hygiene finding for world-readable |
| `strong.crt` | ECDSA P-256, SHA-256, 825 days | No hygiene findings. `quantum_vulnerable`, `signature` primitive |
| `strong.key` | EC private key, mode 0644 | Metadata only; hygiene finding |
| `expiring.crt` | RSA-2048, SHA-256, 45 days | Expires within 90 days |
| `bundle.p12` | PKCS#12: `weak.crt` + `weak.key` | **Metadata only** — see below |
| `embedded-cert.conf` | PEM pasted into a `.conf` file | Must be found by content sniffing, not by extension (§7.3) |

**The `.p12` is the interesting case.** `.p12` is on §7.3's extension list *and* the
file contains a private key, so "parse every certificate file" and "never load private
key bytes" collide inside one file. Expected behaviour: **treat it as key material.**
Record path, size and permissions; do not open it. §1 is a hard rule and does not have
a convenience exception, and a certificate that is only reachable through a key
container is not worth breaking it for.

**POSIX permissions caveat.** The world-readable hygiene finding only appears when the
scan runs on Linux or against a container image. NTFS does not carry a POSIX mode, so
on Windows the collector should record permissions as unavailable rather than
inventing `0644` — an absent observation reported as a value is how a tool starts
lying.

**Not committed.** `demo/certs/` is generated and gitignored. A private key in a git
history is a real incident even when the key is a toy.

### F — `oldssl`, the blocked-recommendation target (`oldssl/`)

Ubuntu 20.04, OpenSSL 1.1.1f. Produces no findings of its own from a file scan; its
job is to be the reason the advisor cannot recommend anything yet:

```json
{"status": "blocked", "target": "ML-KEM-768",
 "prerequisites": [{"unmet": "openssl>=3.5", "observed": "openssl 1.1.1"},
                   {"unmet": "TLS 1.3",      "observed": "TLS 1.2"}]}
```

Both halves of that chain come from real observations: the OpenSSL version from the
binary collector's `DT_NEEDED` on `cbin`, the protocol ceiling from the probe of 8443.

This output is worth more than the recommendation it replaces. "Adopt ML-KEM" is a
wish. "Upgrade OpenSSL, then enable TLS 1.3, then adopt ML-KEM" is a work plan, and it
surfaces the item with the procurement lead time first.

### G — `cbin`, the compiled binary (`cbin/`, built to `cbin/build/cryptodemo`)

| Evidence | Source | Confidence |
|---|---|---|
| `DT_NEEDED: libcrypto.so.1.1` | dynamic section | `high` |
| `MD5_Init`, `MD5_Update`, `MD5_Final` | `.dynsym` | `high` |
| `RSA_generate_key_ex` | `.dynsym` | `high` |
| `EVP_sha1` | `.dynsym` | `high` |
| `DES_set_key_unchecked`, `DES_ecb_encrypt` | `.dynsym` | `high` |
| `TLS_RSA_WITH_3DES_EDE_CBC_SHA`, `AES-256-GCM`, `sha1WithRSAEncryption` | `.rodata` | `medium` |
| `OpenSSL 1.1.1f  31 Mar 2020` | `.rodata` | `medium` |

`source_layer: artifact`. The confidence split is the point: a symbol in `.dynsym`
proves the binary can call the function, while a string in `.rodata` might be a log
label, a lookup key or dead data. Reporting both at `high` would make the higher
number meaningless.

**A useful wrinkle for step 10.** `DT_NEEDED` gives the soname — `libcrypto.so.1.1` or
`libcrypto.so.3` — and a soname carries the major version only. It cannot distinguish
OpenSSL 3.3 from 3.5, which is exactly the boundary `requires: openssl>=3.5` needs. The
`OPENSSL_VERSION_TEXT` string in `.rodata` gives the precise version for this binary.
Whatever the advisor does when it only has a soname, it must not round in the
optimistic direction.

The binary is built with symbols intact and dynamically linked. Stripping it would
leave `DT_NEEDED` intact but lose the symbol evidence, which is half the target.

### H — `sshd/sshd_config`

Not one of §14's eight targets, added because §7.4 ships an sshd_config parser and a
parser with nothing to parse cannot be tested. Kept as a file rather than a running
daemon: it is a declaration, nothing in the demo probes SSH, and a live sshd would add
attack surface while proving nothing.

| Marker | Declares |
|---|---|
| `config-ssh-ciphers` | `3des-cbc`, `aes128-cbc`, `aes256-cbc` alongside CTR modes |
| `config-ssh-kex` | `diffie-hellman-group1-sha1` (1024-bit MODP), `group14-sha1` |
| `config-ssh-macs` | `hmac-md5`, `hmac-sha1-96` |
| `config-ssh-hostkeyalgorithms` | `ssh-rsa` — RSA with SHA-1, disabled by default since OpenSSH 8.8 |

All `source_layer: config`. There is no live SSH observation to compare against, so
**alignment must emit no note for any of it.** Config with no corresponding live
finding produces nothing — §9 says do not guess, and this is the case that tests it.

### I — `sample_cbom.json`, the import path

CycloneDX 1.6 with ten `cryptographic-asset` components spanning all four asset types
(`algorithm`, `certificate`, `protocol`, `related-crypto-material`), plus a dependency
graph. Attributed to CBOMkit, which is the honest framing: §18 treats it as an input,
not a competitor.

Expected on import (§7.6):

- Findings for each component, carrying algorithm, primitive, OID and
  `evidence.occurrences` where present.
- The raw document stored **byte-identical** in `provenance_blobs` and never
  re-parsed. It exists so a disputed finding can be traced to exactly what the source
  tool said, which requires the bytes, not a re-serialisation of them.
- `source_layer: source` — including for the `TLS 1.0` protocol component. A third
  party's report of a handshake is not our observation of one, so it must **not** feed
  the alignment check. Only `live` findings do.
- An `ML-KEM-768` component is included so `quantum_safe` has a member and the
  readiness percentage has a numerator.
- Occurrence paths overlap the native scan deliberately (`pyapp/app.py`,
  `cbin/cryptodemo.c`), so imported and natively-discovered findings for the same
  algorithm exercise identity resolution.

The `primitive` values use CycloneDX's vocabulary — `pke`, `key-agree`, `kem`,
`block-cipher` — which is not ECDAT's. Mapping those onto `key_exchange | signature |
hash | cipher | protocol` is the normalizer's job, and `pke` is the awkward one: RSA
appears under it whether it is being used to encrypt or to sign, and only the
`cryptoFunctions` list distinguishes them. Getting that wrong sends the finding to the
wrong wave.

---

## What must NOT be flagged

A list of true negatives is as much a specification as a list of findings.

| Case | Why not |
|---|---|
| `MaxProtocol = TLSv1.2` on the weak host | The server also tops out at TLS 1.2. It agrees. Flag diverging usage sites, not files (§9 rule 3) |
| Anything on `nginx-strong` as drift | Every declaration matches the handshake |
| `sshd_config` as drift | Config with no live counterpart. §9: emit no note, do not guess |
| The imported `TLS 1.0` component as drift | `source_layer: source`. Alignment compares `live` against `config` only |
| A server-wide floor vs. one probed virtual host | Different scope. §9 scope guard |
| AES-256-GCM on the strong host | `quantum_safe`. Grover weakens symmetric crypto, it does not break it |
| `hazmat.decrepit` import comments, marker comments | Comments about weak crypto are not uses of it |

---

## Gaps in the shipped policy pack that this demo exposes

The pack in `backend/policy/algorithms.yaml` is §6 verbatim plus the two cited entries
listed at the end of this section. Several demo targets hit no rule in it and must
therefore resolve to `unknown` → `verify`. That is the correct behaviour (§10: never
guess, never assume safe), and it is worth seeing on the dashboard rather than
papering over:

| Target | Why `unknown` |
|---|---|
| `hashlib.sha1()`, `MessageDigest.getInstance("SHA-1")` | `sha1-signature` matches `primitive: signature`. A bare hash use is `primitive: hash` and hits nothing |
| DES, 3DES, RC4 | `pqc_targets.yaml` has a `cipher-upgrade` rule for them, `algorithms.yaml` has no verdict entry |
| Weak TLS 1.2 cipher suites | The pack rules on protocol versions, not on suites |
| Every hygiene observation — `ssl_prefer_server_ciphers off`, world-readable key files, self-signed and expiring certificates, hardcoded key material | The pack rules on algorithms. These are not algorithms, so nothing in it matches them and the `hygiene` verdict has no members yet |
| ChaCha20 | The pack's `quantum_safe` entries cite NIST documents, which do not cover a cipher NIST has not approved. A citation for it would have to come from somewhere else |

Two gaps that were **not** left open, because they were omissions rather than
demonstrations, and both were closed the way this table says gaps are closed —
an entry with a citation, no code change:

| Added in step 6 | Why it was not a deliberate gap |
|---|---|
| `sha2-safe` (SHA-256/384/512 → `quantum_safe`) | §6 requires SHA-256 to resolve to `quantum_safe` and prints no rule that would do it |
| `dh-dsa-quantum` (DH, DSA → `quantum_vulnerable`) | Shor breaks discrete log as readily as factoring, and `pqc_targets.yaml` already names DH as a migration target. Ruling on ECDH but not on finite-field DH is not a demonstration of anything |

Closing these is a **policy-pack edit with a citation**, not a code change — which is
the property the pack exists to have. Each needs a `source` field or the loader
refuses to start. Until then, the honest output is `unknown`, and a `verify` wave with
real members demonstrates that the tool distinguishes "safe" from "not assessed".

---

## Generated, not committed

| Path | Made by |
|---|---|
| `demo/certs/` | `gen_certs.sh`, or the `certgen` compose service |
| `demo/cbin/build/` | `make -C demo/cbin`, or the `cbin` compose service |

Both are gitignored. Run `gen_certs.sh` (or bring the stack up once) before scanning
`demo/`, or the certificate collector has nothing to read.

## Tearing it down

```bash
docker compose -f demo/docker-compose.yml down -v
rm -rf demo/certs demo/cbin/build
```
