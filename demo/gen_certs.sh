#!/bin/sh
# Reproducible certificate material for the ECDAT demo environment (SPEC.md §14).
#
# Nothing here is committed. Certificates carry private keys, and a private key
# in a git history is a real incident even when the key is a toy — so the demo
# generates its own and `.gitignore` keeps `demo/certs/` out of the tree.
#
# Run it directly, or let `docker compose up` run it for you: the `certgen`
# service executes this same script inside the OpenSSL 1.1.1 image, which will
# sign SHA-1 and 1024-bit RSA without argument. Modern OpenSSL 3.x can still do
# both, but some distribution builds (RHEL 9, Fedora) refuse SHA-1 signatures
# outright, which is why the container path exists.
#
#   ./demo/gen_certs.sh                 # into demo/certs/
#   ./demo/gen_certs.sh /tmp/certs      # somewhere else
#   ./demo/gen_certs.sh --force         # regenerate over existing files
#
# Existing files are left alone by default. Certificates are an input to a scan
# and swapping them mid-run would change the answer underneath it.
#
# Portability note: subject names go through a generated config file rather than
# `-subj "/C=IN/O=..."`. On Git Bash the MSYS layer rewrites any argument
# starting with `/` into a Windows path, turning the subject into
# `C:/Program Files/Git/C=IN/O=...` and failing. A config file has no leading
# slash to mangle and behaves identically on Linux and in the container.

set -eu

FORCE=0
OUT=""
for arg in "$@"; do
    case "$arg" in
        --force) FORCE=1 ;;
        -*) echo "gen_certs.sh: unknown option $arg" >&2; exit 2 ;;
        *) OUT="$arg" ;;
    esac
done

if [ -z "$OUT" ]; then
    OUT="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)/certs"
fi

if ! command -v openssl >/dev/null 2>&1; then
    echo "gen_certs.sh: no openssl on PATH." >&2
    echo "  Use the containerised path instead:" >&2
    echo "  docker compose -f demo/docker-compose.yml run --rm certgen" >&2
    exit 1
fi

mkdir -p "$OUT"
CNF="$OUT/.subject.cnf"
trap 'rm -f "$CNF"' EXIT INT TERM

echo "gen_certs.sh: $(openssl version)"
echo "gen_certs.sh: output -> $OUT"

# Writes the throwaway config carrying one certificate's subject and SANs.
# Deleted on the way out: it is not a demo target, and a stray file named
# something.cnf inside the scan tree would be noise the README does not account
# for.
#   $1 common name   $2 subjectAltName value   $3 key bits (RSA only, unused for EC)
write_subject_cnf() {
    cat > "$CNF" <<CNF_EOF
[ req ]
default_bits       = ${3:-2048}
prompt             = no
distinguished_name = dn
x509_extensions    = v3_ext

[ dn ]
C  = IN
O  = ECDAT Demo
CN = $1

[ v3_ext ]
subjectAltName       = $2
basicConstraints     = critical,CA:TRUE
subjectKeyIdentifier = hash
CNF_EOF
}

# ---------------------------------------------------------------------------
# 1. The weak certificate: RSA-1024, SHA-1 self-signed. Served on 8443.
#
#    Two independent findings live in one file. RSA-1024 is below the 2048-bit
#    floor (NIST SP 800-131A Rev.2) and SHA-1 as a signature algorithm is broken
#    outright — so the certificate collector must report both, not just the
#    first one it notices.
# ---------------------------------------------------------------------------
if [ "$FORCE" = "1" ] || [ ! -f "$OUT/weak.crt" ]; then
    write_subject_cnf "legacy.ecdat.demo" \
        "DNS:legacy.ecdat.demo,DNS:localhost,IP:127.0.0.1" 1024
    openssl req -x509 -new -newkey rsa:1024 -sha1 -nodes -days 825 \
        -config "$CNF" \
        -keyout "$OUT/weak.key" -out "$OUT/weak.crt" 2>/dev/null
    echo "  weak.crt            RSA-1024 / SHA-1 self-signed, 825 days"
else
    echo "  weak.crt            exists, kept"
fi

# ---------------------------------------------------------------------------
# 2. The strong certificate: ECDSA P-256, SHA-256. Served on 8444.
#
#    This one is hygienically clean and still `quantum_vulnerable` — ECDSA falls
#    to Shor. The report needs that case as much as it needs the red one: "no
#    findings" and "no quantum-vulnerable findings" are very different claims.
#
#    The key is generated in its own step rather than with
#    `-newkey ec -pkeyopt ec_paramgen_curve:prime256v1`, because that argument's
#    colon is another thing the MSYS layer tries to read as a path list.
# ---------------------------------------------------------------------------
if [ "$FORCE" = "1" ] || [ ! -f "$OUT/strong.crt" ]; then
    write_subject_cnf "modern.ecdat.demo" \
        "DNS:modern.ecdat.demo,DNS:localhost,IP:127.0.0.1"
    openssl ecparam -name prime256v1 -genkey -noout -out "$OUT/strong.key" 2>/dev/null
    openssl req -x509 -new -key "$OUT/strong.key" -sha256 -days 825 \
        -config "$CNF" -out "$OUT/strong.crt" 2>/dev/null
    echo "  strong.crt          ECDSA P-256 / SHA-256 self-signed, 825 days"
else
    echo "  strong.crt          exists, kept"
fi

# ---------------------------------------------------------------------------
# 3. A near-expiry certificate. Not served — it exists so the "expires within
#    90 days" rule has something to fire on without putting an expiry clock on
#    the demo servers themselves.
# ---------------------------------------------------------------------------
if [ "$FORCE" = "1" ] || [ ! -f "$OUT/expiring.crt" ]; then
    write_subject_cnf "expiring.ecdat.demo" "DNS:expiring.ecdat.demo" 2048
    openssl req -x509 -new -newkey rsa:2048 -sha256 -nodes -days 45 \
        -config "$CNF" \
        -keyout "$OUT/expiring.key" -out "$OUT/expiring.crt" 2>/dev/null
    echo "  expiring.crt        RSA-2048 / SHA-256, 45 days — trips the 90-day rule"
else
    echo "  expiring.crt        exists, kept"
fi

# ---------------------------------------------------------------------------
# 4. A PKCS#12 bundle. A .p12 is on the certificate collector's extension list
#    and it contains a private key, so it is the case where "parse every cert
#    file" and "never load private key bytes" collide. Expected behaviour is in
#    demo/README.md: treat it as key material, metadata only.
# ---------------------------------------------------------------------------
if [ "$FORCE" = "1" ] || [ ! -f "$OUT/bundle.p12" ]; then
    openssl pkcs12 -export -out "$OUT/bundle.p12" \
        -inkey "$OUT/weak.key" -in "$OUT/weak.crt" \
        -name "legacy.ecdat.demo" -passout pass: 2>/dev/null
    echo "  bundle.p12          cert + key, empty password — key-material path"
else
    echo "  bundle.p12          exists, kept"
fi

# ---------------------------------------------------------------------------
# 5. A certificate pasted inside a file with an unrelated extension. §7.3
#    requires candidates to be found by content sniffing as well as by
#    extension, because configs embed PEM blocks constantly.
# ---------------------------------------------------------------------------
if [ "$FORCE" = "1" ] || [ ! -f "$OUT/embedded-cert.conf" ]; then
    {
        echo "# ECDAT demo: a PEM certificate inside a file the extension list misses."
        echo "# The certificate collector has to sniff for the BEGIN line (SPEC.md §7.3)."
        echo "upstream_tls_pin = |"
        cat "$OUT/weak.crt"
    } > "$OUT/embedded-cert.conf"
    echo "  embedded-cert.conf  PEM inline in a non-cert extension"
else
    echo "  embedded-cert.conf  exists, kept"
fi

# Private keys left world-readable on purpose: the certificate collector emits a
# hygiene finding for mode 0644 on key material. POSIX permissions do not
# survive a Windows filesystem, so that finding only appears when the scan runs
# on Linux or against the container image — noted in demo/README.md.
chmod 644 "$OUT"/*.key "$OUT/bundle.p12" 2>/dev/null || true

echo "gen_certs.sh: done."
