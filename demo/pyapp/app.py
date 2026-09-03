"""Legacy billing helpers — ECDAT demo target C (SPEC.md §14).

Every cryptographic choice in this module is wrong on purpose. It exists to
give the Semgrep collector (§7.1) something to find, and to give the risk
scorer a spread of primitives so the wave assignment has to actually
discriminate rather than sorting one homogeneous list.

Lines carrying an ``ECDAT-EXPECT:`` marker are the ones a collector must
report. The marker sits on the line Semgrep anchors the match to, so a test can
grep the markers out of this file and assert a finding exists at each of those
line numbers, instead of hardcoding line numbers that drift on the next edit.
The convention is described in demo/README.md.

Nothing in here is safe to copy.
"""

from __future__ import annotations

import hashlib
import http.server
import json
import os

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa

# ECDAT-EXPECT: hardcoded-key
# A symmetric key as a byte literal in source. Anyone with read access to the
# repository has the key, and rotating it is a code change plus a deploy.
BILLING_AES_KEY = b"\x8f\x1c\x44\xd2\x0b\x7a\x93\xe5\x21\xc8\x6f\x30\xab\x59\x74\xe2"

# ECDAT-EXPECT: hardcoded-key
LEGACY_3DES_KEY = b"legacy-3des-key-24bytes!"

# ECDAT-EXPECT: high-entropy-literal
# 32 characters, Shannon entropy above 4.5 — the shape of a credential, which
# is all a scanner can honestly say about it (§7.1).
LEGACY_API_TOKEN = "hR7kQ2vX9pL4mN6bT8wZ3cY5dF1gJ0sA"


def customer_fingerprint(record: str) -> str:
    """Stable id for a customer record.

    MD5 was chosen years ago for the hex length, not for any security property,
    and that is the usual story. Whether this one matters depends on whether
    anything downstream trusts the value — which the tool cannot know and does
    not guess.
    """
    return hashlib.md5(record.encode("utf-8")).hexdigest()  # ECDAT-EXPECT: weak-hash-md5


def statement_checksum(blob: bytes) -> str:
    """Integrity check on a generated statement PDF."""
    return hashlib.sha1(blob).hexdigest()  # ECDAT-EXPECT: weak-hash-sha1


def issue_signing_key():
    """Mint the key that signs outbound settlement files.

    1024-bit RSA is below the NIST SP 800-131A Rev.2 floor: `broken_now`, not
    merely quantum-vulnerable. It is also a signature primitive, so the risk
    scorer must not apply Mosca's inequality to it (§12).
    """
    return rsa.generate_private_key(public_exponent=65537, key_size=1024)  # ECDAT-EXPECT: rsa-weak-key


def encrypt_invoice(plaintext: bytes) -> bytes:
    """Encrypt an invoice blob before it goes to object storage.

    ECB leaks structure: identical plaintext blocks produce identical ciphertext
    blocks, so the shape of the document survives encryption. The key size is
    irrelevant to that — AES-256-ECB is as broken as AES-128-ECB, which is why
    the policy rule matches on mode and ignores key size.
    """
    padding = (-len(plaintext)) % 16
    padded = plaintext + bytes([padding or 16]) * (padding or 16)
    cipher = Cipher(algorithms.AES(BILLING_AES_KEY), modes.ECB())  # ECDAT-EXPECT: aes-ecb
    encryptor = cipher.encryptor()
    return encryptor.update(padded) + encryptor.finalize()


def encrypt_partner_batch(plaintext: bytes) -> bytes:
    """Encrypt the nightly batch for a partner that never upgraded.

    3DES has a 64-bit block, so it leaks after roughly 32 GB on one key
    (SWEET32, CVE-2016-2183). A confidentiality primitive, so this one *does*
    go through Mosca — and lands in wave_0 anyway, being broken already.
    """
    iv = os.urandom(8)
    cipher = Cipher(algorithms.TripleDES(LEGACY_3DES_KEY), modes.CBC(iv))  # ECDAT-EXPECT: weak-cipher-3des
    encryptor = cipher.encryptor()
    return iv + encryptor.update(plaintext.ljust(((len(plaintext) // 8) + 1) * 8, b"\0")) + encryptor.finalize()


class BillingHandler(http.server.BaseHTTPRequestHandler):
    """Keeps the container alive and gives the endpoint something to answer."""

    def do_GET(self) -> None:  # noqa: N802 — stdlib naming
        body = json.dumps(
            {
                "service": "ecdat-demo-billing",
                "fingerprint": customer_fingerprint("demo-customer-0001"),
                "checksum": statement_checksum(b"demo statement"),
                "invoice_ciphertext_len": len(encrypt_invoice(b"demo invoice body")),
            }
        ).encode()
        self.send_response(200)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args) -> None:
        return


def main() -> None:
    server = http.server.HTTPServer(("0.0.0.0", 8081), BillingHandler)
    print("ecdat demo billing service on :8081", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
