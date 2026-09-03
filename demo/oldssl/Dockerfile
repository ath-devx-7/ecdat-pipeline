# OpenSSL 1.1.1 host — ECDAT demo target F (SPEC.md §14).
#
# Ubuntu 20.04 ships OpenSSL 1.1.1f. Its job in the demo is to be the reason a
# recommendation comes back `blocked` instead of `recommended`:
#
#   {"status": "blocked", "target": "ML-KEM-768",
#    "prerequisites": [{"unmet": "openssl>=3.5", "observed": "openssl 1.1.1"},
#                      {"unmet": "TLS 1.3",      "observed": "TLS 1.2"}]}
#
# That output is worth more than the recommendation it replaces. "Adopt ML-KEM"
# is a wish; "upgrade OpenSSL, then enable TLS 1.3, then adopt ML-KEM" is a work
# plan, and the OpenSSL upgrade is the item with the procurement lead time.
#
# This image doubles as the certificate generator. OpenSSL 1.1.1 signs SHA-1 and
# 1024-bit RSA without complaint, which some 3.x distribution builds will not.
FROM ubuntu:20.04

RUN apt-get update \
 && apt-get install -y --no-install-recommends openssl ca-certificates \
 && rm -rf /var/lib/apt/lists/*

# Stays up so it can be exec'd into — it is also the most reliable TLS 1.0
# client on hand, since an OpenSSL 3.5 client on the host refuses TLS 1.0 as
# firmly as a 3.5 server would.
CMD ["/bin/sh", "-c", "openssl version -a && exec sleep infinity"]
