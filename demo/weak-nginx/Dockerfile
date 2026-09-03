# The legacy TLS host for the ECDAT demo (SPEC.md §14).
#
# nginx 1.20 is pinned because it links OpenSSL 1.1.1. nginx images from 1.23
# onward link OpenSSL 3.x, where TLS 1.0 needs increasingly awkward coaxing and
# the 1024-bit SHA-1 certificate is refused at more security levels. The demo
# needs a server that genuinely speaks TLS 1.0 — a mocked one proves nothing
# about the probe.
#
# OpenSSL 1.1.1 is also what makes this host a realistic `blocked` case for the
# advisor: the ML-KEM prerequisite chain wants openssl>=3.5 and TLS 1.3, and
# this image has neither.
FROM nginx:1.20.2-alpine

# The claim. Placed at the path this image's OpenSSL actually reads, so that
# nothing about the drift depends on the file being hidden — only on the
# missing activation pointer inside it.
COPY openssl.cnf /etc/ssl/openssl.cnf

COPY nginx.conf /etc/nginx/nginx.conf

EXPOSE 8443
