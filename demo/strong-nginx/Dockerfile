# The modern TLS host for the ECDAT demo (SPEC.md §14).
#
# nginx 1.27 links OpenSSL 3.x, which is what makes TLS 1.3 and the
# `ssl_conf_command Ciphersuites` directive available. Deliberately a different
# base from the legacy host: the binary collector should report two different
# libcrypto versions across the demo, and the advisor's feasibility check should
# reach different conclusions for the two of them.
FROM nginx:1.27-alpine

COPY openssl.cnf /etc/ssl/openssl.cnf
COPY nginx.conf /etc/nginx/nginx.conf

EXPOSE 8444
