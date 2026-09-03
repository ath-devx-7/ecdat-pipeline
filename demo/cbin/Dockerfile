# Compiled artefact target — ECDAT demo target G (SPEC.md §14).
#
# Built on Ubuntu 20.04 for its OpenSSL 1.1.1: the resulting DT_NEEDED entry is
# `libcrypto.so.1.1`, which is exactly the observation the advisor needs in
# order to report `openssl>=3.5` as an unmet prerequisite.
#
# Single stage on purpose. A builder stage would leave the runtime image without
# the toolchain, but it would also drop the source next to the binary, and the
# demo wants both present so the code collector and the binary collector can be
# seen reaching the same conclusion by different routes.
FROM ubuntu:20.04

RUN apt-get update \
 && apt-get install -y --no-install-recommends build-essential libssl-dev \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/app
COPY cryptodemo.c Makefile ./
RUN make BUILD=/opt/app/build

# Copies the binary out to the mounted ./cbin/build so the host-side file scan
# has an ELF to read, then runs it. Without this the binary would only exist
# inside the image and only the docker_image source type could reach it.
CMD ["/bin/sh", "-c", "mkdir -p /out && cp /opt/app/build/cryptodemo /out/cryptodemo && exec /opt/app/build/cryptodemo"]
