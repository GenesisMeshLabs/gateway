# syntax=docker/dockerfile:1@sha256:4edf897a3ffa55b89f906fc8cc78afdb3f1834cc9c7083565e611a8a7d5fe99e
#
#   docker build -t genesis-mesh-gateway .

FROM --platform=$BUILDPLATFORM rust:1-slim-bookworm@sha256:2c3a22f0a5533ea2dd5a16627bc841228151faa2d4de2644ac9987e4a2f1f2fa AS build
ARG TARGETARCH
ARG DEBIAN_FRONTEND=noninteractive
# Static musl binaries, cross-compiled with cargo-zigbuild: Zig is the C
# toolchain for SQLite, ring and aws-lc on both targets. The runtime image then
# needs no libc, so it carries no glibc, OpenSSL or zlib to patch.
COPY docker/zig-requirements.txt /tmp/zig-requirements.txt
RUN apt-get update \
 && apt-get install -y --no-install-recommends python3-pip \
 && rm -rf /var/lib/apt/lists/* \
 && pip3 install --no-cache-dir --break-system-packages --require-hashes -r /tmp/zig-requirements.txt \
 && cargo install --locked cargo-zigbuild@0.24.1 \
 && rustup target add aarch64-unknown-linux-musl x86_64-unknown-linux-musl
WORKDIR /src
COPY . .
RUN --mount=type=cache,target=/usr/local/cargo/registry,id=gateway-registry-${TARGETARCH} \
    --mount=type=cache,target=/src/target,id=gateway-musl-target-${TARGETARCH} \
    case "$TARGETARCH" in amd64) target=x86_64-unknown-linux-musl ;; arm64) target=aarch64-unknown-linux-musl ;; *) exit 1 ;; esac \
 && cargo zigbuild --locked --release --target "$target" --bin genesis-mesh-gateway --bin genesis-mesh-operator \
 && cp "target/$target/release/genesis-mesh-gateway" /usr/local/bin/genesis-mesh-gateway \
 && cp "target/$target/release/genesis-mesh-operator" /usr/local/bin/genesis-mesh-operator
RUN mkdir -p /var/lib/gateway

# Static runtime: CA certificates, tzdata and /etc/passwd, no libc or shared libraries.
FROM gcr.io/distroless/static-debian13:nonroot@sha256:25ac8f0c3b2334a9eb05452266bd4697864a8c8ef0ef71e5e6480d7f92868329
ARG VERSION=dev
ARG REVISION=unknown
LABEL org.opencontainers.image.title="genesis-mesh-gateway" \
      org.opencontainers.image.description="Genesis Mesh trust gateway: verification, authority services and console" \
      org.opencontainers.image.source="https://github.com/GenesisMeshLabs/gateway" \
      org.opencontainers.image.documentation="https://docs.genesismesh.org/operations/container-images.html" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${REVISION}"
COPY --from=build --chown=10001:10001 /var/lib/gateway /var/lib/gateway
COPY --from=build /usr/local/bin/genesis-mesh-gateway /usr/local/bin/genesis-mesh-gateway
COPY --from=build /usr/local/bin/genesis-mesh-operator /usr/local/bin/genesis-mesh-operator
USER 10001:10001
# The distroless home (/home/nonroot) belongs to uid 65532; work where this uid owns state.
WORKDIR /var/lib/gateway
ENV GATEWAY_ADDR=0.0.0.0:8080
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD ["/usr/local/bin/genesis-mesh-gateway", "--healthcheck"]
ENTRYPOINT ["/usr/local/bin/genesis-mesh-gateway"]
