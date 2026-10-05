# syntax=docker/dockerfile:1@sha256:4edf897a3ffa55b89f906fc8cc78afdb3f1834cc9c7083565e611a8a7d5fe99e
#
#   docker build -t genesis-mesh-gateway .

FROM --platform=$BUILDPLATFORM rust:1-slim-bookworm@sha256:452176c0cefca88c0b3184ce85a4eb03e3d4fa05d2afb5366abcba853221019e AS build
ARG TARGETARCH
ARG DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
 && apt-get install -y --no-install-recommends gcc-aarch64-linux-gnu gcc-x86-64-linux-gnu libc6-dev-arm64-cross libc6-dev-amd64-cross \
 && rm -rf /var/lib/apt/lists/* \
 && rustup target add aarch64-unknown-linux-gnu x86_64-unknown-linux-gnu
ENV CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=aarch64-linux-gnu-gcc \
    CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER=x86_64-linux-gnu-gcc \
    CC_aarch64_unknown_linux_gnu=aarch64-linux-gnu-gcc \
    CC_x86_64_unknown_linux_gnu=x86_64-linux-gnu-gcc
WORKDIR /src
COPY . .
RUN --mount=type=cache,target=/usr/local/cargo/registry,id=gateway-registry-${TARGETARCH} \
    --mount=type=cache,target=/src/target,id=gateway-cross-target-${TARGETARCH} \
    case "$TARGETARCH" in amd64) target=x86_64-unknown-linux-gnu ;; arm64) target=aarch64-unknown-linux-gnu ;; *) exit 1 ;; esac \
 && cargo build --locked --release --target "$target" --bin genesis-mesh-gateway --bin genesis-mesh-operator \
 && cp "target/$target/release/genesis-mesh-gateway" /usr/local/bin/genesis-mesh-gateway \
 && cp "target/$target/release/genesis-mesh-operator" /usr/local/bin/genesis-mesh-operator
RUN mkdir -p /var/lib/gateway

FROM gcr.io/distroless/cc-debian13:nonroot@sha256:e792ab3d241a468a4fd7519ddbbebe66b49b5f365771716ea688ad40b6c6f1c2
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
