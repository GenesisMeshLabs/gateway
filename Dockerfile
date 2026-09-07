# syntax=docker/dockerfile:1
#
#   docker build -t genesis-mesh-gateway .

FROM --platform=$BUILDPLATFORM rust:1-slim-bookworm AS build
ARG TARGETARCH
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

FROM gcr.io/distroless/cc-debian13:nonroot@sha256:c31ff9abcb1910f3ab25c7957bdaf0bfe12a01eb546e8df2282f1c8f682b606c
COPY --from=build --chown=10001:10001 /var/lib/gateway /var/lib/gateway
COPY --from=build /usr/local/bin/genesis-mesh-gateway /usr/local/bin/genesis-mesh-gateway
COPY --from=build /usr/local/bin/genesis-mesh-operator /usr/local/bin/genesis-mesh-operator
USER 10001:10001
ENV GATEWAY_ADDR=0.0.0.0:8080
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD ["/usr/local/bin/genesis-mesh-gateway", "--healthcheck"]
ENTRYPOINT ["/usr/local/bin/genesis-mesh-gateway"]
