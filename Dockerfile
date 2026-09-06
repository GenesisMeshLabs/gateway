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
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target,id=gateway-cross-target-${TARGETARCH} \
    case "$TARGETARCH" in amd64) target=x86_64-unknown-linux-gnu ;; arm64) target=aarch64-unknown-linux-gnu ;; *) exit 1 ;; esac \
 && cargo build --locked --release --target "$target" --bin genesis-mesh-gateway --bin genesis-mesh-operator \
 && cp "target/$target/release/genesis-mesh-gateway" /usr/local/bin/genesis-mesh-gateway \
 && cp "target/$target/release/genesis-mesh-operator" /usr/local/bin/genesis-mesh-operator

FROM debian:bookworm-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends curl ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --system --uid 10001 gateway
COPY --from=build /usr/local/bin/genesis-mesh-gateway /usr/local/bin/genesis-mesh-gateway
COPY --from=build /usr/local/bin/genesis-mesh-operator /usr/local/bin/genesis-mesh-operator
USER gateway
ENV GATEWAY_ADDR=0.0.0.0:8080
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD curl -fsS http://127.0.0.1:8080/health || exit 1
ENTRYPOINT ["/usr/local/bin/genesis-mesh-gateway"]
