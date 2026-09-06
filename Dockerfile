# syntax=docker/dockerfile:1
#
#   docker build -t genesis-mesh-gateway .

FROM rust:1-slim-bookworm AS build
WORKDIR /src
COPY . .
RUN cargo build --release --bin genesis-mesh-gateway \
 && cp target/release/genesis-mesh-gateway /usr/local/bin/genesis-mesh-gateway

FROM debian:bookworm-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends curl ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --system --uid 10001 gateway
COPY --from=build /usr/local/bin/genesis-mesh-gateway /usr/local/bin/genesis-mesh-gateway
USER gateway
ENV GATEWAY_ADDR=0.0.0.0:8080
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD curl -fsS http://127.0.0.1:8080/health || exit 1
ENTRYPOINT ["/usr/local/bin/genesis-mesh-gateway"]
