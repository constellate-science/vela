# vela-hub container — multi-stage build.
#
# Doctrine: the hub is dumb transport; the container ships the binary
# and nothing else. The Postgres URL is injected at runtime via Fly
# secrets, never baked in.

FROM rust:1.91-slim-bookworm AS builder
WORKDIR /build

RUN apt-get update \
 && apt-get install -y --no-install-recommends pkg-config libssl-dev ca-certificates \
 && rm -rf /var/lib/apt/lists/*

# Workspace context: copy everything we need to build the hub.
# `web/styles/*.css` and `assets/brand/*.svg` are embedded into the
# binary at compile time via `include_str!` so the runtime image carries
# no static-asset directory.
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
COPY web ./web
COPY assets ./assets

# CARGO_BUILD_JOBS=1: serialize compilation so only one rustc runs at a time.
# The remote builder OOM-killed the parallel release build of vela-protocol
# once the write-security layer grew the crate; compiling it alone fits.
RUN CARGO_BUILD_JOBS=1 cargo build --release -p vela-hub

FROM debian:bookworm-slim AS runtime
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --system --uid 10001 vela

COPY --from=builder /build/target/release/vela-hub /usr/local/bin/vela-hub

USER vela
EXPOSE 8080
ENV VELA_HUB_PORT=8080
ENTRYPOINT ["/usr/local/bin/vela-hub"]
