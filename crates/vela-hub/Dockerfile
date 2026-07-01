# vela-hub container — multi-stage build with cargo-chef dependency caching.
#
# Doctrine: the hub is dumb transport; the runtime image ships the binary and
# nothing else. The Postgres URL is injected at runtime via Fly secrets.
#
# Why cargo-chef: without it, every source edit invalidated the single build
# layer and recompiled all ~400 dependencies from scratch (8-10 min/deploy).
# cargo-chef isolates the dependency build into a layer keyed on the Cargo
# manifests alone, so a source-only deploy reuses the cached deps and only
# recompiles the workspace crates that changed (~1-2 min). Deploy from the
# substrate root:
#   flyctl deploy --config crates/vela-hub/fly.toml
#
# `web/styles/*.css` and `assets/brand/*.svg` are embedded into the binary at
# compile time via `include_str!`, so the runtime image carries no asset dir.

FROM rust:1.91-slim-bookworm AS chef
WORKDIR /build
RUN apt-get update \
 && apt-get install -y --no-install-recommends pkg-config libssl-dev ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 && cargo install cargo-chef --locked

# --- planner: compute the dependency recipe from the manifests ---
FROM chef AS planner
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
RUN cargo chef prepare --recipe-path recipe.json

# --- builder: cook deps (cached layer), then build the app ---
FROM chef AS builder
# CARGO_JOBS: rustc parallelism. Defaults to 1 to fit the remote Fly builder's
# memory (a parallel release build of vela-protocol OOM-killed it once). Override
# on a roomier host — e.g. a local build on a workstation — with
# `--build-arg CARGO_JOBS=16` to use all cores.
ARG CARGO_JOBS=1
COPY --from=planner /build/recipe.json recipe.json
# Build + cache every dependency. This layer is invalidated only when the recipe
# changes (Cargo.toml / Cargo.lock), not on source edits.
RUN CARGO_BUILD_JOBS=${CARGO_JOBS} cargo chef cook --release -p vela-hub --recipe-path recipe.json
# Now the real source. Deps are already compiled above, so this step only
# recompiles the workspace crates that actually changed.
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
COPY web ./web
COPY assets ./assets
RUN CARGO_BUILD_JOBS=${CARGO_JOBS} cargo build --release -p vela-hub

FROM debian:bookworm-slim AS runtime
# git: the ingestion loop fetches registered frontier repos (git_ingest.rs)
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates git \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --system --uid 10001 vela

COPY --from=builder /build/target/release/vela-hub /usr/local/bin/vela-hub

USER vela
EXPOSE 8080
ENV VELA_HUB_PORT=8080
ENTRYPOINT ["/usr/local/bin/vela-hub"]
