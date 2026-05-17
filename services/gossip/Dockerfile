# syntax=docker/dockerfile:1
# Multi-stage build for KELS Gossip service
FROM rust:bookworm AS builder

WORKDIR /app

# Install build dependencies
RUN apt-get update && \
    apt-get install -y \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Copy source code
COPY lib/gossip /app/lib/gossip
COPY lib/derive /app/lib/derive
COPY lib/exchange /app/lib/exchange
COPY lib/kels /app/lib/kels
COPY lib/policy /app/lib/policy
COPY services/gossip /app/services/gossip

# FEDERATION_IEL_PREFIX is the compile-time default federation IEL prefix
# baked into the binary at build (#190 / #194). Runtime override via the
# same env var; mismatch logs a startup warning. See
# `docs/design/infrastructure/federation.md §Configuration`.
ARG FEDERATION_IEL_PREFIX

# Build with BuildKit cache mounts for cargo registry and target directory
WORKDIR /app/services/gossip
RUN --mount=type=cache,id=kels-cargo-registry,target=/usr/local/cargo/registry \
    --mount=type=cache,id=gossip-target,target=/app/services/gossip/target \
    FEDERATION_IEL_PREFIX="${FEDERATION_IEL_PREFIX}" cargo build --release --bin gossip && \
    cp target/release/gossip /app/gossip

# Final stage
FROM debian:bookworm-slim

WORKDIR /app

# Install runtime dependencies
RUN apt-get update && \
    apt-get install -y \
    libstdc++6 \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Copy built binary and migrations
COPY --from=builder /app/gossip /app/gossip
COPY --from=builder /app/services/gossip/migrations /app/services/gossip/migrations

EXPOSE 4001

CMD ["/app/gossip"]
