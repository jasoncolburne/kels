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
COPY lib/kels-derive /app/lib/kels-derive
COPY lib/kels /app/lib/kels
COPY services/gossip /app/services/gossip

# TRUSTED_REGISTRY_PREFIXES contains the KELS prefixes of trusted registries
# This MUST be provided at compile time as it's embedded in the binary for security
ARG TRUSTED_REGISTRY_PREFIXES

# Build with BuildKit cache mounts for cargo registry and target directory
WORKDIR /app/services/gossip
RUN --mount=type=cache,id=kels-cargo-registry,target=/usr/local/cargo/registry \
    --mount=type=cache,id=gossip-target,target=/app/services/gossip/target \
    TRUSTED_REGISTRY_PREFIXES="${TRUSTED_REGISTRY_PREFIXES}" cargo build --release --bin gossip && \
    cp target/release/gossip /app/gossip

# Final stage
FROM debian:bookworm-slim

WORKDIR /app

# Install runtime dependencies
RUN apt-get update && \
    apt-get install -y \
    libstdc++6 \
    && rm -rf /var/lib/apt/lists/*

# Copy built binary and migrations
COPY --from=builder /app/gossip /app/gossip
COPY --from=builder /app/services/gossip/migrations /app/services/gossip/migrations

EXPOSE 4001

CMD ["/app/gossip"]
