# syntax=docker/dockerfile:1
# Multi-stage build for KELS Gossip service
FROM rust:bookworm AS builder

WORKDIR /app

# Install build dependencies
RUN apt-get update && \
    apt-get install -y \
    clang \
    libclang-dev \
    llvm-dev \
    build-essential \
    protobuf-compiler \
    && rm -rf /var/lib/apt/lists/*

# Copy minimal workspace Cargo.toml (for [patch] section) and source code
COPY services/kels-gossip/Cargo.workspace.toml /app/Cargo.toml
COPY lib/kels-derive /app/lib/kels-derive
COPY lib/kels /app/lib/kels
COPY services/kels-gossip /app/services/kels-gossip

# TRUSTED_REGISTRY_PREFIXES contains the KELS prefixes of trusted registries
# This MUST be provided at compile time as it's embedded in the binary for security
ARG TRUSTED_REGISTRY_PREFIXES

# Build with BuildKit cache mounts for cargo registry and target directory
# Note: workspace target is at /app/target, not /app/services/kels-gossip/target
WORKDIR /app/services/kels-gossip
RUN --mount=type=cache,id=kels-cargo-registry,target=/usr/local/cargo/registry \
    --mount=type=cache,id=kels-gossip-target,target=/app/target \
    TRUSTED_REGISTRY_PREFIXES="${TRUSTED_REGISTRY_PREFIXES}" cargo build --release --bin kels-gossip && \
    cp /app/target/release/kels-gossip /app/kels-gossip

# Final stage
FROM debian:bookworm-slim

WORKDIR /app

# Install runtime dependencies
RUN apt-get update && \
    apt-get install -y \
    libstdc++6 \
    && rm -rf /var/lib/apt/lists/*

# Copy built binary
COPY --from=builder /app/kels-gossip /app/kels-gossip

EXPOSE 4001

CMD ["/app/kels-gossip"]
