# syntax=docker/dockerfile:1
# Multi-stage build for test client with kels-bench and kels-cli

# Stage 1: Build kels-bench and kels-cli
FROM rust:bookworm AS builder

WORKDIR /app

# Copy all source code
COPY clients/test/Cargo.toml /app/
COPY lib/kels /app/lib/kels
COPY lib/kels-derive /app/lib/kels-derive
COPY clients/kels-bench /app/clients/kels-bench
COPY clients/kels-cli /app/clients/kels-cli

# TRUSTED_REGISTRY_PREFIXES contains the KELS prefixes of trusted registries
ARG TRUSTED_REGISTRY_PREFIXES

# Build kels-bench
WORKDIR /app/clients/kels-bench
RUN --mount=type=cache,id=kels-cargo-registry,target=/usr/local/cargo/registry \
    --mount=type=cache,id=kels-bench-target,target=/app/target \
    TRUSTED_REGISTRY_PREFIXES="${TRUSTED_REGISTRY_PREFIXES}" cargo build --release && \
    cp /app/target/release/kels-bench /app/kels-bench

# Build kels-cli with dev-tools for adversarial testing
WORKDIR /app/clients/kels-cli
RUN --mount=type=cache,id=kels-cargo-registry,target=/usr/local/cargo/registry \
    --mount=type=cache,id=kels-cli-target,target=/app/target \
    TRUSTED_REGISTRY_PREFIXES="${TRUSTED_REGISTRY_PREFIXES}" cargo build --release --features dev-tools && \
    cp /app/target/release/kels-cli /app/kels-cli

# Stage 2: Final test client image
FROM debian:bookworm-slim

# Install testing tools
RUN apt-get update && apt-get install -y --no-install-recommends \
    bash \
    curl \
    dnsutils \
    python3 \
    isc-dhcp-client \
    iproute2 \
    net-tools \
    iputils-ping \
    jq \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /tests

# Copy binaries
COPY --from=builder /app/kels-bench /usr/local/bin/kels-bench
COPY --from=builder /app/kels-cli /usr/local/bin/kels-cli

# Copy test scripts
COPY clients/test/scripts/ /tests/

# Keep container running
CMD ["sleep", "infinity"]
