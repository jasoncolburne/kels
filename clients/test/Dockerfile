# syntax=docker/dockerfile:1
# Multi-stage build for test client with vdig and vreg

# Stage 1: Build vdig and vreg
FROM rust:bookworm AS builder

WORKDIR /app

# Copy all source code
COPY lib/kels /app/lib/kels
COPY clients/kels-bench /app/clients/kels-bench

# Build kels-bench with BuildKit cache mounts
WORKDIR /app/clients/kels-bench
RUN --mount=type=cache,id=kels-bench-registry,target=/usr/local/cargo/registry \
    --mount=type=cache,id=kels-bench-target,target=/app/clients/kels-bench/target \
    cargo build --release && \
    cp /app/clients/kels-bench/target/release/kels-bench /app/kels-bench

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

# Copy test scripts
COPY clients/test/scripts/ /tests/

# Keep container running
CMD ["sleep", "infinity"]
