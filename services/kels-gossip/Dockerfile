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

# Copy all source code
COPY lib/kels-derive /app/lib/kels-derive
COPY lib/kels /app/lib/kels
COPY services/kels-gossip /app/services/kels-gossip

# Build with BuildKit cache mounts for cargo registry and target directory
WORKDIR /app/services/kels-gossip
RUN --mount=type=cache,id=kels-gossip-registry,target=/usr/local/cargo/registry \
    --mount=type=cache,id=kels-gossip-target,target=/app/services/kels-gossip/target \
    cargo build --release --bin kels-gossip && \
    cp /app/services/kels-gossip/target/release/kels-gossip /app/kels-gossip

# Final stage
FROM debian:bookworm-slim

WORKDIR /app

# Install runtime dependencies
RUN apt-get update && \
    apt-get install -y \
    ca-certificates \
    libstdc++6 \
    && rm -rf /var/lib/apt/lists/*

# Copy built binary and migrations
COPY --from=builder /app/kels-gossip /app/kels-gossip
COPY --from=builder /app/services/kels-gossip/migrations /app/services/kels-gossip/migrations

EXPOSE 4001

CMD ["/app/kels-gossip"]
