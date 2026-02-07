# syntax=docker/dockerfile:1
# Multi-stage build for KELS service
FROM rust:bookworm AS builder

WORKDIR /app

# Install build dependencies for RocksDB
RUN apt-get update && \
    apt-get install -y \
    clang \
    libclang-dev \
    llvm-dev \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Copy all source code
COPY lib/kels-derive /app/lib/kels-derive
COPY lib/kels /app/lib/kels
COPY services/kels /app/services/kels

# Build with BuildKit cache mounts for cargo registry and target directory
WORKDIR /app/services/kels
RUN --mount=type=cache,id=kels-cargo-registry,target=/usr/local/cargo/registry \
    --mount=type=cache,id=kels-target,target=/app/services/kels/target \
    cargo build --release --bin kels && \
    cp /app/services/kels/target/release/kels /app/kels

# Final stage
FROM debian:bookworm-slim

WORKDIR /app

# Install runtime dependencies
RUN apt-get update && \
    apt-get install -y \
    ca-certificates \
    libssl3 \
    libstdc++6 \
    && rm -rf /var/lib/apt/lists/*

# Copy built binary
COPY --from=builder /app/kels /app/kels

COPY --from=builder /app/services/kels/migrations /app/services/kels/migrations

EXPOSE 8091

CMD ["/app/kels"]
