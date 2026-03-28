# syntax=docker/dockerfile:1
# Multi-stage build for KELS SADStore service
FROM rust:bookworm AS builder

WORKDIR /app

# Install build dependencies
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
COPY services/kels-sadstore /app/services/kels-sadstore

# Build with BuildKit cache mounts for cargo registry and target directory
WORKDIR /app/services/kels-sadstore
RUN --mount=type=cache,id=kels-sadstore-cargo-registry,target=/usr/local/cargo/registry \
    --mount=type=cache,id=kels-sadstore-target,target=/app/services/kels-sadstore/target \
    cargo build --release --bin kels-sadstore && \
    cp /app/services/kels-sadstore/target/release/kels-sadstore /app/kels-sadstore

# Final stage
FROM debian:bookworm-slim

WORKDIR /app

# Install runtime dependencies
RUN apt-get update && \
    apt-get install -y \
    libstdc++6 \
    && rm -rf /var/lib/apt/lists/*

# Copy built binary
COPY --from=builder /app/kels-sadstore /app/kels-sadstore

COPY --from=builder /app/services/kels-sadstore/migrations /app/services/kels-sadstore/migrations

EXPOSE 80

CMD ["/app/kels-sadstore"]
