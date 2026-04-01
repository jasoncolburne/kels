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
COPY services/sadstore /app/services/sadstore

# Build with BuildKit cache mounts for cargo registry and target directory
WORKDIR /app/services/sadstore
RUN --mount=type=cache,id=sadstore-cargo-registry,target=/usr/local/cargo/registry \
    --mount=type=cache,id=sadstore-target,target=/app/services/sadstore/target \
    cargo build --release --bin sadstore && \
    cp /app/services/sadstore/target/release/sadstore /app/sadstore

# Final stage
FROM debian:bookworm-slim

WORKDIR /app

# Install runtime dependencies
RUN apt-get update && \
    apt-get install -y \
    libstdc++6 \
    && rm -rf /var/lib/apt/lists/*

# Copy built binary
COPY --from=builder /app/sadstore /app/sadstore

COPY --from=builder /app/services/sadstore/migrations /app/services/sadstore/migrations

EXPOSE 80

CMD ["/app/sadstore"]
