# syntax=docker/dockerfile:1
# Multi-stage build for Identity service
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
COPY services/identity /app/services/identity

# Build with BuildKit cache mounts for cargo registry and target directory
WORKDIR /app/services/identity
RUN --mount=type=cache,id=identity-registry,target=/usr/local/cargo/registry \
    --mount=type=cache,id=identity-target,target=/app/services/identity/target \
    cargo build --release --bin identity --bin identity-admin && \
    cp /app/services/identity/target/release/identity /app/identity && \
    cp /app/services/identity/target/release/identity-admin /app/identity-admin

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

# Copy built binaries
COPY --from=builder /app/identity /app/identity
COPY --from=builder /app/identity-admin /app/identity-admin

COPY --from=builder /app/services/identity/migrations /app/services/identity/migrations

EXPOSE 80

CMD ["/app/identity"]
