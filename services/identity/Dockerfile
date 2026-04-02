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
COPY lib/derive /app/lib/derive
COPY lib/kels /app/lib/kels
COPY lib/mock-hsm /app/lib/mock-hsm
COPY services/identity /app/services/identity

# Build mock HSM shared library
WORKDIR /app/lib/mock-hsm
RUN --mount=type=cache,id=kels-cargo-registry,target=/usr/local/cargo/registry \
    --mount=type=cache,id=mock-hsm-target,target=/app/lib/mock-hsm/target \
    cargo build --release && \
    cp /app/lib/mock-hsm/target/release/libkels_mock_hsm.so /app/libkels_mock_hsm.so 2>/dev/null || \
    cp /app/lib/mock-hsm/target/release/libkels_mock_hsm.dylib /app/libkels_mock_hsm.so 2>/dev/null || true

# Build identity service
WORKDIR /app/services/identity
RUN --mount=type=cache,id=kels-cargo-registry,target=/usr/local/cargo/registry \
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
    libstdc++6 \
    && rm -rf /var/lib/apt/lists/*

# Copy built binaries and mock HSM library
COPY --from=builder /app/identity /app/identity
COPY --from=builder /app/identity-admin /app/identity-admin
COPY --from=builder /app/libkels_mock_hsm.so /app/libkels_mock_hsm.so
COPY --from=builder /app/services/identity/migrations /app/services/identity/migrations

# Create HSM data directory
RUN mkdir -p /data/hsm

EXPOSE 80

CMD ["/app/identity"]
