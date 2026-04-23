# syntax=docker/dockerfile:1
# Multi-stage build for KELS Registry service
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

# Copy source code
COPY lib/derive /app/lib/derive
COPY lib/kels /app/lib/kels
COPY services/registry /app/services/registry

# Build with BuildKit cache mounts
# TRUSTED_REGISTRY_MEMBERS must be provided at build time for zero-trust federation
ARG TRUSTED_REGISTRY_MEMBERS
WORKDIR /app/services/registry
RUN --mount=type=cache,id=kels-cargo-registry,target=/usr/local/cargo/registry \
    --mount=type=cache,id=registry-target,target=/app/services/registry/target \
    TRUSTED_REGISTRY_MEMBERS="${TRUSTED_REGISTRY_MEMBERS}" \
    cargo build --release --bin registry --bin registry-admin && \
    cp /app/services/registry/target/release/registry /app/registry && \
    cp /app/services/registry/target/release/registry-admin /app/registry-admin

# Final stage
FROM debian:bookworm-slim

WORKDIR /app

# Install runtime dependencies
RUN apt-get update && \
    apt-get install -y \
    libstdc++6 \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Copy built binaries
COPY --from=builder /app/registry /app/registry
COPY --from=builder /app/registry-admin /app/registry-admin

# Copy migrations
COPY --from=builder /app/services/registry/migrations /app/services/registry/migrations

EXPOSE 80

CMD ["/app/registry"]
