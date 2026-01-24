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
COPY lib/kels-derive /app/lib/kels-derive
COPY lib/kels /app/lib/kels
COPY services/kels-registry /app/services/kels-registry

# Build with BuildKit cache mounts
WORKDIR /app/services/kels-registry
RUN --mount=type=cache,id=kels-registry-cargo,target=/usr/local/cargo/registry \
    --mount=type=cache,id=kels-registry-target,target=/app/services/kels-registry/target \
    cargo build --release --bin kels-registry --bin kels-registry-admin && \
    cp /app/services/kels-registry/target/release/kels-registry /app/kels-registry && \
    cp /app/services/kels-registry/target/release/kels-registry-admin /app/kels-registry-admin

# Final stage
FROM debian:bookworm-slim

WORKDIR /app

# Install runtime dependencies
RUN apt-get update && \
    apt-get install -y \
    ca-certificates \
    libstdc++6 \
    && rm -rf /var/lib/apt/lists/*

# Copy built binaries
COPY --from=builder /app/kels-registry /app/kels-registry
COPY --from=builder /app/kels-registry-admin /app/kels-registry-admin

# Copy migrations
COPY --from=builder /app/services/kels-registry/migrations /app/services/kels-registry/migrations

EXPOSE 80

CMD ["/app/kels-registry"]
