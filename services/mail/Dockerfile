# syntax=docker/dockerfile:1
# Multi-stage build for KELS Mail service
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
COPY lib/derive /app/lib/derive
COPY lib/kels /app/lib/kels
COPY lib/exchange /app/lib/exchange
COPY services/mail /app/services/mail

# Build with BuildKit cache mounts for cargo registry and target directory
WORKDIR /app/services/mail
RUN --mount=type=cache,id=mail-cargo-registry,target=/usr/local/cargo/registry \
    --mount=type=cache,id=mail-target,target=/app/services/mail/target \
    cargo build --release --bin mail && \
    cp /app/services/mail/target/release/mail /app/mail

# Final stage
FROM debian:bookworm-slim

WORKDIR /app

# Install runtime dependencies
RUN apt-get update && \
    apt-get install -y \
    libstdc++6 \
    && rm -rf /var/lib/apt/lists/*

# Copy built binary
COPY --from=builder /app/mail /app/mail

COPY --from=builder /app/services/mail/migrations /app/services/mail/migrations

EXPOSE 80

CMD ["/app/mail"]
