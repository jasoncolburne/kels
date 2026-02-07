# syntax=docker/dockerfile:1
# Multi-stage build for HSM service with SoftHSM2
FROM rust:bookworm AS builder

WORKDIR /app

# Install build dependencies
RUN apt-get update && \
    apt-get install -y \
    clang \
    libclang-dev \
    llvm-dev \
    build-essential \
    softhsm2 \
    && rm -rf /var/lib/apt/lists/*

# Copy all source code
COPY services/hsm /app/services/hsm

# Build with BuildKit cache mounts for cargo registry and target directory
WORKDIR /app/services/hsm
RUN --mount=type=cache,id=kels-cargo-registry,target=/usr/local/cargo/registry \
    --mount=type=cache,id=hsm-target,target=/app/services/hsm/target \
    cargo build --release && \
    cp /app/services/hsm/target/release/hsm /app/hsm

# Final stage
FROM debian:bookworm-slim

WORKDIR /app

# Install SoftHSM2 runtime
RUN apt-get update && \
    apt-get install -y \
    ca-certificates \
    libssl3 \
    libstdc++6 \
    softhsm2 \
    && rm -rf /var/lib/apt/lists/*

# Create SoftHSM2 directories
RUN mkdir -p /var/lib/softhsm/tokens && \
    chmod 755 /var/lib/softhsm /var/lib/softhsm/tokens

# Configure SoftHSM2
RUN echo "directories.tokendir = /var/lib/softhsm/tokens" > /etc/softhsm/softhsm2.conf && \
    echo "objectstore.backend = file" >> /etc/softhsm/softhsm2.conf && \
    echo "log.level = INFO" >> /etc/softhsm/softhsm2.conf

# Initialize a token (PIN: 1234, SO-PIN: 12345678)
RUN softhsm2-util --init-token --slot 0 --label "kels-hsm" --pin 1234 --so-pin 12345678

# Copy built binary
COPY --from=builder /app/hsm /app/hsm

# Set environment variables for SoftHSM2
ENV SOFTHSM2_LIBRARY=/usr/lib/softhsm/libsofthsm2.so
ENV HSM_SLOT=0
ENV HSM_PIN=1234

EXPOSE 80

CMD ["/app/hsm"]
