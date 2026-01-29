# Build Stage
FROM rust:latest as builder
WORKDIR /app
COPY . .
RUN cargo build --release

# Runtime Stage
FROM debian:bookworm-slim
WORKDIR /app

# Install Runtime Dependencies for Headless Chrome
RUN apt-get update && apt-get install -y \
    chromium \
    ca-certificates \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/target/release/spectre /usr/local/bin/spectre

# Create non-root user
RUN useradd -m spectre
USER spectre

ENTRYPOINT ["spectre"]
