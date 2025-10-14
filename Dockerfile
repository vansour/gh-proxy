# Build stage
FROM rust:trixie AS builder

WORKDIR /app

# Copy all sources
COPY Cargo.toml /app/
COPY src /app/src
COPY config /app/config

# Build the project
RUN cargo build --release

# Final runtime stage - use lightweight debian image
FROM debian:trixie-slim
WORKDIR /app

# Install CA certificates for HTTPS connections
RUN apt-get update && \
    apt-get install -y ca-certificates && \
    rm -rf /var/lib/apt/lists/*

# Copy the compiled binary
COPY --from=builder /app/target/release/gh-proxy /app/gh-proxy

# Copy static files
COPY web /app/web

# Copy default config to a separate location
COPY config /app/config-default

# Create empty config directory for volume mount
RUN mkdir -p /app/config

# Copy entrypoint script
COPY docker-entrypoint.sh /app/docker-entrypoint.sh
RUN chmod +x /app/docker-entrypoint.sh

EXPOSE 8080

ENTRYPOINT ["/app/docker-entrypoint.sh"]
