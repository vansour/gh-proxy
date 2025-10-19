# ============================================================================
# Stage 1: Builder - Compile the Rust application with optimizations
# ============================================================================
FROM rust:trixie AS builder

WORKDIR /app

# Install build dependencies
RUN apt-get update && \
    apt-get install -y pkg-config libssl-dev && \
    rm -rf /var/lib/apt/lists/*

# Copy manifest files
COPY Cargo.toml Cargo.lock* /app/

# Copy source code
COPY src /app/src
COPY config /app/config

# Build with release profile optimizations (defined in Cargo.toml)
# Uses LTO, strip, and maximum optimization levels
RUN cargo build --release

# ============================================================================
# Stage 2: Runtime - Distroless base image with minimal dependencies
# ============================================================================
FROM debian:trixie-slim

# Create non-root user and group for security
# Using numeric IDs (1000:1000) for better container portability
RUN groupadd -r appgroup && useradd -r -g appgroup -u 1000 appuser

# Install only runtime dependencies (CA certificates for HTTPS)
# Use --no-install-recommends to minimize layer size
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        ca-certificates && \
    update-ca-certificates && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

WORKDIR /app

# Copy the optimized binary from builder stage
COPY --from=builder --chown=appuser:appgroup /app/target/release/gh-proxy /app/gh-proxy

# Copy static web files
COPY --chown=appuser:appgroup web /app/web

# Copy default config files
COPY --chown=appuser:appgroup config /app/config-default

# Create config directory for volume mounts with proper permissions
RUN mkdir -p /app/config && \
    chown -R appuser:appgroup /app && \
    chmod 755 /app && \
    chmod 755 /app/config

# Create logs directory with proper permissions
RUN mkdir -p /app/logs && \
    chown -R appuser:appgroup /app/logs && \
    chmod 755 /app/logs

# Copy entrypoint script and set permissions
COPY --chown=appuser:appgroup docker-entrypoint.sh /app/docker-entrypoint.sh
RUN chmod +x /app/docker-entrypoint.sh

# Switch to non-root user for security
USER appuser

# Expose the listening port
EXPOSE 8080

# Health check to detect container failures
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD /app/gh-proxy --healthz || exit 1

# Use the entrypoint script
ENTRYPOINT ["/app/docker-entrypoint.sh"]
