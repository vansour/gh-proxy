# Multi-stage Dockerfile optimization
# Stage 1: Build stage - compile Rust binary
FROM docker.io/rust:1.75-slim-bookworm as builder

WORKDIR /app

# Copy dependency manifests first for better caching
COPY Cargo.toml Cargo.lock ./

# Copy source code
COPY src ./src

# Build in release mode with optimizations
RUN cargo build --release --locked && \
    # Strip debug symbols to reduce binary size
    strip target/release/gh-proxy

# Stage 2: Runtime stage - minimal image
FROM docker.io/debian:bookworm-slim

# Install only essential runtime dependencies
# ca-certificates: For HTTPS/TLS connections
# (curl and wget are not needed for the running container)
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        ca-certificates \
    && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

# Create application directories
WORKDIR /app
RUN mkdir -p /app/logs /app/.defaults/config

# Copy compiled binary from builder
COPY --from=builder /app/target/release/gh-proxy /app/gh-proxy

# Copy configuration files
COPY config /app/.defaults/config
COPY config /app/config
COPY web /app/web

# Copy and set up entrypoint script
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

# Set environment variables
ENV RUST_LOG=info
ENV RUST_BACKTRACE=1

# Health check configuration
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD /usr/bin/curl -f http://localhost:8080/healthz || exit 1

# Expose service port
EXPOSE 8080

# Use non-root user for security (optional, requires setup)
# USER nobody

# Set entrypoint and default command
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
CMD ["/app/gh-proxy"]
