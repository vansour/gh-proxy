FROM ghcr.io/vansour/rust:trixie AS builder
WORKDIR /app
COPY Cargo.toml Cargo.lock ./
COPY src ./src

# Install build dependencies including make
# 'build-essential' includes gcc, g++, make, etc. required for tikv-jemalloc-sys
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    make \
    && rm -rf /var/lib/apt/lists/*

RUN cargo build --release && strip target/release/gh-proxy

# Revert to the requested Debian base image
FROM ghcr.io/vansour/debian:trixie-slim

# Install runtime dependencies
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    ca-certificates \
    tzdata \
    curl \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

ENV TZ=Asia/Shanghai
RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone

WORKDIR /app
RUN mkdir -p /app/logs /app/.defaults/config

# Copy the binary
COPY --from=builder /app/target/release/gh-proxy /app/gh-proxy

# Copy static resources & config defaults
COPY config /app/.defaults/config
COPY config /app/config
COPY web /app/web

# Restore entrypoint script
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

ENV RUST_LOG=info
ENV RUST_BACKTRACE=1

# Restore healthcheck using curl
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD /usr/bin/curl -f http://localhost:8080/healthz || exit 1

EXPOSE 8080

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
CMD ["/app/gh-proxy"]