# Build stage
FROM rust:trixie AS builder

WORKDIR /app

# Pre-copy manifest to leverage build cache
COPY Cargo.toml ./

# Create dummy src to satisfy cargo while caching dependencies
RUN mkdir src && echo "fn main() {}" > src/main.rs && cargo build --release && rm -rf src

# Copy actual sources
COPY src ./src
COPY config ./config

RUN cargo build --release

# Final runtime stage - requirement: base on rust:trixie
FROM rust:trixie
WORKDIR /app

COPY --from=builder /app/target/release/gh-proxy /usr/local/bin/gh-proxy
COPY config ./config
COPY web ./web

# Create log directory
RUN mkdir -p /app/logs

ENV GH_PROXY_CONFIG=/app/config/config.toml
EXPOSE 8080

CMD ["gh-proxy"]
