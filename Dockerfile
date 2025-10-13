# Build stage
FROM rust:trixie AS builder

WORKDIR /app

# Copy all sources
COPY Cargo.toml ./
COPY src ./src
COPY config ./config

# Build the project
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
