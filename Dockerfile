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
COPY config /app/config

EXPOSE 8080

CMD ["/app/gh-proxy"]
