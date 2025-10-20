FROM rust:trixie as builder
WORKDIR /app

COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY config ./config
RUN cargo build --release

FROM debian:trixie-slim

RUN apt-get update && apt-get install -y \
    ca-certificates \
    curl \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app
RUN mkdir -p /app/logs /app/.defaults/config

# 二进制
COPY --from=builder /app/target/release/gh-proxy /app/gh-proxy

COPY config /app/.defaults/config
COPY config /app/config
COPY web /app/web

# 启动脚本
COPY /entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

ENV RUST_LOG=info
ENV RUST_BACKTRACE=1

EXPOSE 8080

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]

CMD ["/app/gh-proxy"]
