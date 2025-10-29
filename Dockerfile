FROM ghcr.io/vansour/rust:trixie AS builder
WORKDIR /app
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo build --release && strip target/release/gh-proxy
FROM ghcr.io/vansour/debian:trixie-slim
RUN apt update && DEBIAN_FRONTEND=noninteractive apt install -y --no-install-recommends ca-certificates tzdata && apt clean && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*
ENV TZ=Asia/Shanghai
RUN ln -snf /usr/share/zoneinfo/Asia/Shanghai /etc/localtime && echo "Asia/Shanghai" > /etc/timezone
WORKDIR /app
RUN mkdir -p /app/logs /app/.defaults/config
COPY --from=builder /app/target/release/gh-proxy /app/gh-proxy
COPY config /app/.defaults/config
COPY config /app/config
COPY web /app/web
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh
ENV RUST_LOG=info
ENV RUST_BACKTRACE=1
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD /usr/bin/curl -f http://localhost:8080/healthz || exit 1
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
CMD ["/app/gh-proxy"]
