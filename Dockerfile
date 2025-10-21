FROM docker.io/rust:trixie as builder
WORKDIR /app

COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY config ./config
RUN cargo build --release

FROM docker.io/debian:trixie

RUN apt -y update && apt -y upgrade && apt -y full-upgrade && apt -y autoremove && apt -y install wget curl jq sudo vim apt-transport-https ca-certificates cron unzip git gpg e2fsprogs dnsutils iproute2 iputils-ping

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
