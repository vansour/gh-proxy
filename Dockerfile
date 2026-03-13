FROM rust:latest@sha256:0e6da0c8f06f25e9591f21c0f741cd4ff1086e271c3330f29f6e4e95869c7843 AS builder

WORKDIR /app

ARG TARGETARCH
ARG DX_VERSION=0.7.3
ARG RUST_TOOLCHAIN=1.93.0
ENV CARGO_TARGET_DIR=/app/target

COPY rust-toolchain.toml /app/rust-toolchain.toml

# 下载预编译 Dioxus CLI 并构建前端
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*
RUN case "${TARGETARCH}" in \
        amd64) dx_target="x86_64-unknown-linux-gnu" ;; \
        arm64) dx_target="aarch64-unknown-linux-gnu" ;; \
        *) echo "Unsupported TARGETARCH: ${TARGETARCH}" >&2; exit 1 ;; \
    esac \
    && curl -fsSLO "https://github.com/DioxusLabs/dioxus/releases/download/v${DX_VERSION}/dx-${dx_target}.tar.gz" \
    && curl -fsSLO "https://github.com/DioxusLabs/dioxus/releases/download/v${DX_VERSION}/dx-${dx_target}.sha256" \
    && grep "dx-${dx_target}.tar.gz" "dx-${dx_target}.sha256" | sha256sum -c - \
    && tar -xzf "dx-${dx_target}.tar.gz" -C /usr/local/bin dx \
    && chmod +x /usr/local/bin/dx \
    && rm -f "dx-${dx_target}.tar.gz" "dx-${dx_target}.sha256"
RUN rustup toolchain install "${RUST_TOOLCHAIN}" --profile minimal --component clippy --component rustfmt \
    && rustup target add wasm32-unknown-unknown --toolchain "${RUST_TOOLCHAIN}"
COPY Cargo.toml Cargo.lock /app/
COPY backend/Cargo.toml /app/backend/Cargo.toml
COPY backend/src /app/backend/src
COPY frontend/Cargo.toml /app/frontend/Cargo.toml
COPY frontend/Dioxus.toml /app/frontend/Dioxus.toml
COPY frontend /app/frontend
WORKDIR /app/frontend
RUN dx build --release --debug-symbols false

WORKDIR /app
# 复制后端源码
COPY backend /app/backend

# 构建后端
RUN cargo build --locked --release -p gh-proxy

# 最终镜像
FROM debian:trixie-slim@sha256:1d3c811171a08a5adaa4a163fbafd96b61b87aa871bbc7aa15431ac275d3d430

# 安装运行时依赖
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    ca-certificates \
    tzdata \
    curl \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

ENV TZ=Asia/Shanghai
RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone

WORKDIR /app
RUN mkdir -p /app/logs /app/.defaults/config /app/web

# 复制后端二进制
COPY --from=builder /app/target/release/gh-proxy /app/gh-proxy
COPY docker/entrypoint.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

# 复制配置
COPY backend/config /app/.defaults/config

# 复制 Dioxus 构建产物
COPY --from=builder /app/target/dx/gh-proxy-frontend/release/web/public/ /app/web/

ENV RUST_LOG=info
ENV RUST_BACKTRACE=1

HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD /usr/bin/curl -f http://localhost:8080/healthz || exit 1

EXPOSE 8080

ENTRYPOINT ["/app/entrypoint.sh"]
