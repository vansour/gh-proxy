# GitHub 文件代理加速器 (gh-proxy)

[![CI](https://github.com/vansour/gh-proxy/workflows/CI/badge.svg)](https://github.com/vansour/gh-proxy/actions)
[![Rust](https://img.shields.io/badge/Rust-1.93.0-orange)](https://www.rust-lang.org/)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Docker](https://img.shields.io/badge/Docker-Supported-blue)](Dockerfile)

一个高性能的 GitHub 文件代理服务，用于加速 GitHub 文件下载，支持 Web UI、REST API、Prometheus 指标和 Docker Registry 代理功能。

## 🌟 主要特性

- **高性能代理**: 基于 Rust 和 Tokio 异步运行时，统一使用 hyper HTTP 客户端
- **多格式支持**: 支持原始文件、压缩包等多种下载格式
- **Web UI**: 现代化的 Web 界面，支持实时转换
- **REST API**: 灵活的 API 接口，满足不同使用场景
- **IP 限流**: 基于 IP 的请求限流保护（默认 100 请求/分钟/IP）
- **Prometheus 指标**: 丰富的监控指标（按状态码、方法、路径类型分类）
- **graceful shutdown**: 优雅关闭，确保请求完成
- **日志系统**: 完整的日志记录和追踪功能
- **Cloudflare 集成**: 支持 Cloudflare CDN，自动识别真实客户端 IP
- **Docker 支持**: 开箱即用的 Docker 部署
- **Docker Registry 代理**: 集成 Docker Registry V2 代理，支持 /v2/* 路径

## 📋 系统要求

- Rust 1.93.0+（本地构建）
- Docker（Docker 部署）
- Linux/macOS/Windows（开发环境）

## 🚀 快速开始

### 使用 Docker Compose（推荐）

```yml
services:
  gh-proxy:
    image: ghcr.io/vansour/gh-proxy:latest
    container_name: gh-proxy
    ports:
      - "8080:8080"
    volumes:
      - ./config:/app/config
    environment:
      - GH_PROXY_CONFIG=/app/config/config.toml
    restart: unless-stopped
```

```bash
docker compose up -d
```

### 本地构建

```bash
# 克隆项目
git clone https://github.com/vansour/gh-proxy.git
cd gh-proxy

# 构建并运行
cargo build --release
./target/release/gh-proxy
```

## ⚙️ 配置指南

编辑 `config/config.toml`：

```toml
[server]
host = "0.0.0.0"
port = 8080
size_limit = 2048              # 文件大小限制 (MB)
request_timeout_secs = 60      # 请求超时（秒）
max_concurrent_requests = 100  # 最大并发请求

[shell]
editor = true                  # 启用脚本链接替换

[log]
log_file_path = "/app/logs/gh-proxy.log"
level = "info"                 # debug, info, warn, error

[auth]
token = ""                     # GitHub API token（可选）

[registry]
default = "registry-1.docker.io"

[cloudflare]
zone_id = ""                   # Cloudflare Zone ID（可选）
api_token = ""                 # Cloudflare API Token（可选）
```

> **注意**: 配置字段使用 `snake_case` 命名，同时兼容旧版 `camelCase`（如 `sizeLimit`）。

环境变量 `GH_PROXY_CONFIG` 可覆盖配置文件路径。

## 📡 API 端点

| 端点 | 描述 |
|------|------|
| `GET /` | Web UI |
| `GET /docker` | Docker 代理 UI |
| `GET /healthz` | 健康检查 |
| `GET /metrics` | Prometheus 指标 |
| `GET /api/config` | 当前配置 |
| `GET /api/stats` | 服务统计 |
| `GET /github/{*path}` | GitHub 文件代理 |
| `GET/HEAD/POST/PUT /v2/*` | Docker Registry V2 代理 |

### Prometheus 指标

```
gh_proxy_requests_total              # 总请求数
gh_proxy_requests_by_status{status}  # 按状态码 (2xx/4xx/5xx)
gh_proxy_requests_by_type{type}      # 按类型 (github/registry/api)
gh_proxy_requests_by_method{method}  # 按方法 (GET/POST/HEAD)
gh_proxy_errors_total{error_type}    # 错误计数
gh_proxy_info{version}               # 服务版本
gh_proxy_uptime_seconds              # 运行时间
gh_proxy_active_requests             # 活跃请求数
gh_proxy_bytes_transferred_total     # 传输字节数
```

## 🏗️ 项目结构

```
gh-proxy/
├── src/
│   ├── main.rs              # 应用入口
│   ├── config.rs            # 配置管理
│   ├── state.rs             # 应用状态
│   ├── errors.rs            # 错误处理
│   ├── router.rs            # 路由配置
│   ├── api.rs               # API 处理
│   ├── handlers/            # HTTP 处理器
│   ├── middleware/          # 中间件
│   │   ├── lifecycle.rs     # 请求生命周期
│   │   └── rate_limit.rs    # IP 限流
│   ├── proxy/               # 代理核心
│   │   ├── handler.rs       # 代理处理器
│   │   ├── headers.rs       # 头部处理
│   │   ├── resolver.rs      # URL 解析
│   │   └── stream.rs        # 流处理
│   ├── providers/           # 数据提供者
│   │   ├── github.rs        # GitHub 代理
│   │   └── registry.rs      # Docker Registry 代理
│   ├── services/            # 业务服务
│   │   ├── client.rs        # HTTP 客户端 (hyper)
│   │   ├── cloudflare.rs    # Cloudflare 集成
│   │   ├── shutdown.rs      # 优雅关闭
│   │   └── text_processor.rs
│   └── infra/               # 基础设施
│       ├── log.rs           # 日志
│       └── metrics.rs       # Prometheus 指标
├── web/                     # Web UI
├── config/                  # 配置文件
├── Dockerfile
└── compose.yml
```

## 🔧 开发指南

```bash
# 运行测试
cargo test

# 代码格式化
cargo fmt

# 静态检查
cargo clippy --all-targets -- -D warnings

# 构建发布版
cargo build --release
```

## 📝 许可证

MIT License - 详见 [LICENSE](LICENSE)

## 👥 贡献

欢迎提交 Issue 和 Pull Request！

- GitHub Issues: [gh-proxy/issues](https://github.com/vansour/gh-proxy/issues)
- 项目主页: [gh-proxy](https://github.com/vansour/gh-proxy)
