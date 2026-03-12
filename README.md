# GitHub 文件代理加速器 (gh-proxy)

[![CI](https://github.com/vansour/gh-proxy/workflows/CI/badge.svg)](https://github.com/vansour/gh-proxy/actions)
[![Rust](https://img.shields.io/badge/Rust-1.93.0-orange)](https://www.rust-lang.org/)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Docker](https://img.shields.io/badge/Docker-Supported-blue)](Dockerfile)

一个高性能的 GitHub 文件代理服务，用于加速 GitHub 文件下载，支持 Dioxus Web UI、REST API、Prometheus 指标和只读 Docker Registry 代理功能。

## 📘 正式版基线文档

为了推进正式版发布，仓库内维护以下基线文档：

- [docs/RELEASE_SCOPE.md](docs/RELEASE_SCOPE.md): 定义首个正式版支持什么、不支持什么。
- [docs/RELEASE_RUNBOOK.md](docs/RELEASE_RUNBOOK.md): 定义正式版 / RC 发布时的最小流程与 tag 规则。
- [docs/COMPATIBILITY.md](docs/COMPATIBILITY.md): 定义配置、接口、指标和运行环境的兼容性承诺。
- [docs/SECURITY_MODEL.md](docs/SECURITY_MODEL.md): 定义正式版安全假设、受保护边界和非目标。
- [docs/PRODUCTION_SECURITY_CHECKLIST.md](docs/PRODUCTION_SECURITY_CHECKLIST.md): 给出生产部署时的安全检查项和 Cloudflare 侧建议。

## 📁 项目结构

```
gh-proxy/
├── backend/              # 后端 Rust 代码
├── frontend/
│   └── dioxus-app/      # 唯一前端来源（Dioxus）
└── README.md          # 本文件
```

## 🌟 主要特性

- **高性能代理**: 基于 Rust 和 Tokio 异步运行时，统一使用 hyper HTTP 客户端
- **多格式支持**: 支持原始文件、压缩包等多种下载格式
- **Web UI**: 基于 Dioxus 的前端界面
- **单一前端来源**: 后端只分发 Dioxus 构建产物
- **REST API**: 灵活的 API 接口，满足不同使用场景
- **IP 限流**: 基于 IP 的请求限流保护（默认 100 请求/分钟/IP）
- **Prometheus 指标**: 丰富的监控指标（按状态码、方法、路径类型分类）
- **graceful shutdown**: 优雅关闭，确保请求完成
- **日志系统**: 完整的日志记录和追踪功能
- **Docker 支持**: 开箱即用的 Docker 部署
- **Docker Registry 代理**: 集成 Docker Registry V2 只读代理，支持 `docker pull` 和 `/v2/*` 读路径

## 🚀 快速开始

### 使用 Docker Compose（推荐）

```bash
docker compose up -d
```

首次启动时，容器会把镜像内置默认配置导出到 `./config/config.toml`，之后直接编辑宿主机上的这个文件即可。

### 本地构建

```bash
# 安装前端构建前置
rustup target add wasm32-unknown-unknown

# 安装 Dioxus CLI
cargo install dioxus-cli --version 0.7.3

# 产出浏览器静态资源
cd frontend/dioxus-app
dx build --release --debug-symbols false

# 运行工作区测试
cd ../..
cargo test -p gh-proxy
cargo test -p gh-proxy-frontend

# 运行后端
cargo run -p gh-proxy
```

本地运行后，后端会优先读取 `/app/web`，如果不存在则回退到
`frontend/dioxus-app/target/dx/gh-proxy-frontend/release/web/public` 下的 Dioxus 构建产物。

## ⚙️ 配置指南

Docker/Compose 部署时，编辑 `./config/config.toml`。

如果还没有这个文件，先执行一次：

```bash
docker compose up -d
```

容器会自动在挂载目录里生成默认配置。

如需在本地验证容器镜像能否完整启动并暴露核心接口，可以直接运行：

```bash
bash docker/smoke-test.sh
```

默认内容如下：

```toml
[server]
size_limit = 2048
request_timeout_secs = 60
max_concurrent_requests = 100
request_size_limit = 10

[server.pool]
idle_timeout_secs = 90
max_idle_per_host = 32
http2_stream_window_size = 2097152
http2_connection_window_size = 8388608

[shell]
editor = false
public_base_url = ""

[ingress]
auth_header_name = "x-gh-proxy-origin-auth"
auth_header_value = ""

[debug]
endpoints_enabled = false
metrics_enabled = false

[log]
level = "info"

[auth]
token = ""

[registry]
default = "registry-1.docker.io"
allowed_hosts = ["registry-1.docker.io"]
readiness_depends_on_registry = false

[proxy]
allowed_hosts = ["github.com", "*.github.com", "githubusercontent.com", "*.githubusercontent.com"]

[cache]
strategy = "memory_with_cdn"
max_size_bytes = 536870912
default_ttl_secs = 3600
max_ttl_secs = 86400
min_object_size = 1024
max_object_size = 104857600
cacheable_patterns = ["/github/*", "/v2/*/blobs/*", "/v2/*/manifests/*"]
bypass_patterns = ["/api/*", "/metrics", "/healthz", "/readyz"]

[rate_limit]
window_secs = 60
max_requests = 100
```

本地源码开发时，默认配置模板仍在 `backend/config/config.toml`，后端如果找不到 `/app/config/config.toml`，会回退到这份仓库内模板。

> **注意**: 配置字段使用 `snake_case` 命名，同时兼容旧版 `camelCase`（如 `sizeLimit`）。

关键配置项：

- `proxy.allowed_hosts`: 允许代理访问的上游域名白名单，重定向也会按这个列表校验。
- `registry.default`: 默认 Docker Registry 上游，支持主机名或完整 origin URL；启动时会规范化为 concrete origin，不支持 wildcard。
- `registry.readiness_depends_on_registry`: 控制 `/readyz` 是否把 registry 可达性纳入 readiness 判定，默认 `false`。
- `registry.allowed_hosts`: Docker Registry 代理允许访问的 registry host 白名单；默认仅允许 `registry.default`。
- `cache.*`: 控制内存缓存策略、对象大小范围和缓存/绕过路径模式。
- `rate_limit.*`: 控制单 IP 的窗口限流参数。
- `server.pool.*`: 控制 Hyper 客户端连接池与 HTTP/2 窗口大小。
- `ingress.auth_header_name` / `ingress.auth_header_value`: 为非 loopback 源站请求增加一道共享密钥头校验。推荐由 Cloudflare Transform Rule / Worker 注入，默认关闭。
- `debug.endpoints_enabled`: 控制内部调试接口（如 `/debug/blob-info`）是否对外暴露，默认关闭。
- `debug.metrics_enabled`: 控制 `/metrics` 是否允许非 loopback 远端访问；默认关闭，仅保留本机抓取。
- `shell.public_base_url`: shell/html 文本重写时使用的对外代理基准地址，生产环境建议显式配置为 Cloudflare 暴露的正式域名，例如 `https://gh-proxy.example.com`。

运行前提：

- 服务按“永远运行在 Cloudflare 后面”设计。源站会优先信任 `CF-Connecting-IP`、`CF-Visitor`、`CF-IPCountry` 来识别真实客户端，并在转发到 GitHub / Registry 上游前主动剥离这些代理链头，避免把访客来源信息继续泄露给上游。
- 源站默认不开放跨站浏览器 CORS；Dioxus 前端按同源模式访问 `/api/*`、`/readyz`。如果第三方站点想把它当浏览器侧跨域代理直接调用，默认会被浏览器拦住。
- 如果启用了 `shell.editor = true`，生产环境还应配置 `shell.public_base_url`。否则服务只会为 localhost/dev 请求自动推导重写前缀，不再直接信任外部传入的 `Host` 头。
- 配置了 `shell.public_base_url` 后，源站还会把它同时当作允许接收的公开 `Host`，非 loopback 的错域名请求会直接被拒绝。这能减少绕过 Cloudflare 后直接拿任意 `Host` 头访问源站的空间。
- 如果设置了 `ingress.auth_header_value`，非 loopback 请求还必须额外带上匹配的 `ingress.auth_header_name` 头；这样即使源站 IP 泄露，也不能只靠伪造 `Host` 和 Cloudflare 头直接访问。
- 出于同样原因，只有 loopback 或已通过源站密钥认证的远端请求，服务才会信任 `CF-Connecting-IP`、`CF-IPCountry`、`X-Forwarded-*` 这些客户端身份头。未启用 `ingress.auth_header_value` 时，远端请求会退回使用 socket 对端地址做限流和日志归因。
- `/metrics` 默认只接受 loopback 访问；如果确实需要让远端 Prometheus 经由 Cloudflare/内网抓取，再显式打开 `debug.metrics_enabled = true`。
- `/api/*`、`/healthz`、`/readyz`、`/metrics`、`/registry/healthz`、`/debug/*` 会显式返回 `Cache-Control: no-store`，避免浏览器或 Cloudflare 误缓存动态状态与运维数据；同源 UI/API 响应也会补充基础安全头。

环境变量 `GH_PROXY_CONFIG` 可覆盖配置文件路径。

## 📡 API 端点

| 端点 | 描述 |
|------|------|
| `GET /` | Dioxus Web UI |
| `GET /healthz` | 轻量存活检查 |
| `GET /readyz` | 就绪检查（默认只反映本地接流能力，同时返回 registry 子状态） |
| `GET /metrics` | Prometheus 指标，默认仅 loopback 可访问 |
| `GET /api/config` | 当前公开运行摘要（供状态页使用的最小配置子集） |
| `GET /api/stats` | 服务、缓存、请求分布与错误统计 |
| `GET/HEAD /github/{*path}` | GitHub 仓库相对路径代理，例如 `owner/repo/main/file.txt` |
| `GET /registry/healthz` | Docker Registry 专项健康检查 |
| `GET /debug/blob-info` | Registry 调试接口，仅在 `debug.endpoints_enabled = true` 时开放 |
| `GET/HEAD /v2/*` | Docker Registry V2 只读代理 |

完整 GitHub URL 走回退入口，例如：

- `/https://github.com/owner/repo/blob/main/file.txt`
- `/https://raw.githubusercontent.com/owner/repo/main/file.txt`
- `/https://github.com/owner/repo/releases/download/v1.0.0/app.tar.gz`

GitHub 代理入口和 fallback 入口都是只读模式，仅支持 `GET` 与 `HEAD`。

### Prometheus 指标

默认情况下，`/metrics` 只对本机开放；远端抓取需要显式设置 `debug.metrics_enabled = true`。

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

## 🔧 开发指南

```bash
# 运行后端测试
cargo test -p gh-proxy

# 运行前端测试
cargo test -p gh-proxy-frontend

# 代码格式化
cargo fmt --all

# 静态检查
cargo clippy -p gh-proxy --all-targets --all-features -- -D warnings
cargo clippy -p gh-proxy-frontend --all-targets --all-features -- -D warnings

# 供应链与安全检查
cargo audit
cargo deny check bans licenses sources

# 构建发布版
cargo build --release -p gh-proxy
```

## 📌 当前能力边界

- 首页用于生成 GitHub 文件、raw 地址和 release 下载地址的代理链接，不支持仅输入 `owner/repo` 仓库首页。
- `/github/*` 仅接受仓库相对路径；如果输入的是完整 GitHub URL，请使用回退入口格式。
- GitHub/file 代理入口是只读模式，仅支持 `GET` 与 `HEAD`，不接受 `POST`、`PUT`、`PATCH` 等写方法。
- Docker Registry 代理当前是只读模式，支持 `pull`，不支持 `push`、blob 上传和镜像发布。
- 调试接口默认关闭；只有在明确启用 `debug.endpoints_enabled = true` 时才会开放 `/debug/blob-info`。
- `GET /healthz` 是轻量存活检查，适合容器 `HEALTHCHECK` 与 liveness probe。
- `GET /readyz` 默认反映服务接流能力，并在响应体中返回 registry 子状态；如需把 registry 可达性也纳入 readiness 判定，可启用 `registry.readiness_depends_on_registry = true`。

## 📝 许可证

MIT License - 详见 [LICENSE](LICENSE)

## 👥 贡献

欢迎提交 Issue 和 Pull Request！

- GitHub Issues: [gh-proxy/issues](https://github.com/vansour/gh-proxy/issues)
- 项目主页: [gh-proxy](https://github.com/vansour/gh-proxy)
