# GitHub 文件代理加速器 (gh-proxy)

[![CI](https://github.com/vansour/gh-proxy/workflows/CI/badge.svg)](https://github.com/vansour/gh-proxy/actions)
[![Rust](https://img.shields.io/badge/Rust-1.93.0-orange)](https://www.rust-lang.org/)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Docker](https://img.shields.io/badge/Docker-Supported-blue)](Dockerfile)

一个高性能的 GitHub 文件代理服务，用于加速 GitHub 文件下载，支持 Web UI、REST API、Prometheus 指标和 Docker Registry 代理功能。

## 🌟 主要特性

- **高性能代理**: 基于 Rust 和 Tokio 异步运行时，支持高并发请求
- **多格式支持**: 支持原始文件、压缩包等多种下载格式
- **Web UI**: 现代化的 Web 界面，支持实时转换
- **REST API**: 灵活的 API 接口，满足不同使用场景
- **graceful shutdown**: 优雅关闭，确保请求完成
- **日志系统**: 完整的日志记录和追踪功能
- **Cloudflare 集成**: 可选 Cloudflare Analytics 读取（需 Zone ID / API Token）
- **IP 信息服务**: 可选 ipinfo.io 集成，用于返回 IP 的 ASN/信息
- **Docker 支持**: 开箱即用的 Docker 部署
- **Docker Registry 代理（集成）**: 已合并 Docker Registry v2 的代理功能，可通过 /v2/* 路径访问（例如 /v2/library/ubuntu/manifests/latest）。

## 📋 系统要求

- Rust 1.93.0+（本地构建）
- Docker（Docker 部署）
- Linux/macOS/Windows（开发环境）

## ⚙️ 环境变量

- GH_PROXY_CONFIG: 覆盖配置文件位置，默认 `/app/config/config.toml`。


## 🚀 快速开始

### 使用 Docker compose（推荐）

 - 编写compose.yml文件

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

 - 使用docker compose运行
```bash
docker compose up -d
```

### 本地构建测试

```bash
# 安装 Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# 克隆项目
git clone https://github.com/vansour/gh-proxy.git
cd gh-proxy

# 配置设置
cp config/config.toml config/config.toml.local
# 编辑 config/config.toml 文件进行自定义配置

# 构建项目
cargo build --release

# 运行应用
./target/release/gh-proxy
```

示例操作：

```bash
# 通过 gh-proxy 下载 GitHub 上某个文件（自动将 blob 转为 raw）
curl -L http://localhost:8080/github/vansour/gh-proxy/blob/main/README.md

# 拉取 Docker Registry 的 manifest（代理到 /v2/）
curl -L http://localhost:8080/v2/library/ubuntu/manifests/latest

# 查看 Prometheus 指标
curl -s http://localhost:8080/metrics | head -n 20
```

## ⚙️ 配置指南

编辑 `config/config.toml` 文件进行配置：

```toml
[server]
host = "0.0.0.0"           # 监听地址
port = 8080                # 监听端口
# 默认文件大小限制（MB）：125。可以把它调整为更高的值，例如 2048
sizeLimit = 125            # 文件大小限制 (MB)
requestTimeoutSecs = 60    # 请求超时（秒）
maxConcurrentRequests = 50 # 最大并发下载请求

[shell]
editor = true              # 是否启用编辑器（针对脚本/文本内容的链接替换）

[log]
# 日志配置字段在代码中名为 `log_file_path`（snake_case），示意如下：
log_file_path = "/app/log/ghproxy.log"  # 日志文件路径
level = "info"             # 日志级别: debug, info, warn, error, trace, none

[auth]
token = ""                 # GitHub API token（可选），用于提高 GitHub API 限额

[registry]
default = "docker.io"      # 默认镜像仓库

[cloudflare]
zoneId = ""               # Cloudflare zone id（可选）
apiToken = ""             # Cloudflare API Token（需要 analytics:read 权限）

[ipinfo]
token = ""                # ipinfo.io Token（可选）
```
**注意**: 默认读取的配置路径为 `/app/config/config.toml`。你可以通过环境变量 `GH_PROXY_CONFIG` 覆盖配置文件位置，例如：

```bash
export GH_PROXY_CONFIG=/path/to/your/config.toml
```

## 🌐 Web 界面

访问 `http://localhost:8080` 打开 Web UI，支持：

- GitHub 文件链接输入
- 多格式下载选择
- 实时链接转换
- 复制转换结果

另外，集成的 Docker 镜像代理 UI 可在 `http://localhost:8080/docker` 访问，用于生成镜像拉取命令 / 交互式体验。

## 📡 API 端点

### 健康检查

```bash
GET /healthz
```

响应：
```json
{
  "state": "Ready",
  "version": "1.2.0",
  "active_requests": 0,
  "uptime_secs": 1000,
  "accepting_requests": true
}
```

### 获取配置

```
GET /api/config
```

响应示例：

```json
{
  "server": { "sizeLimit": 125 },
  "shell": { "editor": true }
}
```

### 其他 API 与端点

- GET /                    -> Web UI
- GET /healthz             -> 健康检查
- GET /metrics             -> Prometheus 指标
- GET /api/config          -> 返回当前配置（sizeLimit、shell.editor 等）
- GET /api/stats           -> 返回一些服务统计（例如 Cloudflare）
- GET /github/{*path}      -> GitHub 文件代理（会自动转换 blob -> raw）
- GET/HEAD/POST/PUT /v2/*  -> Docker Registry V2 兼容代理端点
- GET /docker              -> Docker 镜像代理交互式 UI

这些端点在默认监听端口 8080 提供（可在配置中修改）。

Prometheus metrics 示例（/metrics）将返回文本格式的指标，例如 HTTP 请求计数、活动请求数、字节传输总数等，供 Prometheus 抓取。

## 🏗️ 项目结构

```
gh-proxy/
├── src/
│   ├── main.rs           # 应用入口
│   ├── api.rs            # API 路由定义
│   ├── config.rs         # 配置管理
│   ├── handlers/         # HTTP 处理器
│   │   ├── mod.rs
│   │   ├── files.rs      # 文件下载处理
│   │   └── health.rs     # 健康检查处理
│   ├── infra/            # 基础设施
│   │   ├── mod.rs
│   │   └── log.rs        # 日志配置
│   ├── providers/        # 数据提供者
│   │   ├── mod.rs
│   │   └── github.rs     # GitHub 交互
│   ├── services/         # 业务逻辑服务
│   │   ├── mod.rs
│   │   ├── client.rs     # HTTP 客户端
│   │   ├── request.rs    # 请求处理
│   │   ├── text_processor.rs # 文本处理流（Shell 编辑器替换逻辑）
│   │   ├── shutdown.rs   # 优雅关闭
│   │   ├── cloudflare.rs # Cloudflare 统计/集成
│   │   └── ipinfo.rs     # IP 信息服务（IP -> ASN / 提示）
│   └── utils/            # 工具函数
│       ├── mod.rs
│       ├── errors.rs     # 错误处理
│       └── url.rs        # URL 处理工具
├── web/                  # Web UI 资源
│   ├── index.html        # HTML 页面
│   ├── script.js         # JavaScript 脚本
│   └── style.css         # 样式表
├── config/               # 配置文件
│   └── config.toml       # 主配置文件
├── Cargo.toml            # Rust 项目配置
├── Cargo.lock            # 依赖版本锁定
├── Dockerfile            # Docker 镜像定义
├── compose.yml           # Docker Compose 配置
└── README.md             # 本文件
```

## 🔧 开发指南


### 代码质量检查

项目配置了自动化 CI/CD 流程，每次提交和 Pull Request 都会运行以下检查：

- **测试**: 运行所有单元测试
- **格式化**: 检查代码格式是否符合 Rust 标准
- **Clippy**: 运行 Rust 静态分析工具

在提交代码前，建议在本地运行以下命令：

```bash
# 运行测试
cargo test

# 检查代码格式
cargo fmt --all -- --check

# 运行 clippy 检查
cargo clippy --all-targets --all-features -- -D warnings

# 构建项目
cargo build --release
```

## 📝 许可证

本项目采用 MIT 许可证。详见 [LICENSE](LICENSE) 文件。

## 👥 贡献

欢迎提交 Issue 和 Pull Request！

## 📧 联系方式

- GitHub Issues: [gh-proxy/issues](https://github.com/vansour/gh-proxy/issues)
- 项目主页: [gh-proxy](https://github.com/vansour/gh-proxy)
