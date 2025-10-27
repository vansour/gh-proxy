# GitHub 文件代理加速器 (gh-proxy)

[![CI](https://github.com/vansour/gh-proxy/workflows/CI/badge.svg)](https://github.com/vansour/gh-proxy/actions)
[![Rust](https://img.shields.io/badge/Rust-1.48.0-orange)](https://www.rust-lang.org/)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Docker](https://img.shields.io/badge/Docker-Supported-blue)](Dockerfile)

一个高性能的 GitHub 文件代理服务，用于加速 GitHub 文件下载，支持 Web UI、REST API 和黑名单功能。

## 🌟 主要特性

- **高性能代理**: 基于 Rust 和 Tokio 异步运行时，支持高并发请求
- **多格式支持**: 支持原始文件、压缩包等多种下载格式
- **Web UI**: 现代化的 Web 界面，支持实时转换
- **REST API**: 灵活的 API 接口，满足不同使用场景
- **黑名单功能**: 支持 IP 和用户黑名单，增强安全性
- **graceful shutdown**: 优雅关闭，确保请求完成
- **日志系统**: 完整的日志记录和追踪功能
- **Cloudflare CDN 优化**: 智能缓存策略、协议检测、客户端 IP 提取、范围请求支持
- **Docker 支持**: 开箱即用的 Docker 部署

## 📋 系统要求

- Rust 1.48.0+（本地构建）
- Docker（Docker 部署）
- Linux/macOS/Windows（开发环境）

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

## ⚙️ 配置指南

编辑 `config/config.toml` 文件进行配置：

```toml
[server]
host = "0.0.0.0"           # 监听地址
port = 8080                # 监听端口
sizeLimit = 2048           # 文件大小限制 (MB)
connectTimeoutSeconds = 30 # 回源连接超时 (秒, 0 表示关闭)
keepAliveSeconds = 90      # 与回源保持连接时长 (秒, 0 表示关闭)
poolMaxIdlePerHost = 8     # 每个源站的最大空闲连接数

[shell]
editor = true              # 是否启用编辑器

[log]
logFilePath = "/app/logs/gh-proxy.log"  # 日志文件路径
maxLogSize = 5             # 最大日志大小 (MB)
level = "info"             # 日志级别: debug, info, warn, error, none

[auth]
token = ""                 # GitHub API token (可选)

[blacklist]
enabled = true             # 是否启用黑名单
blacklistFile = "/app/config/blacklist.json"  # 黑名单文件路径
```

### 黑名单配置

编辑 `config/blacklist.json` 文件：

```json
{
  "explain": "ex_rules为规则使用样例，无实际功能",
  "ex_rules": [
    "1.2.3.4",
    "10.0.0.0/24",
    "172.16.0.0/16",
    "192.168.1.100-192.168.1.200",
    "203.0.113.*"
  ],
  "rules": [
    
  ]
}
```
## 🌐 Web 界面

访问 `http://localhost:8080` 打开 Web UI，支持：

- GitHub 文件链接输入
- 多格式下载选择
- 实时链接转换
- 复制转换结果

## 📡 API 端点

### 健康检查

```bash
GET /healthz
```

响应：
```json
{
  "state": "Ready",
  "active_requests": 0,
  "uptime_secs": 1000,
  "accepting_requests": true
}
```

## 🏗️ 项目结构

```
gh-proxy/
├── src/
│   ├── main.rs           # 应用入口
│   ├── api.rs            # API 路由定义
│   ├── config.rs         # 配置管理
│   ├── github.rs         # GitHub 交互
│   ├── shutdown.rs       # 优雅关闭
│   ├── handlers/         # HTTP 处理器
│   ├── services/         # 业务逻辑服务
│   └── utils/            # 工具函数
├── web/                  # Web UI 资源
│   ├── index.html        # HTML 页面
│   ├── script.js         # JavaScript 脚本
│   └── style.css         # 样式表
├── config/               # 配置文件
│   ├── config.toml       # 主配置文件
│   └── blacklist.json    # 黑名单配置
├── Cargo.toml            # Rust 项目配置
├── Dockerfile            # Docker 镜像定义
├── compose.yml           # Docker Compose 配置
└── README.md            # 本文件
```

## 📦 核心依赖

- **axum**: 现代 Rust Web 框架
- **tokio**: 异步运行时
- **hyper**: HTTP 客户端库
- **serde**: 数据序列化框架
- **tracing**: 日志和追踪

更多依赖详见 `Cargo.toml`。

## ☁️ Cloudflare CDN 优化

本项目针对 Cloudflare CDN 进行了优化，可以显著改善在 Cloudflare 后的缓存效率和用户体验。

### 1. 智能缓存策略

服务器根据文件类型自动添加 `Cache-Control` 和 `s-maxage` 头：

- **小文件** (JS, CSS, HTML, JSON, SVG): `s-maxage=31536000` (1年)
- **发布资产** (releases/download): `immutable, s-maxage=31536000` (1年，不可变)
- **源代码文件** (.rs, .py, .go, etc): `s-maxage=2592000` (30天)
- **其他内容**: `s-maxage=86400` (1天)

### 2. 缓存验证头

自动保留或生成：
- **ETag**: 用于条件请求 (304 Not Modified)
- **Last-Modified**: 支持客户端缓存验证
- **Accept-Ranges**: 启用范围请求和部分内容缓存

### 3. 协议检测 (Cloudflare 感知)

智能检测请求协议，支持 Cloudflare 特定头：

| 优先级 | 头字段 | 说明 |
|------|-------|------|
| 1 | `cf-visitor` | Cloudflare 访问者协议 (`{"scheme":"https"}`) |
| 2 | `X-Forwarded-Proto` | 标准代理协议头 |
| 3 | URI scheme | 请求 URI 中的协议 |
| 4 | 启发式判断 | 根据主机名和端口 |

### 4. 客户端 IP 提取 (Cloudflare 优先)

准确识别真实客户端 IP，优先级顺序：

| 优先级 | 头字段 | 说明 |
|------|-------|------|
| 1 | `cf-connecting-ip` | Cloudflare 连接 IP |
| 2 | `X-Forwarded-For` | 代理链 IP |
| 3 | `Forwarded` | RFC 7239 标准头 |
| 4 | `True-Client-IP` | Akamai/CF 备用 |
| 5 | `X-Real-IP` | nginx/reverse proxy |
| 6 | 连接信息 | 直接连接的源 IP |

### 5. 范围请求支持

- 保留 `Range` 和 `Accept-Ranges` 头
- 支持断点续传和分块下载
- Cloudflare 可缓存部分内容 (206 Partial Content)

### 使用建议

1. **配置 Cloudflare Cache Level**: 设置为 "Cache Everything" 或 "Standard"
2. **启用 Edge Caching TTL**: 配置与返回的 `Cache-Control` 头相匹配
3. **启用 Gzip 压缩**: Cloudflare 自动处理压缩
4. **设置 Browser Cache TTL**: 配合 `max-age` 使用

### 性能提示

- 发布资产和存档被标记为 `immutable`，Cloudflare 将永久缓存
- 源代码文件使用 30 天缓存，平衡新鲜度和性能
- 小文件使用最长缓存周期，减少源站流量
- 范围请求支持让大文件下载可在边缘节点恢复

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

### 自动格式化

可以使用以下命令自动格式化代码：

```bash
cargo fmt --all
```

## 📝 许可证

本项目采用 MIT 许可证。详见 [LICENSE](LICENSE) 文件。

## 👥 贡献

欢迎提交 Issue 和 Pull Request！

## 📧 联系方式

- GitHub Issues: [gh-proxy/issues](https://github.com/vansour/gh-proxy/issues)
- 项目主页: [gh-proxy](https://github.com/vansour/gh-proxy)