# 生产部署安全检查表

本文档给出 gh-proxy 在生产环境中的最小安全部署要求。它是 [SECURITY_MODEL.md](SECURITY_MODEL.md) 的操作化版本。

## 1. 必做项

以下项目在正式生产部署中应全部满足：

1. 服务只通过 Cloudflare 或等价受控入口暴露。
2. 源站只接收固定公开域名，配置 `shell.public_base_url`。
3. 源站启用共享密钥头校验，配置 `ingress.auth_header_value`。
4. `proxy.allowed_hosts` 仅包含实际要代理的上游域名。
5. `registry.allowed_hosts` 仅包含实际要代理的 registry host。
6. `debug.endpoints_enabled = false`。
7. `debug.metrics_enabled = false`，除非确认需要远端抓取 metrics。
8. 源站安全组、防火墙或上游 ACL 不对公网直接放开管理面。
9. 发布前完成 `cargo audit` 与 `cargo deny` 检查。

## 2. 推荐配置模板

以下配置适合作为生产环境起点：

```toml
[shell]
editor = true
public_base_url = "https://gh-proxy.example.com"

[ingress]
auth_header_name = "x-gh-proxy-origin-auth"
auth_header_value = "replace-with-random-secret"

[debug]
endpoints_enabled = false
metrics_enabled = false

[registry]
default = "registry-1.docker.io"
allowed_hosts = ["registry-1.docker.io", "ghcr.io"]

[proxy]
allowed_hosts = [
  "github.com",
  "*.github.com",
  "githubusercontent.com",
  "*.githubusercontent.com",
]
```

如果生产环境并不需要文本重写能力，可以把 `shell.editor` 设为 `false`，但仍建议保留 `shell.public_base_url` 作为 Host pinning 基线。

## 3. Cloudflare 侧建议

### 3.1 DNS 与入口

- 为 gh-proxy 使用独立子域名，例如 `gh-proxy.example.com`。
- 只通过该公开域名暴露服务。
- 不要把源站 IP 直接公布到其他 DNS 记录。

### 3.2 源站共享密钥头

建议由 Cloudflare Transform Rule、Worker 或等价入口能力向源站注入：

- Header name: `x-gh-proxy-origin-auth`
- Header value: 与 `ingress.auth_header_value` 完全一致

这样即使源站 IP 泄露，也不能仅靠伪造 `Host` 直接访问源站。

### 3.3 缓存与路径规则

- `/api/*`
- `/healthz`
- `/readyz`
- `/metrics`
- `/registry/healthz`
- `/debug/*`

以上路径不应被 Cloudflare 页面规则或自定义缓存策略强行缓存。

## 4. 源站侧建议

- 仅开放服务端口给受控入口或受信网络。
- 如果需要远端 Prometheus 抓取，再显式开启 `debug.metrics_enabled = true`。
- 定期轮换 `ingress.auth_header_value`。
- 如果确实要代理多个 registry，只把需要的 registry host 显式加入 `registry.allowed_hosts`。
- 为 `config/config.toml` 设置最小必要权限。
- 对日志和容器编排平台设置容量与保留策略。

## 5. 发布前检查

每次准备发布或升级前，至少执行：

```bash
cargo fmt --all
cargo test -p gh-proxy
cargo test -p gh-proxy-frontend
cargo clippy -p gh-proxy --all-targets --all-features -- -D warnings
cargo clippy -p gh-proxy-frontend --all-targets --all-features -- -D warnings
cargo audit
cargo deny check advisories bans licenses sources
```

## 6. 上线后验证

部署完成后，至少验证以下行为：

1. `GET /healthz` 返回 200。
2. `GET /readyz` 返回 200，或在依赖 registry 时给出符合预期的状态。
3. 使用错误 `Host` 访问源站时返回拒绝。
4. 不带共享密钥头直接访问源站时返回拒绝。
5. `/metrics` 默认不能被远端直接访问。
6. `/debug/blob-info` 默认不能访问。
7. GitHub 文件代理和 Registry `pull` 正常工作。

## 7. 常见误配置

- 未设置 `shell.public_base_url`，导致远端 Host pinning 失效。
- 未设置 `ingress.auth_header_value`，导致源站身份边界过弱。
- 把 `/api/*` 或 `/metrics` 配成边缘缓存路径。
- 将 `proxy.allowed_hosts` 放得过宽，把服务变成高风险代理。
- 将 `registry.allowed_hosts` 放得过宽，把 registry 代理变成任意出站入口。
- 线上打开 `debug.endpoints_enabled` 后忘记关闭。
