# 正式版发行范围

本文档定义 gh-proxy 首个正式版的产品边界。后续阶段的开发、测试和发布流程，都以这里的范围为准。

## 1. 产品定位

gh-proxy 是一个面向自托管部署的只读代理服务，目标是：

- 为 GitHub 文件、raw 内容、release 资源提供受控代理访问。
- 为 Docker Registry V2 提供只读 `pull` 代理。
- 提供同源 Web UI、健康检查、运行状态接口和 Prometheus 指标。

gh-proxy 不是通用反向代理，也不是开放互联网代理。

## 2. 正式版支持的能力

首个正式版支持以下能力：

- `GET /` 与 `GET /status` 提供同源 Dioxus Web UI。
- `GET /healthz`、`GET /readyz`、`GET /api/config`、`GET /api/stats` 提供运维与状态信息。
- `GET /metrics` 提供 Prometheus 指标，默认仅 loopback 可访问。
- `GET/HEAD /github/{*path}` 提供 GitHub 仓库相对路径代理。
- `GET/HEAD /https://...` fallback 入口提供完整 GitHub URL 代理。
- `GET/HEAD /v2/*` 提供 Docker Registry V2 只读代理，覆盖 manifest/blob 拉取链路。
- `shell.editor = true` 时，对 shell/html 文本中的 GitHub URL 执行代理前缀重写。
- 内存缓存与 CDN 缓存头协同工作。

## 3. 部署前提

首个正式版的生产部署前提如下：

- 服务按“运行在 Cloudflare 或等价受控入口之后”设计。
- 源站应使用固定公开域名，生产环境应配置 `shell.public_base_url`。
- 生产环境应启用 `ingress.auth_header_value`，避免源站被直接绕过公开入口访问。
- `proxy.allowed_hosts` 应收敛到实际需要的最小上游集合。
- `registry.allowed_hosts` 应收敛到实际需要的最小 registry 集合。
- 同源 UI/API 是默认访问模式；浏览器跨站 CORS 代理不是正式版目标。

## 4. 明确不在正式版范围内的能力

以下能力不纳入首个正式版承诺：

- 通用 URL 代理或开放 SSRF 代理。
- GitHub 网页浏览能力，例如仓库首页、issues、pull requests、actions 页面代理。
- GitHub 写操作、登录态透传、用户级鉴权。
- Docker Registry `push`、blob 上传、镜像发布。
- 多租户权限模型、用户系统、配额管理。
- 持久化缓存、分布式缓存、跨节点缓存一致性。
- 跨站浏览器 CORS 代理能力。
- 非文档化 debug 接口的长期兼容保证。

## 5. 关键安全特性

- **路径隔离**: `/github/{*path}` 入口仅接受仓库相对路径，并自动归一化为 `raw.githubusercontent.com` 或 `codeload.github.com`。
- **Host 锁定**: 生产环境强制配置 `shell.public_base_url` 后，所有非 loopback 请求必须匹配该 Host，有效防止绕过 CDN 的 SSRF 攻击。
- **身份透传限制**: 源站会剥离 `CF-Connecting-IP`、`CF-Visitor`、`X-Forwarded-For` 等代理链头，仅在已通过 `ingress.auth_header_value` 认证的请求中才信任并处理这些信息，避免访客隐私泄露给上游 GitHub/Registry。

### 5.1 安全路径匹配规则

正式版实现的路径匹配逻辑如下：

- **GitHub 代理**: 仅允许匹配 `allowed_hosts` 的域名。
- **Docker Registry**: 仅允许 `GET` 与 `HEAD` 操作。
- **SSRF 防御**: `proxy.allowed_hosts` 默认仅包含 GitHub 相关域名，不支持代理任意互联网地址。

## 6. 首个正式版的发布门槛

在正式版发布前，至少满足以下门槛：

1. 发行范围、兼容性承诺和安全模型有独立文档，并与 README 保持一致。
2. GitHub 代理、fallback 代理、Registry 只读代理、缓存、限流、健康检查、metrics 权限控制均有自动化测试覆盖。
3. Docker 镜像可重复构建，并有最小 smoke test 验证。
4. 默认配置对 debug 能力和远端 metrics 维持保守关闭。
5. 已完成一轮 RC 验证，且没有阻断正式版发布的 P0/P1 问题。

## 6. 发行后允许演进的方向

正式版之后可以继续增强，但不应破坏上述边界：

- 扩展更多只读 GitHub/Registry 兼容场景。
- 强化可观测性、压测基线、缓存策略。
- 补充更多部署示例与 Cloudflare 配置模板。
- 在新大版本中讨论更宽泛的代理能力，但不能在小版本里突破安全边界。
