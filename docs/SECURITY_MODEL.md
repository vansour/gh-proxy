# 安全模型

本文档描述 gh-proxy 首个正式版的安全假设、受保护边界和明确非目标。

## 1. 威胁模型与基本假设

gh-proxy 的设计目标不是暴露在无保护的公网环境中充当通用代理。

首个正式版基于以下前提：

- 服务运行在 Cloudflare 或等价受控入口之后。
- 源站公开域名是固定的，生产环境使用 `shell.public_base_url` 绑定。
- 生产环境启用 `ingress.auth_header_value`，由受控入口向源站注入共享密钥头。
- 上游目标通过 `proxy.allowed_hosts` 白名单显式限制。
- Docker Registry 上游通过 `registry.allowed_hosts` 白名单显式限制。
- 服务只提供只读代理，不承担上游写入能力。

如果部署方不满足这些前提，项目的安全边界会明显变弱。

## 2. 受保护的边界

### 2.1 上游访问边界

- fallback 目标 URL 和重定向目标都必须命中 `proxy.allowed_hosts`。
- `/github/*` 只允许解析到 GitHub 相关白名单主机。
- Registry 代理只处理 Registry V2 只读拉取路径。
- 即使镜像名里包含显式 registry host，也必须命中 `registry.allowed_hosts`。

这条边界的目标是避免 gh-proxy 演化成任意上游代理。

### 2.2 源站访问边界

- loopback 请求始终允许访问。
- 非 loopback 请求可通过 `shell.public_base_url` 做 Host pinning。
- 非 loopback 请求可通过 `ingress.auth_header_name` + `ingress.auth_header_value` 做共享密钥校验。

这条边界的目标是减少源站 IP 暴露后的直接访问风险。

### 2.3 客户端身份边界

- 只有在受控部署前提下，服务才应依赖 `CF-Connecting-IP`、`CF-IPCountry`、`X-Forwarded-*` 等身份头。
- 当部署方未启用 origin auth 时，系统应退回使用 socket 对端地址作为主要归因依据。

这条边界的目标是防止任何远端请求都能伪造客户端身份。

### 2.4 数据泄露边界

- 转发到上游前会移除 `cookie`、`origin`、`referer`、`x-forwarded-*`、`cf-*` 等头。
- `/api/*`、`/healthz`、`/readyz`、`/metrics`、`/registry/healthz`、`/debug/*` 默认返回 `no-store`。
- 默认不开放浏览器跨站 CORS。

这条边界的目标是减少客户端隐私、调试信息和运维状态泄露。

## 3. 正式版默认安全姿态

首个正式版的默认安全姿态如下：

- `debug.endpoints_enabled = false`
- `debug.metrics_enabled = false`
- 代理入口只接受只读方法
- Registry 代理只接受只读拉取链路
- 未命中白名单的上游目标直接拒绝

生产环境还应额外执行：

1. 设置 `shell.public_base_url`
2. 设置 `ingress.auth_header_value`
3. 最小化 `proxy.allowed_hosts`
4. 最小化 `registry.allowed_hosts`
5. 仅通过受控入口暴露服务

## 4. 明确的非安全目标

以下内容不属于 gh-proxy 首个正式版的安全承诺：

- 为任意公网用户提供通用匿名代理服务。
- 替代 WAF、DDoS 防护或 Bot 管理系统。
- 对上游内容进行恶意文件检测、内容审查或许可证审计。
- 提供用户级 RBAC、租户隔离或细粒度审计。
- 在源站被完全接管时继续保证数据安全。

## 5. 安全相关的发行阻断条件

以下问题应视为正式版阻断项：

- 可绕过 `proxy.allowed_hosts` 访问未授权上游。
- 可绕过 `registry.allowed_hosts` 访问未授权 registry。
- 可通过重定向跳出白名单。
- 可通过伪造源站 Host 或共享密钥头绕过入口边界。
- 可通过默认配置直接暴露 debug 接口或远端 metrics。
- 可通过代理把客户端敏感头透传给上游。
- 可通过写方法触发 GitHub 或 Registry 上游修改行为。

## 6. 后续安全工作方向

正式版之后，安全工作优先级按以下方向推进：

1. 增加更多针对 Host、redirect、header spoofing、cache poisoning 的自动化测试。
2. 把供应链检查纳入 CI，例如依赖漏洞和许可证审计。
3. 补充生产部署示例，明确 Cloudflare 侧的推荐配置。
4. 评估是否需要更强的 ingress 身份校验机制，而不只是共享密钥头。

生产环境的具体操作项见 [PRODUCTION_SECURITY_CHECKLIST.md](PRODUCTION_SECURITY_CHECKLIST.md)。
