# 兼容性承诺

本文档定义 gh-proxy 从首个正式版开始的兼容性策略。

## 1. 版本策略

- 项目从正式版开始遵循语义化版本。
- `MAJOR` 用于不兼容变更。
- `MINOR` 用于向后兼容的新能力。
- `PATCH` 用于向后兼容的缺陷修复。

如果某项能力被标记为“实验性”或“调试用途”，则不受相同级别的兼容性约束。

## 2. 配置兼容性

以下配置域进入正式版兼容承诺：

- `server`
- `server.pool`
- `shell`
- `ingress`
- `debug`
- `log`
- `auth`
- `registry`
- `proxy`
- `cache`
- `rate_limit`

兼容规则：

- 已发布的 `snake_case` 字段名在同一主版本内不删除、不改语义。
- 旧版 `camelCase` 别名在首个正式版之后继续保留，但视为兼容层，不作为首选写法。
- `registry.default` 的语义固定为“具体 registry origin”，不能在同一主版本内改成通配或非 origin 语义。
- `proxy.allowed_hosts` 与 `registry.allowed_hosts` 的语义固定为 host 白名单，不能在同一主版本内放宽成任意 URL 列表。
- 新字段可以在小版本中增加。
- 字段删除、重命名、语义反转只能发生在大版本。
- 默认值调整如果会显著改变安全边界或缓存语义，应视为 breaking change。

## 3. HTTP 接口兼容性

以下接口进入正式版兼容承诺：

- `GET /`
- `GET /status`
- `GET /healthz`
- `GET /readyz`
- `GET /metrics`
- `GET /api/config`
- `GET /api/stats`
- `GET/HEAD /github/{*path}`
- `GET /registry/healthz`
- `GET/HEAD /v2/*`
- fallback 只读代理入口

兼容规则：

- 已文档化路由在同一主版本内不删除。
- 已文档化只读语义在同一主版本内不放宽为写语义。
- `GET /api/config` 当前文档化字段包括 `server.maxConcurrentRequests`、`server.requestTimeoutSecs`、`shell.editor`、`shell.publicBaseUrl`、`debug.endpointsEnabled`、`registry.default`、`registry.allowedHosts`、`registry.readinessDependsOnRegistry`、`proxy.allowedHosts`、`cache.strategy`、`rateLimit.windowSecs`、`rateLimit.maxRequests`。
- JSON 响应允许增加字段，但已发布字段在同一主版本内不删除、不改类型。
- 非文档化响应头不进入兼容承诺，除非后续被显式文档化。
- `/debug/*` 接口默认视为实验性，不承诺主版本内稳定。

## 4. 指标兼容性

以下 Prometheus 指标族进入正式版兼容承诺：

- `gh_proxy_requests_total`
- `gh_proxy_requests_by_status`
- `gh_proxy_requests_by_type`
- `gh_proxy_requests_by_method`
- `gh_proxy_errors_total`
- `gh_proxy_info`
- `gh_proxy_uptime_seconds`
- `gh_proxy_active_requests`
- `gh_proxy_bytes_transferred_total`

兼容规则：

- 指标名在同一主版本内不变更。
- 已存在标签的含义在同一主版本内不变更。
- 可以增加新指标族。
- 如需删除或重命名指标族，应在大版本中处理。

## 5. 运行环境兼容性

首个正式版的主要支持目标如下：

- 容器部署优先。
- Linux `amd64` 与 `arm64` 为主要发布架构。
- 源码构建以稳定版 Rust 工具链为主，正式版会在发布文档中固定最低支持版本。
- 前端 UI 以现代浏览器为目标，要求支持 `fetch`、`URL`、`Clipboard API`。

以下内容不进入严格兼容承诺：

- 非 Linux 平台运行行为。
- 未发布的本地开发脚本和临时调试流程。
- UI 的视觉细节、布局和文案。

## 6. 兼容性变更流程

如果后续需要调整兼容性范围，应遵循以下流程：

1. 先在文档中声明当前行为是否稳定。
2. 若为 breaking change，必须在变更进入主分支前标记目标大版本。
3. 若为弃用但仍兼容，至少提前一个小版本给出迁移说明。
4. README、配置模板和变更日志必须同步更新。
