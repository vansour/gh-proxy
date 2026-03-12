# 发布运行手册

本文档定义 gh-proxy 首个正式版阶段的最小发布流程。目标不是复杂化发版，而是保证镜像、版本号和仓库状态之间可追踪、可验证。

## 1. 发布前提

准备正式版或 RC 标签前，至少确认以下条件：

1. `main` 分支的 CI 为绿色。
2. 工作区、后端、前端版本号已经同步更新。
3. `docs/RELEASE_SCOPE.md`、`docs/COMPATIBILITY.md`、`docs/SECURITY_MODEL.md` 没有与当前实现冲突的内容。
4. 本地或 CI 已通过 `bash docker/smoke-test.sh`。
5. 如果 `ghcr.io/<owner>/gh-proxy` 已存在，确认该 GHCR package 已关联当前仓库，或已在 package 设置的 `Manage Actions access` 中授予当前仓库写权限。

## 2. 版本号规则

- Git tag 使用 `vX.Y.Z` 或 `vX.Y.Z-rc.N` 形式。
- `Cargo.toml`、`backend/Cargo.toml`、`frontend/dioxus-app/Cargo.toml` 中的版本号必须与 tag 去掉前缀 `v` 后完全一致。
- 已发布 tag 不重写、不复用。发现问题时发布新的 patch / RC tag。

## 3. 自动发布流程

仓库内置 `Release` workflow，支持两种入口：

1. 推送 tag，例如 `git tag v1.2.1 && git push origin v1.2.1`
2. 在 GitHub Actions 页面手动触发，并填写 `release_tag`

工作流会执行以下动作：

1. 校验 release tag 格式。
2. 校验 tag 对应版本与 workspace / backend / frontend 清单文件一致。
3. 重新执行后端测试、前端测试和 Docker smoke test。
4. 构建并推送多架构 OCI 镜像到 `ghcr.io/<owner>/gh-proxy`。
5. 为镜像生成 OCI labels、SBOM 与 provenance。
6. 校验发布后的 manifest list 同时包含 `linux/amd64` 和 `linux/arm64`。

发布 workflow 默认使用 `GITHUB_TOKEN` 推送 GHCR；如果 package 没有继承当前仓库权限，可额外配置以下 secrets 作为兜底：

- `GHCR_USERNAME`：拥有目标 package 写权限的 GitHub 用户名。
- `GHCR_TOKEN`：对应账户的 PAT，至少包含 `write:packages`，如需拉取校验可同时带 `read:packages`。

## 4. 镜像 tag 策略

对于稳定版 `v1.2.1`，发布工作流会推送：

- `ghcr.io/<owner>/gh-proxy:1.2.1`
- `ghcr.io/<owner>/gh-proxy:v1.2.1`
- `ghcr.io/<owner>/gh-proxy:1.2`
- `ghcr.io/<owner>/gh-proxy:1`
- `ghcr.io/<owner>/gh-proxy:latest`
- `ghcr.io/<owner>/gh-proxy:sha-<gitsha>`

对于预发布版本，例如 `v1.2.1-rc.1`，不会推送 `latest`、主版本浮动 tag 或大版本浮动 tag。

## 5. 发布后检查

发布成功后，至少确认以下内容：

1. GHCR 中可见目标 tag。
2. `docker buildx imagetools inspect ghcr.io/<owner>/gh-proxy:<version>` 返回 `amd64` 与 `arm64` 两个平台。
3. 使用新版本镜像启动容器后，`/healthz`、`/readyz`、`/api/config` 和 `/` 可正常访问。
4. 如果本次改动涉及安全边界，README 与文档中的相关说明已同步更新。

## 6. 回滚原则

- 不删除也不重写已发布 tag。
- 如果某个版本存在问题，发布下一个修复版本，例如 `v1.2.2`。
- 如果只是 `latest` 指向不合适，应通过新的稳定 tag 覆盖，而不是手动篡改历史 tag。

## 7. 常见失败排查

- `failed to push ... denied: permission_denied: write_package`：优先检查 GHCR package 是否已绑定当前仓库，或是否在 package 的 `Manage Actions access` 中允许当前仓库写入。
- 同样的错误如果只在 Actions 中出现、本地 PAT 推送正常：为仓库配置 `GHCR_USERNAME` 与 `GHCR_TOKEN` secrets，然后重新运行 `Release` workflow。
- `Node.js 20 actions are deprecated` 只是弃用告警，不会导致当前镜像推送失败；可以单独安排升级 actions 版本。
