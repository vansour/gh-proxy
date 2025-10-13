# Favicon 支持修复

## 问题描述
用户尝试添加网站图标 `gh-proxy.png`，但遇到错误：
```
Invalid Request
The path 'gh-proxy.png' is not a valid proxy target.
```

## 原因分析
1. HTML 中添加了 `<link rel="icon" href="/gh-proxy.png">`
2. 但后端路由没有配置 `/gh-proxy.png` 路径
3. 请求被 fallback 路由处理，返回"无效的代理目标"错误
4. 原 `serve_static_file` 函数使用 `read_to_string`，无法处理二进制图片文件

## 修复方案

### 1. 添加路由支持
在 `src/main.rs` 中添加 PNG 文件路由：

```rust
.route("/gh-proxy.png", get(serve_static_file))
```

### 2. 修改静态文件服务函数
将 `serve_static_file` 函数从文本文件读取改为二进制文件读取：

**修改前：**
```rust
async fn serve_static_file(uri: axum::http::Uri) -> impl axum::response::IntoResponse {
    // 使用 read_to_string（仅支持文本文件）
    match std::fs::read_to_string(&file_path) {
        // ...
    }
}
```

**修改后：**
```rust
async fn serve_static_file(uri: axum::http::Uri) -> Response<Body> {
    let content_type = match path {
        "style.css" => "text/css; charset=utf-8",
        "app.js" => "application/javascript; charset=utf-8",
        "gh-proxy.png" => "image/png",  // 新增 PNG 支持
        _ => "text/plain; charset=utf-8",
    };

    // 使用 read（支持二进制文件）
    match std::fs::read(&file_path) {
        Ok(content) => Response::builder()
            .status(StatusCode::OK)
            .header(hyper::header::CONTENT_TYPE, content_type)
            .body(Body::from(content))
            .unwrap(),
        // ...
    }
}
```

## 使用说明

### 1. 准备图标文件
将 `gh-proxy.png` 文件放到 `/github/gh-proxy/web/` 目录：
```bash
# 推荐尺寸：192x192 像素或更大
cp your-icon.png /github/gh-proxy/web/gh-proxy.png
```

### 2. 重新构建并部署
```bash
cd /github/gh-proxy
docker compose down
docker compose up --build -d
```

### 3. 验证
访问 `http://your-domain/gh-proxy.png` 应该能看到图标文件。
浏览器标签页会显示自定义图标。

## 扩展支持

如果需要支持更多静态文件类型（如 favicon.ico、其他图片等），只需：

1. 在路由中添加路径：
```rust
.route("/favicon.ico", get(serve_static_file))
.route("/logo.svg", get(serve_static_file))
```

2. 在 `content_type` 匹配中添加 MIME 类型：
```rust
let content_type = match path {
    "style.css" => "text/css; charset=utf-8",
    "app.js" => "application/javascript; charset=utf-8",
    "gh-proxy.png" => "image/png",
    "favicon.ico" => "image/x-icon",
    "logo.svg" => "image/svg+xml",
    _ => "text/plain; charset=utf-8",
};
```

## 常见 MIME 类型参考

| 文件类型 | MIME 类型 |
|---------|----------|
| .png | image/png |
| .jpg/.jpeg | image/jpeg |
| .gif | image/gif |
| .svg | image/svg+xml |
| .ico | image/x-icon |
| .webp | image/webp |
| .css | text/css |
| .js | application/javascript |
| .json | application/json |
| .xml | application/xml |
| .html | text/html |

## 测试结果
✅ PNG 图标文件正确加载
✅ CSS 和 JS 文件继续正常工作
✅ 浏览器标签页显示自定义图标
✅ 支持二进制和文本文件混合服务
