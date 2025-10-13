// API 配置
const API_BASE_URL = window.location.origin;
const API_ENDPOINTS = {
    config: '/api/config',
    health: '/healthz'
};

// 状态管理
let appConfig = null;
let currentDomain = window.location.host;
let currentProtocol = window.location.protocol; // 'http:' or 'https:'
let isHttps = currentProtocol === 'https:';

// 初始化应用
document.addEventListener('DOMContentLoaded', async () => {
    await checkServerStatus();
    await loadConfig();
    initializeTabs();
    updateDomainInExamples();
    checkDockerHttpWarning();
});

// 检查服务器状态
async function checkServerStatus() {
    const statusBadge = document.getElementById('statusBadge');
    
    try {
        const response = await fetch(`${API_BASE_URL}${API_ENDPOINTS.health}`);
        
        if (response.ok) {
            statusBadge.classList.add('online');
            statusBadge.querySelector('span:last-child').textContent = '服务正常';
        } else {
            throw new Error('Server returned error status');
        }
    } catch (error) {
        console.error('Health check failed:', error);
        statusBadge.classList.add('offline');
        statusBadge.querySelector('span:last-child').textContent = '服务异常';
        showToast('无法连接到服务器', 'error');
    }
}

// 加载配置
async function loadConfig() {
    try {
        const response = await fetch(`${API_BASE_URL}${API_ENDPOINTS.config}`);
        
        if (!response.ok) {
            throw new Error('Failed to load config');
        }
        
        appConfig = await response.json();
        console.log('Loaded config:', appConfig);
        
        updateConfigUI();
    } catch (error) {
        console.error('Error loading config:', error);
        showToast('加载配置失败', 'error');
        
        // 设置默认值
        setDefaultConfig();
    }
}

// 更新配置 UI
function updateConfigUI() {
    if (!appConfig) {
        setDefaultConfig();
        return;
    }
    
    // 更新文件大小限制
    const sizeLimit = appConfig.server?.sizeLimit || 0;
    const sizeLimitEl = document.getElementById('sizeLimit');
    if (sizeLimitEl) {
        sizeLimitEl.textContent = sizeLimit;
    }
    
    // 更新 Docker 状态
    const dockerEnabled = appConfig.docker?.enabled ? '✅ 已启用' : '❌ 未启用';
    const dockerEnabledEl = document.getElementById('dockerEnabled');
    if (dockerEnabledEl) {
        dockerEnabledEl.textContent = dockerEnabled;
    }
    
    // 更新黑名单状态
    const blacklistEnabled = appConfig.blacklist?.enabled ? '✅ 已启用' : '❌ 未启用';
    const blacklistEnabledEl = document.getElementById('blacklistEnabled');
    if (blacklistEnabledEl) {
        blacklistEnabledEl.textContent = blacklistEnabled;
    }
    
    // 更新编辑器状态
    const editorEnabled = appConfig.shell?.editor ? '✅ 已启用' : '❌ 未启用';
    const editorEnabledEl = document.getElementById('editorEnabled');
    if (editorEnabledEl) {
        editorEnabledEl.textContent = editorEnabled;
    }
    
    // 如果 Docker 未启用，禁用 Docker 标签
    if (!appConfig.docker?.enabled) {
        const dockerTab = document.querySelector('[data-tab="docker"]');
        if (dockerTab) {
            dockerTab.style.opacity = '0.5';
            dockerTab.style.cursor = 'not-allowed';
            dockerTab.title = 'Docker 代理功能未启用';
        }
    }
}

// 设置默认配置
function setDefaultConfig() {
    const elements = ['sizeLimit', 'dockerEnabled', 'blacklistEnabled', 'editorEnabled'];
    elements.forEach(id => {
        const el = document.getElementById(id);
        if (el) {
            el.textContent = '-';
        }
    });
}

// 初始化标签页
function initializeTabs() {
    const tabButtons = document.querySelectorAll('.tab-button');
    
    tabButtons.forEach(button => {
        button.addEventListener('click', () => {
            const tabName = button.getAttribute('data-tab');
            
            // 如果 Docker 未启用且点击的是 Docker 标签，阻止切换
            if (tabName === 'docker' && appConfig && !appConfig.docker?.enabled) {
                showToast('Docker 代理功能未启用', 'error');
                return;
            }
            
            // 移除所有活动状态
            tabButtons.forEach(btn => btn.classList.remove('active'));
            document.querySelectorAll('.tab-content').forEach(content => {
                content.classList.remove('active');
            });
            
            // 添加当前活动状态
            button.classList.add('active');
            document.getElementById(`${tabName}-content`).classList.add('active');
        });
    });
}

// 更新示例中的域名
function updateDomainInExamples() {
    const codeBlocks = document.querySelectorAll('.code-block code');
    
    codeBlocks.forEach(code => {
        const text = code.textContent;
        if (text.includes('your-domain.com')) {
            code.textContent = text.replace(/your-domain\.com/g, currentDomain);
        }
    });
}

// 复制示例命令
function copyExample(type) {
    let textToCopy = '';
    
    const examples = {
        'github-domain': `https://${currentDomain}/github.com/user/repo/file`,
        'github-path': `https://${currentDomain}/github/user/repo/file`,
        'git-clone': `git clone https://${currentDomain}/github.com/user/repo.git`,
        'docker-hub': `docker pull ${currentDomain}/nginx:latest`,
        'ghcr': `docker pull ${currentDomain}/ghcr.io/user/image:tag`,
        'gcr': `docker pull ${currentDomain}/gcr.io/project/image:tag`,
        'k8s': `docker pull ${currentDomain}/registry.k8s.io/image:tag`
    };
    
    textToCopy = examples[type] || '';
    
    if (textToCopy) {
        copyToClipboard(textToCopy);
        showToast('已复制到剪贴板 ✓', 'success');
    }
}

// 复制到剪贴板
async function copyToClipboard(text) {
    try {
        if (navigator.clipboard && navigator.clipboard.writeText) {
            await navigator.clipboard.writeText(text);
        } else {
            // 降级方案
            const textarea = document.createElement('textarea');
            textarea.value = text;
            textarea.style.position = 'fixed';
            textarea.style.opacity = '0';
            document.body.appendChild(textarea);
            textarea.select();
            document.execCommand('copy');
            document.body.removeChild(textarea);
        }
    } catch (error) {
        console.error('Copy failed:', error);
        showToast('复制失败', 'error');
    }
}

// 显示提示消息
function showToast(message, type = 'success') {
    const toast = document.getElementById('toast');
    
    // 支持 HTML 内容（用于多行消息）
    if (message.includes('<br>')) {
        toast.innerHTML = message;
    } else {
        toast.textContent = message;
    }
    
    toast.className = `toast ${type}`;
    
    // 显示 toast
    setTimeout(() => {
        toast.classList.add('show');
    }, 10);
    
    // 根据内容长度调整显示时间
    const displayTime = message.length > 50 ? 5000 : 3000;
    
    // 隐藏 toast
    setTimeout(() => {
        toast.classList.remove('show');
    }, displayTime);
}

// 自动刷新状态（每30秒）
setInterval(async () => {
    await checkServerStatus();
}, 30000);

// 自动刷新配置（每5分钟）
setInterval(async () => {
    await loadConfig();
}, 300000);

// 验证是否是 GitHub 文件链接
function isValidGithubFileUrl(url) {
    try {
        let urlToParse = url;
        
        // 如果不是完整 URL，构造一个
        if (!url.startsWith('http://') && !url.startsWith('https://')) {
            if (url.startsWith('github.com') || url.startsWith('raw.githubusercontent.com')) {
                urlToParse = 'https://' + url;
            } else {
                urlToParse = 'https://github.com/' + url;
            }
        }
        
        const urlObj = new URL(urlToParse);
        const pathParts = urlObj.pathname.split('/').filter(p => p);
        
        // 检查是否是文件链接
        // 有效的文件链接格式:
        // 1. github.com/user/repo/blob/branch/path/to/file
        // 2. github.com/user/repo/raw/branch/path/to/file
        // 3. github.com/user/repo/releases/download/tag/file
        // 4. raw.githubusercontent.com/user/repo/branch/path/to/file
        
        // raw.githubusercontent.com 域名
        if (urlObj.hostname === 'raw.githubusercontent.com') {
            // 格式：/user/repo/branch/path/to/file 或 /user/repo/refs/heads/branch/path/to/file
            // 至少需要: /user/repo/file (3段)
            if (pathParts.length >= 3) {
                return { valid: true };
            }
            return { 
                valid: false, 
                message: '请输入完整的文件链接<br>示例：https://raw.githubusercontent.com/user/repo/main/file.txt' 
            };
        }
        
        // github.com 域名
        if (urlObj.hostname === 'github.com' || urlObj.hostname === 'www.github.com') {
            // 至少需要 5 段：user/repo/blob/branch/file
            if (pathParts.length < 5) {
                return { 
                    valid: false, 
                    message: '请输入完整的文件链接<br>示例：https://github.com/user/repo/blob/main/file.txt' 
                };
            }
            
            const type = pathParts[2]; // user/repo/TYPE/...
            
            // 必须包含 blob, raw 或 releases/download
            if (type !== 'blob' && type !== 'raw' && 
                !(type === 'releases' && pathParts[3] === 'download')) {
                return { 
                    valid: false, 
                    message: '请输入文件链接，而不是仓库主页或其他页面<br>支持格式：<br>• /user/repo/blob/branch/file<br>• /user/repo/raw/branch/file<br>• /user/repo/releases/download/tag/file' 
                };
            }
            
            return { valid: true };
        }
        
        // 必须是 GitHub 相关域名
        if (!urlObj.hostname.includes('github')) {
            return { valid: false, message: '请输入有效的 GitHub 链接' };
        }
        
        // 其他 GitHub 子域名，暂不支持
        return { 
            valid: false, 
            message: '仅支持 github.com 和 raw.githubusercontent.com 域名' 
        };
        
    } catch (error) {
        console.error('URL validation error:', error);
        return { valid: false, message: '链接格式错误' };
    }
}

// 生成 GitHub 加速链接
function generateGithubUrl() {
    const input = document.getElementById('githubInput');
    const resultBox = document.getElementById('githubResult');
    const resultText = document.getElementById('githubResultText');
    
    const url = input.value.trim();
    
    if (!url) {
        showToast('请输入 GitHub 链接', 'error');
        return;
    }
    
    // 验证是否是 GitHub 文件链接
    const validation = isValidGithubFileUrl(url);
    if (!validation.valid) {
        showToast(validation.message, 'error');
        return;
    }
    
    // 生成加速链接
    let acceleratedUrl = '';
    
    try {
        // 获取当前协议 (http: 或 https:)，去掉冒号
        const protocol = currentProtocol.replace(':', '');
        
        // 处理不同格式的 GitHub URL
        if (url.startsWith('http://') || url.startsWith('https://')) {
            const urlObj = new URL(url);
            
            // 完整 URL
            if (urlObj.hostname === 'raw.githubusercontent.com') {
                // raw.githubusercontent.com/user/repo/branch/file 
                // -> http(s)://domain.com/raw.githubusercontent.com/user/repo/branch/file
                acceleratedUrl = `${protocol}://${currentDomain}/${urlObj.hostname}${urlObj.pathname}${urlObj.search}${urlObj.hash}`;
            } else if (urlObj.hostname === 'github.com' || urlObj.hostname === 'www.github.com') {
                // github.com/user/repo/blob/branch/file
                // -> http(s)://domain.com/github.com/user/repo/blob/branch/file
                acceleratedUrl = `${protocol}://${currentDomain}/${urlObj.hostname}${urlObj.pathname}${urlObj.search}${urlObj.hash}`;
            } else {
                // 其他 GitHub 域名
                acceleratedUrl = `${protocol}://${currentDomain}/${urlObj.hostname}${urlObj.pathname}${urlObj.search}${urlObj.hash}`;
            }
        } else if (url.startsWith('raw.githubusercontent.com')) {
            // 域名开头: raw.githubusercontent.com/user/repo -> http(s)://domain.com/raw.githubusercontent.com/user/repo
            acceleratedUrl = `${protocol}://${currentDomain}/${url}`;
        } else if (url.startsWith('github.com')) {
            // 域名开头: github.com/user/repo -> http(s)://domain.com/github.com/user/repo
            acceleratedUrl = `${protocol}://${currentDomain}/${url}`;
        } else {
            // 相对路径: user/repo -> http(s)://domain.com/github.com/user/repo
            acceleratedUrl = `${protocol}://${currentDomain}/github.com/${url}`;
        }
        
        // 显示结果
        resultText.textContent = acceleratedUrl;
        resultBox.style.display = 'block';
        showToast('加速链接生成成功 ✓', 'success');
        
    } catch (error) {
        console.error('URL parsing error:', error);
        showToast('链接格式错误', 'error');
    }
}

// 生成 Docker 加速命令
function generateDockerUrl() {
    const input = document.getElementById('dockerInput');
    const resultBox = document.getElementById('dockerResult');
    const resultText = document.getElementById('dockerResultText');
    
    const imageName = input.value.trim();
    
    if (!imageName) {
        showToast('请输入 Docker 镜像名称', 'error');
        return;
    }
    
    // 检查是否使用 HTTP 访问
    if (!isHttps) {
        showToast('⚠️ Docker 代理需要 HTTPS 协议<br>当前使用 HTTP 访问，Docker 客户端不支持非 HTTPS 的镜像仓库<br>请使用 HTTPS 访问本站点', 'error');
        return;
    }
    
    // 检查 Docker 是否启用
    if (appConfig && !appConfig.docker?.enabled) {
        showToast('Docker 代理功能未启用', 'error');
        return;
    }
    
    // 生成加速命令
    let acceleratedCommand = '';
    
    try {
        // 处理不同格式的镜像名称
        if (imageName.includes('/')) {
            // 包含仓库地址: ghcr.io/user/image:tag 或 user/image:tag
            if (imageName.includes('.')) {
                // 包含域名的完整镜像名称
                acceleratedCommand = `docker pull ${currentDomain}/${imageName}`;
            } else {
                // Docker Hub 用户镜像
                acceleratedCommand = `docker pull ${currentDomain}/${imageName}`;
            }
        } else {
            // 仅镜像名: nginx:latest
            acceleratedCommand = `docker pull ${currentDomain}/${imageName}`;
        }
        
        // 显示结果
        resultText.textContent = acceleratedCommand;
        resultBox.style.display = 'block';
        showToast('加速命令生成成功 ✓', 'success');
        
    } catch (error) {
        console.error('Docker command generation error:', error);
        showToast('镜像名称格式错误', 'error');
    }
}

// 复制生成的结果
function copyResult(type) {
    const resultText = type === 'github' 
        ? document.getElementById('githubResultText').textContent
        : document.getElementById('dockerResultText').textContent;
    
    if (resultText) {
        copyToClipboard(resultText);
        showToast('已复制到剪贴板 ✓', 'success');
    }
}

// 添加回车键支持
document.addEventListener('DOMContentLoaded', () => {
    const githubInput = document.getElementById('githubInput');
    const dockerInput = document.getElementById('dockerInput');
    
    if (githubInput) {
        githubInput.addEventListener('keypress', (e) => {
            if (e.key === 'Enter') {
                generateGithubUrl();
            }
        });
    }
    
    if (dockerInput) {
        dockerInput.addEventListener('keypress', (e) => {
            if (e.key === 'Enter') {
                generateDockerUrl();
            }
        });
    }
});

// 检查 Docker HTTP 警告
function checkDockerHttpWarning() {
    if (!isHttps) {
        const dockerTab = document.querySelector('[data-tab="docker"]');
        if (dockerTab) {
            // 在 Docker 标签页添加警告标识
            const warningBadge = document.createElement('span');
            warningBadge.className = 'http-warning-badge';
            warningBadge.textContent = '⚠️';
            warningBadge.title = 'Docker 代理需要 HTTPS';
            dockerTab.appendChild(warningBadge);
        }
        
        // 在 Docker 输入框区域显示警告提示
        const dockerSection = document.getElementById('dockerSection');
        if (dockerSection) {
            const warningDiv = document.createElement('div');
            warningDiv.className = 'http-warning-message';
            warningDiv.innerHTML = `
                <strong>⚠️ 警告：</strong> 当前使用 HTTP 协议访问<br>
                Docker 代理功能需要 HTTPS 协议才能正常工作
            `;
            dockerSection.insertBefore(warningDiv, dockerSection.firstChild);
        }
    }
}

// 导出全局函数供 HTML 使用
window.copyExample = copyExample;
window.generateGithubUrl = generateGithubUrl;
window.generateDockerUrl = generateDockerUrl;
window.copyResult = copyResult;
