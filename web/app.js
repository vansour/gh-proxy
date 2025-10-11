// API 配置
const API_BASE_URL = window.location.origin;
const API_ENDPOINTS = {
    config: '/api/config',
    health: '/healthz'
};

// 状态管理
let appConfig = null;
let currentDomain = window.location.host;

// 初始化应用
document.addEventListener('DOMContentLoaded', async () => {
    await checkServerStatus();
    await loadConfig();
    initializeTabs();
    updateDomainInExamples();
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
    document.getElementById('sizeLimit').textContent = sizeLimit;
    document.getElementById('sizeLimitTip').textContent = sizeLimit;
    
    // 更新 Docker 状态
    const dockerEnabled = appConfig.docker?.enabled ? '✅ 已启用' : '❌ 未启用';
    document.getElementById('dockerEnabled').textContent = dockerEnabled;
    
    // 更新黑名单状态
    const blacklistEnabled = appConfig.blacklist?.enabled ? '✅ 已启用' : '❌ 未启用';
    document.getElementById('blacklistEnabled').textContent = blacklistEnabled;
    
    // 更新编辑器状态
    const editorEnabled = appConfig.shell?.editor ? '✅ 已启用' : '❌ 未启用';
    document.getElementById('editorEnabled').textContent = editorEnabled;
    
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
    document.getElementById('sizeLimit').textContent = '-';
    document.getElementById('sizeLimitTip').textContent = '-';
    document.getElementById('dockerEnabled').textContent = '-';
    document.getElementById('blacklistEnabled').textContent = '-';
    document.getElementById('editorEnabled').textContent = '-';
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
    
    toast.textContent = message;
    toast.className = `toast ${type}`;
    
    // 显示 toast
    setTimeout(() => {
        toast.classList.add('show');
    }, 10);
    
    // 3秒后隐藏
    setTimeout(() => {
        toast.classList.remove('show');
    }, 3000);
}

// 自动刷新状态（每30秒）
setInterval(async () => {
    await checkServerStatus();
}, 30000);

// 自动刷新配置（每5分钟）
setInterval(async () => {
    await loadConfig();
}, 300000);

// 导出全局函数供 HTML 使用
window.copyExample = copyExample;
