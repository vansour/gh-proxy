const githubForm = document.getElementById('github-form');
const githubLinkInput = document.getElementById('githubLinkInput');
const formattedLinkOutput = document.getElementById('formattedLinkOutput');
const output = document.getElementById('output');
const copyButton = document.getElementById('copyButton');
const openButton = document.getElementById('openButton');
const toast = document.getElementById('toast');
const githubLinkError = document.getElementById('githubLinkError');
const formatToggle = document.getElementById('format-toggle');
const slider = document.querySelector('.segmented-control__slider');
const clearInputButton = document.getElementById('clearInputButton');

function showToast(message) {
    const toastMessage = document.getElementById('toastMessage');
    toastMessage.textContent = message;
    toast.classList.add('toast--visible');
    setTimeout(() => {
        toast.classList.remove('toast--visible');
    }, 3000);
}

function updateClearButtonVisibility() {
    if (githubLinkInput.value.trim()) {
        clearInputButton.classList.add('visible');
    } else {
        clearInputButton.classList.remove('visible');
    }
}

function generateOutput(userInput, format) {
    const base_url = window.location.origin;
    const host = window.location.host;
    let normalizedLink = userInput.trim();

    try {
        if (!/^https?:\/\//i.test(normalizedLink)) {
            normalizedLink = 'https://' + normalizedLink;
        }

        const url = new URL(normalizedLink);
        const proxyPath = url.hostname + url.pathname + url.search + url.hash;
        const directLink = `${base_url}/${proxyPath}`;

        switch (format) {
            case 'git':
                if (url.pathname.endsWith('.git')) {
                    return { link: `git clone ${directLink}`, isUrl: false };
                }
                return { error: 'Git Clone 需要以 .git 结尾的仓库链接' };
            case 'wget':
                return { link: `wget "${directLink}"`, isUrl: false };
            case 'curl':
                return { link: `curl -O "${directLink}"`, isUrl: false };
            case 'direct':
            default:
                return { link: directLink, isUrl: true };
        }
    } catch (e) {
        return { error: '请输入一个有效的 URL' };
    }
}

function handleFormAction() {
    githubLinkError.textContent = '';
    githubLinkError.classList.remove('text-field__error--visible');

    const githubLink = githubLinkInput.value.trim();
    const selectedFormat = formatToggle.querySelector('.active').dataset.value;

    if (!githubLink) {
        githubLinkError.textContent = '请输入Github链接';
        githubLinkError.classList.add('text-field__error--visible');
        return;
    }

    const result = generateOutput(githubLink, selectedFormat);

    if (result.error) {
        githubLinkError.textContent = result.error;
        githubLinkError.classList.add('text-field__error--visible');
        output.style.display = 'none';
    } else {
        formattedLinkOutput.textContent = result.link;
        output.style.display = 'flex';
        openButton.disabled = !result.isUrl;
    }
}

function updateSliderPosition() {
    const activeButton = formatToggle.querySelector('.active');
    if (activeButton) {
        const rect = activeButton.getBoundingClientRect();
        const containerRect = formatToggle.getBoundingClientRect();
        slider.style.width = `${rect.width}px`;
        slider.style.transform = `translateX(${rect.left - containerRect.left}px)`;
    }
}

function initSlider() {
    updateSliderPosition();
    const resizeObserver = new ResizeObserver(updateSliderPosition);
    resizeObserver.observe(formatToggle);
}

githubForm.addEventListener('submit', function (e) {
    e.preventDefault();
    handleFormAction();
});

clearInputButton.addEventListener('click', function (e) {
    e.preventDefault();
    githubLinkInput.value = '';
    updateClearButtonVisibility();
    githubLinkError.textContent = '';
    githubLinkError.classList.remove('text-field__error--visible');
    output.style.display = 'none';
    githubLinkInput.focus();
});

formatToggle.addEventListener('click', (e) => {
    const button = e.target.closest('button');
    if (!button || button.classList.contains('active')) return;
    formatToggle.querySelector('.active')?.classList.remove('active');
    button.classList.add('active');
    updateSliderPosition();
    if (githubLinkInput.value.trim()) {
        handleFormAction();
    }
});

githubLinkInput.addEventListener('input', () => {
    githubLinkError.textContent = '';
    githubLinkError.classList.remove('text-field__error--visible');
    updateClearButtonVisibility();
});

copyButton.addEventListener('click', function () {
    const textToCopy = formattedLinkOutput.textContent;
    if (!textToCopy) return;
    
    // 方案 1: 使用 Clipboard API (HTTPS)
    if (navigator.clipboard && typeof navigator.clipboard.writeText === 'function') {
        navigator.clipboard.writeText(textToCopy)
            .then(() => {
                showToast('已复制到剪贴板');
            })
            .catch(() => {
                // 降级到 execCommand
                copyViaExecCommand(textToCopy);
            });
    } else {
        // 方案 2: 使用 execCommand (HTTP 兼容)
        copyViaExecCommand(textToCopy);
    }
});

function copyViaExecCommand(text) {
    // 创建一个临时的 textarea 元素
    const textarea = document.createElement('textarea');
    
    // 设置样式使其不可见但可交互
    textarea.style.position = 'fixed';
    textarea.style.top = '0';
    textarea.style.left = '0';
    textarea.style.width = '2em';
    textarea.style.height = '2em';
    textarea.style.padding = '0';
    textarea.style.border = 'none';
    textarea.style.outline = 'none';
    textarea.style.boxShadow = 'none';
    textarea.style.background = 'transparent';
    textarea.style.opacity = '0';
    textarea.style.pointerEvents = 'none';
    textarea.style.zIndex = '-9999';
    
    // 禁用自动缩放（移动设备）
    textarea.style.fontSize = '16px';
    textarea.style.lineHeight = '1';
    
    // 设置文本内容
    textarea.value = text;
    
    // 添加到 DOM
    document.body.appendChild(textarea);
    
    // 确保 textarea 获得焦点
    textarea.focus();
    
    try {
        // 使用 setSelectionRange 确保能够选择文本
        textarea.setSelectionRange(0, textarea.value.length);
        
        // 执行复制命令
        const successful = document.execCommand('copy');
        
        console.log('Copy command result:', successful);
        
        if (successful) {
            showToast('已复制到剪贴板');
        } else {
            console.warn('execCommand 返回 false，尝试备用方案');
            // 尝试备用方案：直接 select 后再复制
            textarea.select();
            const retrySuccessful = document.execCommand('copy');
            if (retrySuccessful) {
                showToast('已复制到剪贴板');
            } else {
                showToast('复制失败');
            }
        }
    } catch (err) {
        console.error('复制错误: ', err);
        showToast('复制失败，请手动复制');
    } finally {
        // 移除 textarea 元素
        if (textarea.parentNode) {
            document.body.removeChild(textarea);
        }
    }
}

openButton.addEventListener('click', function () {
    if (!openButton.disabled) {
        window.open(formattedLinkOutput.textContent, '_blank');
    }
});

async function fetchConfigData() {
    try {
        const response = await fetch('/api/config');
        if (!response.ok) throw new Error(`HTTP error! Status: ${response.status}`);
        const config = await response.json();
        
        // 更新文件大小限制
        const sizeLimitElement = document.getElementById('sizeLimitDisplay');
        if (sizeLimitElement && config.server) {
            sizeLimitElement.textContent = `${config.server.sizeLimit} MB`;
        }
        
        // 更新黑名单状态
        const blackListElement = document.getElementById('blackListStatus');
        if (blackListElement && config.blacklist) {
            blackListElement.textContent = config.blacklist.enabled ? '已开启' : '已关闭';
        }
        
        // 更新 Shell 编辑器状态
        const shellNestElement = document.getElementById('shellNestStatus');
        if (shellNestElement && config.shell) {
            shellNestElement.textContent = config.shell.editor ? '已开启' : '已关闭';
        }
        
    } catch (error) {
        console.error('Error fetching config:', error);
        // 设置所有元素为无法获取
        ['sizeLimitDisplay', 'blackListStatus', 'shellNestStatus'].forEach(id => {
            const element = document.getElementById(id);
            if (element) element.textContent = '无法获取';
        });
    }
}

function fetchAllApis() {
    fetchConfigData();
}

document.addEventListener('DOMContentLoaded', () => {
    fetchAllApis();
    initSlider();
    updateClearButtonVisibility();
});