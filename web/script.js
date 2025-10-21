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

function showToast(message) {
    const toastMessage = document.getElementById('toastMessage');
    toastMessage.textContent = message;
    toast.classList.add('toast--visible');
    setTimeout(() => {
        toast.classList.remove('toast--visible');
    }, 3000);
}

function generateOutput(userInput, format) {
    const base_url = window.location.origin;
    const host = window.location.host;
    let normalizedLink = userInput.trim();

    try {
        if (format === 'docker') {
            if (normalizedLink.includes('/') && !normalizedLink.includes(' ') && !normalizedLink.startsWith('http')) {
                return { link: `docker pull ${host}/${normalizedLink}`, isUrl: false };
            }
            return { error: '请输入有效的 Docker 镜像名 (例如: owner/repo)' };
        }
        
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
        githubLinkError.textContent = '请输入链接或镜像名';
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
});

copyButton.addEventListener('click', function () {
    if (!formattedLinkOutput.textContent) return;
    navigator.clipboard.writeText(formattedLinkOutput.textContent).then(() => {
        showToast('已复制到剪贴板');
    }).catch(err => {
        console.error('复制失败: ', err);
        showToast('复制失败');
    });
});

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
});