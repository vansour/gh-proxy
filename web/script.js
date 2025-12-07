(function () {
    'use strict';

    const EL = {
        input: document.getElementById('inputUrl'),
        clearBtn: document.getElementById('clearBtn'),
        pasteBtn: document.getElementById('pasteBtn'),
        errorMsg: document.getElementById('errorMsg'),
        generateBtn: document.getElementById('generateBtn'),
        formatBtns: document.querySelectorAll('.format-btn'),
        outputCard: document.getElementById('outputCard'),
        outputContent: document.getElementById('outputContent'),
        copyBtn: document.getElementById('copyBtn'),
        copyIcon: document.getElementById('copyIcon'),
        openBtn: document.getElementById('openBtn'),
        toast: document.getElementById('toast'),
        historySection: document.getElementById('historySection'),
        historyList: document.getElementById('historyList'),
        clearHistoryBtn: document.getElementById('clearHistoryBtn'),
        // Stats
        statsContainer: document.getElementById('statsContainer'),
        cfTotalBytes: document.getElementById('cfTotalBytes'),
        cfCachedBytes: document.getElementById('cfCachedBytes'),
        cfCachedBytesPct: document.getElementById('cfCachedBytesPct'),
        cfBytesBar: document.getElementById('cfBytesBar'),
        cfTotalReqs: document.getElementById('cfTotalReqs'),
        cfCachedReqs: document.getElementById('cfCachedReqs'),
        cfCachedReqsPct: document.getElementById('cfCachedReqsPct'),
        cfReqsBar: document.getElementById('cfReqsBar'),
        versionBadge: document.getElementById('versionBadge')
    };

    const STATE = {
        format: 'direct',
        history: JSON.parse(localStorage.getItem('gh_proxy_history') || '[]')
    };

    const CONFIG = {
        API_CONFIG: '/api/config',
        API_STATS: '/api/stats',
        API_HEALTH: '/healthz'
    };

    function init() {
        EL.input.focus();
        if (navigator.clipboard && navigator.clipboard.readText) {
            EL.pasteBtn.style.display = 'flex';
        }

        bindEvents();
        renderHistory();
        fetchData();
        setInterval(fetchStats, 15000);
    }

    function bindEvents() {
        EL.formatBtns.forEach(btn => {
            btn.addEventListener('click', () => {
                EL.formatBtns.forEach(b => b.classList.remove('active'));
                btn.classList.add('active');
                STATE.format = btn.dataset.format;
                if (EL.input.value.trim()) processInput();
            });
        });

        EL.input.addEventListener('input', () => {
            const hasVal = !!EL.input.value.trim();
            EL.clearBtn.style.display = hasVal ? 'flex' : 'none';
            EL.pasteBtn.style.display = hasVal ? 'none' : 'flex';
            EL.errorMsg.classList.remove('visible');
        });

        EL.input.addEventListener('keydown', (e) => {
            if (e.key === 'Enter') processInput();
        });

        EL.clearBtn.addEventListener('click', () => {
            EL.input.value = '';
            EL.input.focus();
            EL.outputCard.style.display = 'none';
            EL.clearBtn.style.display = 'none';
            EL.pasteBtn.style.display = 'flex';
        });

        EL.pasteBtn.addEventListener('click', async () => {
            try {
                const text = await navigator.clipboard.readText();
                EL.input.value = text;
                EL.input.dispatchEvent(new Event('input'));
                processInput();
            } catch (err) {
                showToast('无法读取剪贴板');
            }
        });

        EL.generateBtn.addEventListener('click', processInput);

        EL.copyBtn.addEventListener('click', () => copyToClipboard(EL.outputContent.textContent));

        EL.openBtn.addEventListener('click', () => {
            const text = EL.outputContent.textContent;
            if (/^https?:\/\//.test(text)) window.open(text, '_blank');
        });

        EL.clearHistoryBtn.addEventListener('click', () => {
            STATE.history = [];
            saveHistory();
            renderHistory();
        });
    }

    function processInput() {
        let rawUrl = EL.input.value.trim();
        if (!rawUrl) return showError('请输入链接');

        // 尝试移除已存在的代理前缀
        const proxyPrefixRegex = /^(https?:\/\/[^\/]+\/)(https?:\/\/.*)/i;
        const match = rawUrl.match(proxyPrefixRegex);
        if (match) {
            rawUrl = match[2];
        }

        const isDocker = STATE.format === 'docker';
        if (!isDocker && !/^https?:\/\//i.test(rawUrl) && !/^github\.com/i.test(rawUrl)) {
            if (/^github\.com/.test(rawUrl)) {
                EL.input.value = 'https://' + rawUrl;
                return processInput();
            }
            return showError('无效的 URL 格式');
        }

        const baseUrl = window.location.origin;
        let result = '';
        let isUrl = true;

        try {
            if (isDocker) {
                if (!isValidDockerRef(rawUrl)) return showError('无效的 Docker 镜像格式');
                result = `docker pull ${window.location.host}/${rawUrl}`;
                isUrl = false;
            } else {
                let urlObj = new URL(rawUrl.startsWith('http') ? rawUrl : 'https://' + rawUrl);
                const proxyPath = urlObj.hostname + urlObj.pathname + urlObj.search + urlObj.hash;
                const directLink = `${baseUrl}/${proxyPath}`;

                switch (STATE.format) {
                    case 'git':
                        if (!urlObj.pathname.endsWith('.git')) return showError('Git Clone 需要 .git 结尾');
                        result = `git clone ${directLink}`;
                        isUrl = false;
                        break;
                    case 'wget': result = `wget "${directLink}"`; isUrl = false; break;
                    case 'curl': result = `curl -O "${directLink}"`; isUrl = false; break;
                    default: result = directLink;
                }
            }
        } catch (e) {
            return showError('解析错误，请检查链接');
        }

        showOutput(result, isUrl);
        addToHistory(rawUrl);
    }

    function showOutput(text, isUrl) {
        EL.errorMsg.classList.remove('visible');
        EL.outputCard.style.display = 'block';
        EL.outputContent.textContent = text;
        EL.openBtn.style.display = isUrl ? 'flex' : 'none';
    }

    function showError(msg) {
        EL.errorMsg.textContent = msg;
        EL.errorMsg.classList.add('visible');
        EL.outputCard.style.display = 'none';
    }

    function addToHistory(url) {
        STATE.history = STATE.history.filter(item => item !== url);
        STATE.history.unshift(url);
        if (STATE.history.length > 5) STATE.history.pop();
        saveHistory();
        renderHistory();
    }

    function saveHistory() {
        localStorage.setItem('gh_proxy_history', JSON.stringify(STATE.history));
    }

    function renderHistory() {
        if (STATE.history.length === 0) {
            EL.historySection.style.display = 'none';
            return;
        }
        EL.historySection.style.display = 'block';
        EL.historyList.innerHTML = STATE.history.map(url => `
            <div class="history-item" onclick="document.getElementById('inputUrl').value='${url}'; document.getElementById('inputUrl').dispatchEvent(new Event('input')); document.getElementById('generateBtn').click();">
                <span class="history-icon">🕒</span>
                <span class="history-text">${url}</span>
            </div>
        `).join('');
    }

    async function copyToClipboard(text) {
        try {
            if (navigator.clipboard) {
                await navigator.clipboard.writeText(text);
            } else {
                const ta = document.createElement('textarea');
                ta.value = text;
                document.body.appendChild(ta);
                ta.select();
                document.execCommand('copy');
                document.body.removeChild(ta);
            }
            showToast('已复制');
            const originalSvg = EL.copyBtn.innerHTML;
            EL.copyBtn.innerHTML = '<svg viewBox="0 0 24 24"><path d="M9 16.17L4.83 12l-1.42 1.41L9 19 21 7l-1.41-1.41z" fill="#4caf50"/></svg>';
            setTimeout(() => EL.copyBtn.innerHTML = originalSvg, 1500);
        } catch (err) {
            showToast('复制失败');
        }
    }

    function showToast(msg) {
        EL.toast.textContent = msg;
        EL.toast.classList.add('show');
        setTimeout(() => EL.toast.classList.remove('show'), 2000);
    }

    function isValidDockerRef(s) {
        if (!s || /\s/.test(s) || /^https?:\/\//i.test(s)) return false;
        const digestRe = /^(?:[^\/@]+(?:\/[\w.-]+)*)@sha256:[0-9a-fA-F]{64}$/;
        const tagRe = /^(?:[a-zA-Z0-9.-]+(?::[0-9]+)?\/)??(?:[\w.-]+\/?)*[\w.-]+(?::[A-Za-z0-9_][A-Za-z0-9._-]{0,127})?$/;
        return digestRe.test(s) || tagRe.test(s);
    }

    function formatBytes(bytes) {
        if (bytes === 0) return '0 B';
        const k = 1024;
        const sizes = ['B', 'KB', 'MB', 'GB', 'TB', 'PB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
    }

    function updateStatBar(totalEl, cachedEl, pctEl, barEl, total, cached, formatter = n => n.toLocaleString()) {
        totalEl.textContent = formatter(total);
        cachedEl.textContent = formatter(cached);
        let pct = 0;
        if (total > 0) pct = Math.round((cached / total) * 100);
        pctEl.textContent = `${pct}%`;
        barEl.style.width = `${pct}%`;
    }

    async function fetchStats() {
        try {
            const res = await fetch(CONFIG.API_STATS);
            if (res.ok) {
                const data = await res.json();
                if (data.cloudflare) {
                    EL.statsContainer.classList.remove('hidden');
                    updateStatBar(
                        EL.cfTotalBytes, EL.cfCachedBytes, EL.cfCachedBytesPct, EL.cfBytesBar,
                        data.cloudflare.bytes, data.cloudflare.cached_bytes, formatBytes
                    );
                    updateStatBar(
                        EL.cfTotalReqs, EL.cfCachedReqs, EL.cfCachedReqsPct, EL.cfReqsBar,
                        data.cloudflare.requests, data.cloudflare.cached_requests
                    );
                }
            }
        } catch (e) {
            console.warn('Stats fetch failed', e);
        }
    }

    async function fetchData() {
        try {
            fetch(CONFIG.API_HEALTH).then(res => res.json()).then(h => {
                if (h.version) EL.versionBadge.textContent = `v${h.version}`;
            }).catch(() => { });
            fetchStats();
        } catch (e) { }
    }

    init();
})();