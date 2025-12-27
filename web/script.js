/**
 * gh-proxy - GitHub 文件代理加速器
 * 前端脚本 - 优化版
 */
(function () {
    'use strict';

    // ========================================================================
    // DOM Elements Cache
    // ========================================================================
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

    // ========================================================================
    // State
    // ========================================================================
    const STATE = {
        format: 'direct',
        statsInterval: null
    };

    // ========================================================================
    // Configuration
    // ========================================================================
    const CONFIG = {
        API_CONFIG: '/api/config',
        API_STATS: '/api/stats',
        API_HEALTH: '/healthz',
        STATS_INTERVAL_MS: 30000, // 30 seconds
        DEBOUNCE_MS: 100,
        TOAST_DURATION_MS: 2000
    };

    // ========================================================================
    // Utility Functions
    // ========================================================================

    /**
     * Debounce function to limit execution rate
     */
    function debounce(fn, delay) {
        let timer;
        return function (...args) {
            clearTimeout(timer);
            timer = setTimeout(() => fn.apply(this, args), delay);
        };
    }

    /**
     * Format bytes to human readable string
     */
    function formatBytes(bytes) {
        if (bytes === 0) return '0 B';
        const k = 1024;
        const sizes = ['B', 'KB', 'MB', 'GB', 'TB', 'PB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
    }

    /**
     * Show toast notification
     */
    function showToast(msg) {
        EL.toast.textContent = msg;
        EL.toast.classList.add('show');
        setTimeout(() => EL.toast.classList.remove('show'), CONFIG.TOAST_DURATION_MS);
    }

    /**
     * Validate Docker image reference
     */
    function isValidDockerRef(s) {
        if (!s || /\s/.test(s) || /^https?:\/\//i.test(s)) return false;
        const digestRe = /^(?:[^\/@]+(?:\/[\w.-]+)*)@sha256:[0-9a-fA-F]{64}$/;
        const tagRe = /^(?:[a-zA-Z0-9.-]+(?::[0-9]+)?\/)?(?:[\w.-]+\/?)*[\w.-]+(?::[A-Za-z0-9_][A-Za-z0-9._-]{0,127})?$/;
        return digestRe.test(s) || tagRe.test(s);
    }

    // ========================================================================
    // UI Functions
    // ========================================================================

    /**
     * Show error message with animation
     */
    function showError(msg) {
        EL.errorMsg.textContent = msg;
        EL.errorMsg.classList.add('visible');
        EL.outputCard.style.display = 'none';
    }

    /**
     * Show output result
     */
    function showOutput(text, isUrl) {
        EL.errorMsg.classList.remove('visible');
        EL.outputCard.style.display = 'block';
        EL.outputContent.textContent = text;
        EL.openBtn.style.display = isUrl ? 'flex' : 'none';
    }

    /**
     * Update input action buttons visibility
     */
    function updateInputButtons(hasValue) {
        EL.clearBtn.style.display = hasValue ? 'flex' : 'none';
        EL.pasteBtn.style.display = hasValue ? 'none' : 'flex';
    }

    /**
     * Copy text to clipboard with visual feedback
     */
    async function copyToClipboard(text) {
        try {
            if (navigator.clipboard && navigator.clipboard.writeText) {
                await navigator.clipboard.writeText(text);
            } else {
                // Fallback for older browsers
                const ta = document.createElement('textarea');
                ta.value = text;
                ta.style.cssText = 'position:fixed;opacity:0';
                document.body.appendChild(ta);
                ta.select();
                document.execCommand('copy');
                document.body.removeChild(ta);
            }

            showToast('已复制');

            // Visual feedback - checkmark icon
            const originalSvg = EL.copyBtn.innerHTML;
            EL.copyBtn.innerHTML = '<svg viewBox="0 0 24 24"><path d="M9 16.17L4.83 12l-1.42 1.41L9 19 21 7l-1.41-1.41z" fill="#4caf50"/></svg>';
            setTimeout(() => { EL.copyBtn.innerHTML = originalSvg; }, 1500);
        } catch (err) {
            showToast('复制失败');
            console.error('Clipboard error:', err);
        }
    }

    /**
     * Update statistics bar with animation
     */
    function updateStatBar(totalEl, cachedEl, pctEl, barEl, total, cached, formatter = n => n.toLocaleString()) {
        requestAnimationFrame(() => {
            totalEl.textContent = formatter(total);
            cachedEl.textContent = formatter(cached);
            const pct = total > 0 ? Math.round((cached / total) * 100) : 0;
            pctEl.textContent = `${pct}%`;
            barEl.style.width = `${pct}%`;

            // Update ARIA attributes
            const track = barEl.parentElement;
            if (track) {
                track.setAttribute('aria-valuenow', pct);
            }
        });
    }

    // ========================================================================
    // Core Logic
    // ========================================================================

    /**
     * Process input URL and generate proxy link
     */
    function processInput() {
        let rawUrl = EL.input.value.trim();
        if (!rawUrl) return showError('请输入链接');

        // Remove existing proxy prefix if present
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
                const urlObj = new URL(rawUrl.startsWith('http') ? rawUrl : 'https://' + rawUrl);
                const proxyPath = urlObj.hostname + urlObj.pathname + urlObj.search + urlObj.hash;
                const directLink = `${baseUrl}/${proxyPath}`;

                switch (STATE.format) {
                    case 'git':
                        if (!urlObj.pathname.endsWith('.git')) return showError('Git Clone 需要 .git 结尾');
                        result = `git clone ${directLink}`;
                        isUrl = false;
                        break;
                    case 'wget':
                        result = `wget "${directLink}"`;
                        isUrl = false;
                        break;
                    case 'curl':
                        result = `curl -O "${directLink}"`;
                        isUrl = false;
                        break;
                    default:
                        result = directLink;
                }
            }
        } catch (e) {
            return showError('解析错误，请检查链接');
        }

        showOutput(result, isUrl);
    }

    // ========================================================================
    // API Calls
    // ========================================================================

    /**
     * Fetch statistics from API
     */
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
            console.warn('Stats fetch failed:', e);
        }
    }

    /**
     * Fetch initial data (health, version, stats)
     */
    async function fetchInitialData() {
        try {
            // Fetch health/version
            const healthRes = await fetch(CONFIG.API_HEALTH);
            if (healthRes.ok) {
                const health = await healthRes.json();
                if (health.version) {
                    EL.versionBadge.textContent = `v${health.version}`;
                }
            }

            // Fetch stats
            fetchStats();
        } catch (e) {
            console.warn('Initial data fetch failed:', e);
        }
    }

    // ========================================================================
    // Event Binding
    // ========================================================================

    function bindEvents() {
        // Format selector buttons
        EL.formatBtns.forEach(btn => {
            btn.addEventListener('click', () => {
                EL.formatBtns.forEach(b => {
                    b.classList.remove('active');
                    b.setAttribute('aria-selected', 'false');
                });
                btn.classList.add('active');
                btn.setAttribute('aria-selected', 'true');
                STATE.format = btn.dataset.format;

                if (EL.input.value.trim()) {
                    processInput();
                }
            });
        });

        // Input field with debounced handler
        const debouncedInputHandler = debounce(() => {
            EL.errorMsg.classList.remove('visible');
        }, CONFIG.DEBOUNCE_MS);

        EL.input.addEventListener('input', () => {
            const hasVal = !!EL.input.value.trim();
            updateInputButtons(hasVal);
            debouncedInputHandler();
        });

        // Enter key to submit
        EL.input.addEventListener('keydown', (e) => {
            if (e.key === 'Enter') {
                e.preventDefault();
                processInput();
            }
        });

        // Clear button
        EL.clearBtn.addEventListener('click', () => {
            EL.input.value = '';
            EL.input.focus();
            EL.outputCard.style.display = 'none';
            updateInputButtons(false);
        });

        // Paste button
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

        // Generate button
        EL.generateBtn.addEventListener('click', processInput);

        // Copy button
        EL.copyBtn.addEventListener('click', () => copyToClipboard(EL.outputContent.textContent));

        // Open in new window button
        EL.openBtn.addEventListener('click', () => {
            const text = EL.outputContent.textContent;
            if (/^https?:\/\//.test(text)) {
                window.open(text, '_blank', 'noopener,noreferrer');
            }
        });

        // Page visibility - pause/resume stats polling
        document.addEventListener('visibilitychange', () => {
            if (document.hidden) {
                if (STATE.statsInterval) {
                    clearInterval(STATE.statsInterval);
                    STATE.statsInterval = null;
                }
            } else {
                fetchStats();
                STATE.statsInterval = setInterval(fetchStats, CONFIG.STATS_INTERVAL_MS);
            }
        });
    }

    // ========================================================================
    // Initialization
    // ========================================================================

    function init() {
        // Focus input field
        EL.input.focus();

        // Show paste button if clipboard API available
        if (navigator.clipboard && navigator.clipboard.readText) {
            EL.pasteBtn.style.display = 'flex';
        }

        // Bind event handlers
        bindEvents();

        // Fetch initial data
        fetchInitialData();

        // Start stats polling (only when page is visible)
        STATE.statsInterval = setInterval(fetchStats, CONFIG.STATS_INTERVAL_MS);

        // Register service worker if available
        if ('serviceWorker' in navigator) {
            // PWA support - can be expanded later
            // navigator.serviceWorker.register('/sw.js');
        }
    }

    // Start the application
    init();
})();