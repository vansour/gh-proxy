/**
 * gh-proxy - GitHub 文件代理加速器
 * 前端脚本 - 优化版 (With History & Theme)
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
        generateBtn: document.getElementById('generateBtn'),
        formatBtns: document.querySelectorAll('.tab-btn'),
        outputCard: document.getElementById('outputCard'),
        outputContent: document.getElementById('outputContent'),
        copyBtn: document.getElementById('copyBtn'),
        openBtn: document.getElementById('openBtn'),
        toast: document.getElementById('toast'),
        // Stats
        statsContainer: document.getElementById('statsContainer'),
        cfTotalBytes: document.getElementById('cfTotalBytes'),
        cfTotalReqs: document.getElementById('cfTotalReqs'),
        versionBadge: document.getElementById('versionBadge'),
        // New features
        themeToggle: document.getElementById('themeToggle'),
        iconSun: document.querySelector('.icon-sun'),
        iconMoon: document.querySelector('.icon-moon'),
        historySection: document.getElementById('historySection'),
        historyList: document.getElementById('historyList'),
        // Status Dashboard (Status Page)
        statsDashboard: document.getElementById('statsDashboard'),
        totalBytes: document.getElementById('totalBytes'),
        savedBytes: document.getElementById('savedBytes'),
        bytesBar: document.getElementById('bytesBar'),
        bytesRate: document.getElementById('bytesRate'),
        totalReqs: document.getElementById('totalReqs'),
        cachedReqs: document.getElementById('cachedReqs'),
        reqsBar: document.getElementById('reqsBar'),
        reqsRate: document.getElementById('reqsRate'),
        version: document.getElementById('version')
    };

    // ========================================================================
    // State
    // ========================================================================
    const STATE = {
        format: 'direct',
        statsInterval: null,
        history: JSON.parse(localStorage.getItem('gh-proxy-history') || '[]'),
        theme: localStorage.getItem('gh-proxy-theme') || 'light'
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
        TOAST_DURATION_MS: 2000,
        MAX_HISTORY: 5
    };

    // ========================================================================
    // Utility Functions
    // ========================================================================

    function debounce(fn, delay) {
        let timer;
        return function (...args) {
            clearTimeout(timer);
            timer = setTimeout(() => fn.apply(this, args), delay);
        };
    }

    function formatBytes(bytes) {
        if (bytes === 0) return '0 B';
        const k = 1024;
        const sizes = ['B', 'KB', 'MB', 'GB', 'TB', 'PB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
    }

    function formatNumber(num) {
        if (num === 0) return '0';
        const k = 1000;
        const sizes = ['', 'k', 'M', 'B', 'T'];
        const i = Math.floor(Math.log(num) / Math.log(k));
        // Avoid 1000.00k, just return 1M if close enough? no, standard logic is fine.
        // Use 2 decimal places usually, or maybe 1 for compactness?
        // User asked for "dynamic unit", let's keep it similar to bytes (2 decimals)
        return parseFloat((num / Math.pow(k, i)).toFixed(2)) + sizes[i];
    }

    function showToast(msg) {
        EL.toast.textContent = msg;
        EL.toast.classList.add('visible');
        setTimeout(() => EL.toast.classList.remove('visible'), CONFIG.TOAST_DURATION_MS);
    }

    // ...

    // [SKIP to fetchStats to update formatter]
    // Be careful with replace_file_content range. I cannot skip in replacement content.
    // Actually I should split this into multiple chunks via multi_replace if I need to touch widely separated parts.
    // But wait, `formatNumber` is a helper. `fetchStats` calls `renderChart`.
    // I need to:
    // 1. Insert `formatNumber` near `formatBytes`.
    // 2. Modify `fetchStats`.
    // 3. Modify `renderChart`.

    // Let's use multi_replace_file_content.

    function isValidDockerRef(s) {
        if (!s || /\s/.test(s) || /^https?:\/\//i.test(s)) return false;
        const digestRe = /^(?:[^\/@]+(?:\/[\w.-]+)*)@sha256:[0-9a-fA-F]{64}$/;
        const tagRe = /^(?:[a-zA-Z0-9.-]+(?::[0-9]+)?\/)?(?:[\w.-]+\/?)*[\w.-]+(?::[A-Za-z0-9_][A-Za-z0-9._-]{0,127})?$/;
        return digestRe.test(s) || tagRe.test(s);
    }

    // ========================================================================
    // Theme Logic
    // ========================================================================

    function applyTheme(theme) {
        document.body.setAttribute('data-theme', theme);
        if (theme === 'dark') {
            EL.iconMoon.style.display = 'none';
            EL.iconSun.style.display = 'block';
            document.querySelector('meta[name="theme-color"]').setAttribute('content', '#111318');
        } else {
            EL.iconMoon.style.display = 'block';
            EL.iconSun.style.display = 'none';
            document.querySelector('meta[name="theme-color"]').setAttribute('content', '#ffffff');
        }
    }

    function toggleTheme() {
        STATE.theme = STATE.theme === 'light' ? 'dark' : 'light';
        localStorage.setItem('gh-proxy-theme', STATE.theme);
        applyTheme(STATE.theme);
    }

    // ========================================================================
    // History Logic
    // ========================================================================

    function saveHistory(url) {
        // Remove duplicate if exists
        STATE.history = STATE.history.filter(item => item !== url);
        // Add to front
        STATE.history.unshift(url);
        // Trim
        if (STATE.history.length > CONFIG.MAX_HISTORY) {
            STATE.history.pop();
        }
        localStorage.setItem('gh-proxy-history', JSON.stringify(STATE.history));
        renderHistory();
    }

    function renderHistory() {
        if (STATE.history.length === 0 || !EL.historySection) {
            if (EL.historySection) EL.historySection.style.display = 'none';
            return;
        }

        EL.historySection.style.display = 'block';
        EL.historyList.innerHTML = '';

        STATE.history.forEach(url => {
            const div = document.createElement('div');
            div.className = 'history-item';
            div.innerHTML = `
                <div class="history-text">${url}</div>
            `;
            div.onclick = () => {
                EL.input.value = url;
                EL.input.dispatchEvent(new Event('input'));
                processInput();
                window.scrollTo({ top: 0, behavior: 'smooth' });
            };
            EL.historyList.appendChild(div);
        });
    }

    // ========================================================================
    // Core Logic
    // ========================================================================

    function showError(msg) {
        showToast(msg);
        EL.outputCard.style.display = 'none';
    }

    function showOutput(text, isUrl) {
        EL.outputCard.style.display = 'block';
        EL.outputContent.textContent = text;
        EL.openBtn.style.display = isUrl ? 'flex' : 'none';
    }

    function updateInputButtons(hasValue) {
        EL.clearBtn.style.display = hasValue ? 'flex' : 'none';
        EL.pasteBtn.style.display = hasValue ? 'none' : 'flex';
    }

    async function copyToClipboard(text) {
        try {
            await navigator.clipboard.writeText(text);
            showToast('已复制');
        } catch (err) {
            // Fallback
            const ta = document.createElement('textarea');
            ta.value = text;
            ta.style.position = 'fixed';
            ta.style.opacity = '0';
            document.body.appendChild(ta);
            ta.select();
            document.execCommand('copy');
            document.body.removeChild(ta);
            showToast('已复制');
        }
    }

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
            // Save to history only if successful
            saveHistory(rawUrl);

        } catch (e) {
            return showError('解析错误，请检查链接');
        }

        showOutput(result, isUrl);
    }

    // ========================================================================
    // API Calls
    // ========================================================================

    async function fetchStats() {
        try {
            const res = await fetch(CONFIG.API_STATS);
            if (!res.ok) return;
            const data = await res.json();

            if (data.cloudflare) {
                const cf = data.cloudflare;

                // Update Status Page Dashboard if exists
                if (EL.totalBytes) EL.totalBytes.textContent = formatBytes(cf.bytes);
                if (EL.savedBytes) EL.savedBytes.textContent = formatBytes(cf.cached_bytes);

                if (EL.bytesBar || EL.bytesRate) {
                    const byteRate = cf.bytes > 0 ? (cf.cached_bytes / cf.bytes * 100).toFixed(1) : 0;
                    if (EL.bytesBar) EL.bytesBar.style.width = `${byteRate}%`;
                    if (EL.bytesRate) EL.bytesRate.textContent = `${byteRate}%`;
                }

                if (EL.totalReqs) EL.totalReqs.textContent = cf.requests.toLocaleString();
                if (EL.cachedReqs) EL.cachedReqs.textContent = cf.cached_requests.toLocaleString();

                if (EL.reqsBar || EL.reqsRate) {
                    const reqRate = cf.requests > 0 ? (cf.cached_requests / cf.requests * 100).toFixed(1) : 0;
                    if (EL.reqsBar) EL.reqsBar.style.width = `${reqRate}%`;
                    if (EL.reqsRate) EL.reqsRate.textContent = `${reqRate}%`;
                }

                // Render Charts if series data available
                if (cf.series) {
                    if (document.getElementById('chartContainer')) {
                        renderChart(cf.series, 'chartContainer', 'bytes', formatBytes, 'var(--primary)');
                    }
                    if (document.getElementById('reqChartContainer')) {
                        renderChart(cf.series, 'reqChartContainer', 'requests', formatNumber, 'var(--accent)');
                    }
                }
            }
        } catch (e) {
            console.warn('Stats fetch failed', e);
        }
    }

    async function fetchInitialData() {
        try {
            const healthRes = await fetch(CONFIG.API_HEALTH);
            if (healthRes.ok) {
                const health = await healthRes.json();
                if (health.version) {
                    if (EL.versionBadge) EL.versionBadge.textContent = `v${health.version}`;
                    if (EL.version) EL.version.textContent = `v${health.version}`;
                }
            }
        } catch (e) {
            // silent fail
        }
    }

    function renderChart(series, containerId, key, formatFn, colorVar) {
        const container = document.getElementById(containerId);
        if (!container) return;

        // Process data
        const data = series.map(s => ({
            date: s.date.slice(5), // Remove year "MM-DD"
            val: s[key]
        }));

        const maxVal = Math.max(...data.map(d => d.val)) * 1.1; // 10% padding
        if (maxVal === 0) return;

        const width = container.clientWidth;
        const height = container.clientHeight;
        const padding = 30;
        const chartW = width - padding * 2;
        const chartH = height - padding * 2;

        // Generate points
        const points = data.map((d, i) => {
            const x = padding + (i / (data.length - 1)) * chartW;
            const y = height - padding - (d.val / maxVal) * chartH;
            return `${x},${y}`;
        }).join(' ');

        // Generate fill path (close the loop)
        const firstX = padding;
        const lastX = padding + chartW;
        const bottomY = height - padding;
        const fillPath = `${firstX},${bottomY} ${points} ${lastX},${bottomY}`;

        // Create SVG
        const svgNs = "http://www.w3.org/2000/svg";

        // Clear previous
        container.innerHTML = '';

        const svg = document.createElementNS(svgNs, "svg");
        svg.setAttribute("width", "100%");
        svg.setAttribute("height", "100%");
        svg.setAttribute("viewBox", `0 0 ${width} ${height}`);
        svg.style.overflow = 'visible';

        // Gradient
        const gradId = 'grad-' + containerId;
        const defs = document.createElementNS(svgNs, "defs");
        const grad = document.createElementNS(svgNs, "linearGradient");
        grad.id = gradId;
        grad.setAttribute("x1", "0");
        grad.setAttribute("y1", "0");
        grad.setAttribute("x2", "0");
        grad.setAttribute("y2", "1");

        const stop1 = document.createElementNS(svgNs, "stop");
        stop1.setAttribute("offset", "0%");
        stop1.setAttribute("stop-color", colorVar);
        stop1.setAttribute("stop-opacity", "0.3");

        const stop2 = document.createElementNS(svgNs, "stop");
        stop2.setAttribute("offset", "100%");
        stop2.setAttribute("stop-color", colorVar);
        stop2.setAttribute("stop-opacity", "0.0");

        grad.appendChild(stop1);
        grad.appendChild(stop2);
        defs.appendChild(grad);
        svg.appendChild(defs);

        // Area (Fill)
        const area = document.createElementNS(svgNs, "polygon");
        area.setAttribute("points", fillPath);
        area.setAttribute("fill", `url(#${gradId})`);
        svg.appendChild(area);

        // Line
        const line = document.createElementNS(svgNs, "polyline");
        line.setAttribute("points", points);
        line.setAttribute("fill", "none");
        line.setAttribute("stroke", colorVar);
        line.setAttribute("stroke-width", "3");
        line.setAttribute("stroke-linecap", "round");
        line.setAttribute("stroke-linejoin", "round");
        svg.appendChild(line);

        // Grid lines & Labels
        // Y Axis (0, 50%, 100%)
        [0, 0.5, 1].forEach(pct => {
            const y = height - padding - (pct * chartH);
            const gridLine = document.createElementNS(svgNs, "line");
            gridLine.setAttribute("x1", padding);
            gridLine.setAttribute("y1", y);
            gridLine.setAttribute("x2", width - padding);
            gridLine.setAttribute("y2", y);
            gridLine.setAttribute("stroke", "var(--border)");
            gridLine.setAttribute("stroke-dasharray", "4 4");
            svg.appendChild(gridLine);

            const label = document.createElementNS(svgNs, "text");
            label.setAttribute("x", padding - 5);
            label.setAttribute("y", y + 4);
            label.setAttribute("text-anchor", "end");
            label.setAttribute("fill", "var(--text-muted)");
            label.setAttribute("font-size", "10");
            label.textContent = formatFn(maxVal * pct);
            svg.appendChild(label);
        });

        // X Axis Labels (Show All)
        data.forEach((d, i) => {
            // Show every label
            const x = padding + (i / (data.length - 1)) * chartW;
            const label = document.createElementNS(svgNs, "text");
            label.setAttribute("x", x);
            label.setAttribute("y", height - padding + 15);
            label.setAttribute("text-anchor", "middle");
            label.setAttribute("fill", "var(--text-muted)");
            label.setAttribute("font-size", "8"); // Compact font
            label.textContent = d.date;
            svg.appendChild(label);
        });

        // Tooltip interaction (simple overlay)
        // ... (Optional: omitted for brevity, keeping simple static chart first)

        container.appendChild(svg);
    }

    // ========================================================================
    // Event Binding
    // ========================================================================

    function bindEvents() {
        // Theme
        if (EL.themeToggle) {
            EL.themeToggle.addEventListener('click', toggleTheme);
        }

        // Format tabs
        EL.formatBtns.forEach(btn => {
            btn.addEventListener('click', () => {
                EL.formatBtns.forEach(b => b.classList.remove('active'));
                btn.classList.add('active');
                STATE.format = btn.dataset.format;
                if (EL.input.value.trim()) processInput();
            });
        });

        // Input
        if (EL.input) {
            EL.input.addEventListener('input', () => {
                const hasVal = !!EL.input.value.trim();
                updateInputButtons(hasValue);
            });

            EL.input.addEventListener('keydown', (e) => {
                if (e.key === 'Enter') {
                    e.preventDefault();
                    processInput();
                }
            });

            // Clear/Paste
            if (EL.clearBtn) {
                EL.clearBtn.addEventListener('click', () => {
                    EL.input.value = '';
                    EL.input.focus();
                    EL.outputCard.style.display = 'none';
                    updateInputButtons(false);
                });
            }

            if (EL.pasteBtn) {
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
            }

            // Generate/Copy/Open
            EL.generateBtn.addEventListener('click', processInput);
            EL.copyBtn.addEventListener('click', () => copyToClipboard(EL.outputContent.textContent));
            EL.openBtn.addEventListener('click', () => {
                window.open(EL.outputContent.textContent, '_blank', 'noopener,noreferrer');
            });
        }

        // Stats visibility
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
        applyTheme(STATE.theme);

        if (EL.input) {
            EL.input.focus();
            if (navigator.clipboard && navigator.clipboard.readText) {
                EL.pasteBtn.style.display = 'flex';
            }
        }

        bindEvents();
        renderHistory();
        fetchInitialData();
        fetchStats(); // Explicitly fetch stats immediately

        STATE.statsInterval = setInterval(fetchStats, CONFIG.STATS_INTERVAL_MS);
    }

    init();
})();