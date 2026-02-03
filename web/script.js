(function () {
    'use strict';

    const EL = {
        input: document.getElementById('inputUrl'),
        generateBtn: document.getElementById('generateBtn'),
        tabs: document.querySelectorAll('.tab'),
        outputCard: document.getElementById('resultDisplay'),
        outputContent: document.getElementById('outputContent'),
        copyBtn: document.getElementById('copyBtn'),
        openBtn: document.getElementById('openBtn'),
        toast: document.getElementById('toast')
    };

    let currentFormat = 'direct';

    function showToast(msg) {
        EL.toast.textContent = msg;
        EL.toast.classList.add('visible');
        setTimeout(() => EL.toast.classList.remove('visible'), 2000);
    }

    function process() {
        let rawUrl = EL.input.value.trim();
        if (!rawUrl) {
            EL.outputCard.style.display = 'none';
            return;
        }

        // Clean up URL
        rawUrl = rawUrl.replace(/^https?:\/\/[^\/]+\/(https?:\/\/)/i, '$1');

        const baseUrl = window.location.origin;
        let result = '';
        let isUrl = true;

        try {
            if (currentFormat === 'docker') {
                let dockerRef = rawUrl.replace(/^https?:\/\//i, '').replace(/\/$/, '');
                result = `docker pull ${window.location.host}/${dockerRef}`;
                isUrl = false;
            } else {
                if (!/^https?:\/\//i.test(rawUrl)) {
                    if (rawUrl.includes('/')) {
                        rawUrl = 'https://github.com/' + rawUrl;
                    } else {
                        throw new Error('Invalid');
                    }
                }

                const urlObj = new URL(rawUrl);
                const proxyLink = `${baseUrl}/${urlObj.hostname}${urlObj.pathname}${urlObj.search}${urlObj.hash}`;

                switch (currentFormat) {
                    case 'git': result = `git clone ${proxyLink}`; isUrl = false; break;
                    case 'wget': result = `wget "${proxyLink}"`; isUrl = false; break;
                    case 'curl': result = `curl -O "${proxyLink}"`; isUrl = false; break;
                    default: result = proxyLink;
                }
            }
            
            EL.outputContent.textContent = result;
            EL.outputCard.style.display = 'block';
            EL.openBtn.style.display = isUrl ? 'block' : 'none';
        } catch (e) {
            showToast('请输入有效的链接或 Repo 路径');
            EL.outputCard.style.display = 'none';
        }
    }

    // Events
    EL.tabs.forEach(tab => {
        tab.addEventListener('click', () => {
            EL.tabs.forEach(t => t.classList.remove('active'));
            tab.classList.add('active');
            currentFormat = tab.dataset.format;
            if (EL.input.value.trim()) process();
        });
    });

    EL.generateBtn.addEventListener('click', process);
    EL.input.addEventListener('keypress', e => e.key === 'Enter' && process());
    EL.input.addEventListener('paste', () => setTimeout(process, 10));

    EL.copyBtn.addEventListener('click', async () => {
        try {
            await navigator.clipboard.writeText(EL.outputContent.textContent);
            showToast('已复制到剪贴板');
        } catch (err) {
            const ta = document.createElement("textarea");
            ta.value = EL.outputContent.textContent;
            document.body.appendChild(ta);
            ta.select();
            document.execCommand('copy');
            document.body.removeChild(ta);
            showToast('已复制');
        }
    });

    EL.openBtn.addEventListener('click', () => {
        if (EL.outputContent.textContent.startsWith('http')) {
            window.open(EL.outputContent.textContent, '_blank', 'noopener,noreferrer');
        }
    });
})();
