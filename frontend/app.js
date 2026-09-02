/**
 * WebSpectra - Web Application Security Scanner Dashboard
 * Client-side Controller (Vanilla JS)
 */

document.addEventListener('DOMContentLoaded', () => {
    // DOM Elements
    const scanForm = document.getElementById('scan-form');
    const targetUrlInput = document.getElementById('target-url');
    const scanBtn = document.getElementById('scan-btn');
    const presets = document.querySelectorAll('.preset-btn');
    
    // UI State Elements
    const scanningState = document.getElementById('scanning-state');
    const scanningStep = document.getElementById('scanning-step');
    const errorAlert = document.getElementById('error-alert');
    const errorMessage = document.getElementById('error-message');
    const dismissErrorBtn = document.getElementById('dismiss-error-btn');
    const resultsSection = document.getElementById('results-section');
    const noFindingsState = document.getElementById('no-findings-state');
    const apiStatusText = document.getElementById('api-status-text');

    // Target Metadata Elements
    const resTargetUrl = document.getElementById('res-target-url');
    const resFinalUrl = document.getElementById('res-final-url');
    const resStatusCode = document.getElementById('res-status-code');
    const resResponseTime = document.getElementById('res-response-time');
    const resTimestamp = document.getElementById('res-timestamp');

    // Score Elements
    const resScoreNumber = document.getElementById('res-score-number');
    const scoreMeter = document.getElementById('score-meter');
    const resGradeBadge = document.getElementById('res-grade-badge');
    const resRiskBadge = document.getElementById('res-risk-badge');
    const totalFindingsBadge = document.getElementById('total-findings-badge');

    // Finding Counts & Tabs
    const countCritical = document.getElementById('count-critical');
    const countHigh = document.getElementById('count-high');
    const countMedium = document.getElementById('count-medium');
    const countLow = document.getElementById('count-low');

    const tabCountAll = document.getElementById('tab-count-all');
    const tabCountCritical = document.getElementById('tab-count-critical');
    const tabCountHigh = document.getElementById('tab-count-high');
    const tabCountMedium = document.getElementById('tab-count-medium');
    const tabCountLow = document.getElementById('tab-count-low');

    const filterBtns = document.querySelectorAll('.filter-btn');
    const findingsList = document.getElementById('findings-list');

    // State Variables
    let currentFindings = [];
    let activeFilter = 'all';
    let stepInterval = null;

    // Base API URL configuration:
    // If loaded from a static server (e.g. VS Code Live Server on :5500, Vite :5173, or file://),
    // target the FastAPI backend at http://127.0.0.1:8000.
    // If served directly through FastAPI on port 8000, use relative URL ''.
    const API_BASE = (window.location.protocol === 'file:' || (window.location.port !== '8000' && window.location.port !== ''))
        ? 'http://127.0.0.1:8000'
        : '';

    // Check Backend API Health on Load
    checkApiHealth();

    // -------------------------------------------------------------------------
    // Event Listeners
    // -------------------------------------------------------------------------
    scanForm.addEventListener('submit', (e) => {
        e.preventDefault();
        const url = targetUrlInput.value.trim();
        if (url) {
            executeScan(url);
        }
    });

    presets.forEach(btn => {
        btn.addEventListener('click', () => {
            const url = btn.getAttribute('data-url');
            if (url) {
                targetUrlInput.value = url;
                executeScan(url);
            }
        });
    });

    dismissErrorBtn.addEventListener('click', () => {
        errorAlert.classList.add('hidden');
    });

    filterBtns.forEach(btn => {
        btn.addEventListener('click', () => {
            filterBtns.forEach(b => b.classList.remove('active'));
            btn.classList.add('active');
            activeFilter = btn.getAttribute('data-filter');
            renderFindings();
        });
    });

    // -------------------------------------------------------------------------
    // API Health Check
    // -------------------------------------------------------------------------
    async function checkApiHealth() {
        try {
            const res = await fetch(`${API_BASE}/api/health`);
            if (res.ok) {
                apiStatusText.textContent = 'Engine Ready';
                apiStatusText.style.color = 'var(--accent-cyan)';
            } else {
                apiStatusText.textContent = 'Engine Offline (Start Backend)';
                apiStatusText.style.color = 'var(--accent-red)';
            }
        } catch {
            apiStatusText.textContent = 'Engine Offline (Start Backend)';
            apiStatusText.style.color = 'var(--accent-red)';
        }
    }

    // -------------------------------------------------------------------------
    // Scan Execution
    // -------------------------------------------------------------------------
    async function executeScan(url) {
        // UI Preparation
        errorAlert.classList.add('hidden');
        resultsSection.classList.add('hidden');
        scanningState.classList.remove('hidden');
        scanBtn.disabled = true;
        
        startStepAnimation();

        try {
            const response = await fetch(`${API_BASE}/api/scan`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ url: url })
            });

            let data = null;
            try {
                data = await response.json();
            } catch (_) {
                data = null;
            }

            if (!response.ok) {
                if (response.status === 404) {
                    throw new Error('API route /api/scan not found (404). Please ensure the FastAPI backend is running via "python -m uvicorn backend.main:app --reload" at http://127.0.0.1:8000.');
                }
                const detailMsg = (data && data.detail) || `Server responded with status ${response.status}.`;
                throw new Error(detailMsg);
            }

            if (!data) {
                throw new Error('Invalid or empty response from backend scanner.');
            }

            // Display Results
            displayScanResults(data);

        } catch (err) {
            let msg = err.message || 'Failed to communicate with the WebSpectra scanner.';
            if (msg.includes('Failed to fetch') || msg.includes('NetworkError') || msg.includes('Network request failed')) {
                msg = 'Unable to connect to WebSpectra backend API. Please make sure the FastAPI server is running with: python -m uvicorn backend.main:app --reload (at http://127.0.0.1:8000)';
            }
            showError(msg);
        } finally {
            stopStepAnimation();
            scanningState.classList.add('hidden');
            scanBtn.disabled = false;
        }
    }

    // -------------------------------------------------------------------------
    // Loading Steps Animation
    // -------------------------------------------------------------------------
    function startStepAnimation() {
        const steps = [
            'Resolving host and establishing safe connection...',
            'Executing passive HTTP request & inspecting redirects...',
            'Auditing response headers (CSP, X-Content-Type, X-Frame-Options)...',
            'Analyzing TLS encryption, HSTS policies, and Referrer settings...',
            'Inspecting cookie attributes (Secure, HttpOnly, SameSite)...',
            'Calculating heuristic security rating and generating remediation...'
        ];
        let idx = 0;
        scanningStep.textContent = steps[0];
        stepInterval = setInterval(() => {
            idx = (idx + 1) % steps.length;
            scanningStep.textContent = steps[idx];
        }, 1200);
    }

    function stopStepAnimation() {
        if (stepInterval) {
            clearInterval(stepInterval);
            stepInterval = null;
        }
    }

    // -------------------------------------------------------------------------
    // Display Results
    // -------------------------------------------------------------------------
    function displayScanResults(data) {
        // Populate Target Metadata (Safe textContent)
        resTargetUrl.textContent = data.target_url;
        resFinalUrl.textContent = data.final_url;
        resStatusCode.textContent = `${data.status_code} OK`;
        resResponseTime.textContent = `${data.response_time_ms} ms`;
        resTimestamp.textContent = data.scan_timestamp;

        // Populate Score
        const score = data.score;
        resScoreNumber.textContent = score;
        updateScoreMeter(score);

        // Grade Badge
        const grade = data.grade;
        resGradeBadge.textContent = grade;
        resGradeBadge.className = `grade-badge grade-${grade.toLowerCase()}`;

        // Risk Badge
        const risk = data.risk_level;
        resRiskBadge.textContent = risk;
        resRiskBadge.className = `risk-badge risk-${risk.toLowerCase()}`;

        // Findings Metrics
        const summary = data.summary || { critical: 0, high: 0, medium: 0, low: 0 };
        countCritical.textContent = summary.critical;
        countHigh.textContent = summary.high;
        countMedium.textContent = summary.medium;
        countLow.textContent = summary.low;

        // Total Tag
        const total = data.findings_count || 0;
        totalFindingsBadge.textContent = `${total} ${total === 1 ? 'Finding' : 'Findings'}`;

        // Tab Counts
        tabCountAll.textContent = total;
        tabCountCritical.textContent = summary.critical;
        tabCountHigh.textContent = summary.high;
        tabCountMedium.textContent = summary.medium;
        tabCountLow.textContent = summary.low;

        // Store Findings and Render
        currentFindings = data.findings || [];
        activeFilter = 'all';
        
        // Reset active filter button
        filterBtns.forEach(b => {
            b.classList.toggle('active', b.getAttribute('data-filter') === 'all');
        });

        renderFindings();

        // Reveal Results
        resultsSection.classList.remove('hidden');
        resultsSection.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }

    // -------------------------------------------------------------------------
    // Animate SVG Score Meter
    // -------------------------------------------------------------------------
    function updateScoreMeter(score) {
        const radius = 50;
        const circumference = 2 * Math.PI * radius; // ~314.159
        const offset = circumference - (score / 100) * circumference;
        
        scoreMeter.style.strokeDashoffset = offset;

        // Color based on score
        if (score >= 90) {
            scoreMeter.style.stroke = '#10b981'; // Emerald
        } else if (score >= 80) {
            scoreMeter.style.stroke = '#06b6d4'; // Cyan
        } else if (score >= 70) {
            scoreMeter.style.stroke = '#eab308'; // Amber
        } else if (score >= 60) {
            scoreMeter.style.stroke = '#f97316'; // Orange
        } else {
            scoreMeter.style.stroke = '#ef4444'; // Red
        }
    }

    // -------------------------------------------------------------------------
    // Render Findings List (XSS-Safe DOM Generation)
    // -------------------------------------------------------------------------
    function renderFindings() {
        findingsList.innerHTML = '';

        const filtered = currentFindings.filter(f => {
            if (activeFilter === 'all') return true;
            return (f.severity || '').toLowerCase() === activeFilter.toLowerCase();
        });

        if (filtered.length === 0) {
            if (currentFindings.length === 0) {
                noFindingsState.classList.remove('hidden');
            } else {
                noFindingsState.classList.add('hidden');
                const emptyMsg = document.createElement('div');
                emptyMsg.className = 'clean-target-card';
                emptyMsg.innerHTML = `<p class="subtext">No findings with severity "${escapeHtml(activeFilter)}".</p>`;
                findingsList.appendChild(emptyMsg);
            }
            return;
        }

        noFindingsState.classList.add('hidden');

        filtered.forEach(finding => {
            const card = createFindingCard(finding);
            findingsList.appendChild(card);
        });
    }

    // -------------------------------------------------------------------------
    // Build Individual Finding Card DOM
    // -------------------------------------------------------------------------
    function createFindingCard(f) {
        const card = document.createElement('div');
        card.className = 'finding-card';

        const sev = (f.severity || 'Low').toLowerCase();
        const confPercent = Math.round((f.confidence || 0.9) * 100);

        // Header
        const header = document.createElement('div');
        header.className = 'finding-header';

        const titleWrap = document.createElement('div');
        titleWrap.className = 'finding-title-wrap';

        const idBadge = document.createElement('span');
        idBadge.className = 'finding-id';
        idBadge.textContent = f.id || 'SEC';

        const titleText = document.createElement('h3');
        titleText.className = 'finding-title';
        titleText.textContent = f.title;

        titleWrap.appendChild(idBadge);
        titleWrap.appendChild(titleText);

        const badges = document.createElement('div');
        badges.className = 'finding-badges';

        const sevBadge = document.createElement('span');
        sevBadge.className = `severity-pill pill-${sev}`;
        sevBadge.textContent = f.severity;

        const confBadge = document.createElement('span');
        confBadge.className = 'confidence-pill';
        confBadge.textContent = `${confPercent}% Conf.`;

        badges.appendChild(sevBadge);
        badges.appendChild(confBadge);

        header.appendChild(titleWrap);
        header.appendChild(badges);
        card.appendChild(header);

        // Body
        const body = document.createElement('div');
        body.className = 'finding-body';

        // What we found
        body.appendChild(createDetailBlock('What We Found', f.description));

        // Impact
        body.appendChild(createDetailBlock('Why It Matters (Impact)', f.impact));

        // Recommendation
        const recBlock = document.createElement('div');
        recBlock.className = 'remediation-block';
        
        const recHeading = document.createElement('div');
        recHeading.className = 'detail-heading';
        recHeading.textContent = 'Recommended Fix';
        
        const recText = document.createElement('div');
        recText.className = 'detail-text';
        recText.textContent = f.recommendation;

        recBlock.appendChild(recHeading);
        recBlock.appendChild(recText);

        // Configuration Examples
        if (f.examples && (f.examples.nginx || f.examples.apache)) {
            const configWrapper = document.createElement('div');
            configWrapper.className = 'configs-wrapper';

            if (f.examples.nginx) {
                configWrapper.appendChild(createCodeSnippet('Nginx Configuration', f.examples.nginx));
            }
            if (f.examples.apache) {
                configWrapper.appendChild(createCodeSnippet('Apache (.htaccess / httpd.conf)', f.examples.apache));
            }
            recBlock.appendChild(configWrapper);
        }

        body.appendChild(recBlock);
        card.appendChild(body);

        return card;
    }

    function createDetailBlock(headingText, contentText) {
        const block = document.createElement('div');
        block.className = 'detail-block';

        const heading = document.createElement('div');
        heading.className = 'detail-heading';
        heading.textContent = headingText;

        const text = document.createElement('div');
        text.className = 'detail-text';
        text.textContent = contentText;

        block.appendChild(heading);
        block.appendChild(text);
        return block;
    }

    function createCodeSnippet(serverLabel, codeText) {
        const card = document.createElement('div');
        card.className = 'code-snippet-card';

        const header = document.createElement('div');
        header.className = 'code-snippet-header';

        const label = document.createElement('span');
        label.className = 'server-tag';
        label.textContent = serverLabel;

        const copyBtn = document.createElement('button');
        copyBtn.className = 'copy-btn';
        copyBtn.textContent = 'Copy';
        copyBtn.type = 'button';

        copyBtn.addEventListener('click', () => {
            navigator.clipboard.writeText(codeText).then(() => {
                copyBtn.textContent = 'Copied!';
                setTimeout(() => {
                    copyBtn.textContent = 'Copy';
                }, 2000);
            }).catch(() => {
                copyBtn.textContent = 'Copied!';
            });
        });

        header.appendChild(label);
        header.appendChild(copyBtn);

        const pre = document.createElement('pre');
        pre.textContent = codeText;

        card.appendChild(header);
        card.appendChild(pre);
        return card;
    }

    // -------------------------------------------------------------------------
    // Error Handling
    // -------------------------------------------------------------------------
    function showError(msg) {
        errorMessage.textContent = msg;
        errorAlert.classList.remove('hidden');
        errorAlert.scrollIntoView({ behavior: 'smooth', block: 'center' });
    }

    function escapeHtml(str) {
        return (str || '').replace(/[&<>"']/g, (m) => ({
            '&': '&amp;',
            '<': '&lt;',
            '>': '&gt;',
            '"': '&quot;',
            "'": '&#39;'
        })[m]);
    }
});
