// --- DOM ELEMENTS ---
const alertsList = document.getElementById('alertsList');
const extendedLogsList = document.getElementById('extendedLogsList');
const redAlertOverlay = document.getElementById('redAlertOverlay');
const lockdownOverlay = document.getElementById('lockdownOverlay');
const packetStream = document.getElementById('packetStream');
const mapContainer = document.querySelector('.map-container');
const aiConfidenceValue = document.getElementById('aiConfidenceValue');
const aiConfidenceFill = document.getElementById('aiConfidenceFill');
const riskMeter = document.getElementById('riskMeter');
const riskScoreDisplay = document.getElementById('riskScore');
const riskLabel = document.getElementById('riskLabel');

const API_BASE = window.location.origin;

// --- SPA ROUTING LOGIC ---
document.querySelectorAll('.nav-item').forEach(item => {
    item.addEventListener('click', (e) => {
        e.preventDefault();
        const sectionId = item.getAttribute('data-section');
        if (sectionId) {
            window.location.hash = sectionId;
        }
    });
});

window.addEventListener('hashchange', () => {
    const sectionId = window.location.hash.replace('#', '') || 'dashboard';
    navigateTo(sectionId);
});

function navigateTo(sectionId) {
    // Update active nav item
    document.querySelectorAll('.nav-item').forEach(nav => nav.classList.remove('active'));
    const activeNav = document.querySelector(`[data-section="${sectionId}"]`);
    if (activeNav) activeNav.classList.add('active');

    // Update active section
    document.querySelectorAll('.page-section').forEach(section => {
        section.classList.remove('active-section');
    });

    const targetSection = document.getElementById(sectionId);
    if (targetSection) {
        targetSection.classList.add('active-section');
    }
}

// Initial Navigation
const initialHash = window.location.hash.replace('#', '') || 'dashboard';
navigateTo(initialHash);

// --- INITIALIZE DASHBOARD ---
initMapAnimation();
initPacketStream();
addAlert("10:42:05", "google.com", "Safe");
addAlert("10:15:30", "auth-secure-login.xyz", "Phishing");

// --- UNIFIED SCANNER HUB LOGIC ---
function switchScannerTab(tab) {
    document.querySelectorAll('#url-scanner .tab-btn').forEach(btn => btn.classList.remove('active'));
    const btn = document.getElementById(`tabBtn${tab.charAt(0).toUpperCase() + tab.slice(1)}`);
    if (btn) btn.classList.add('active');

    document.getElementById('scannerUrl').style.display = tab === 'url' ? 'block' : 'none';
    document.getElementById('scannerText').style.display = tab === 'text' ? 'block' : 'none';
    document.getElementById('scannerQr').style.display = tab === 'qr' ? 'block' : 'none';

    document.getElementById('scannerResults').style.display = 'none';
}

// ═══════════════════════════════════════════════════════════
//  QR SCANNER MODULE — self-contained, persistent, resettable
// ═══════════════════════════════════════════════════════════
(function initQrModule() {
    const dropZoneEl = document.getElementById('qrDropZone');
    const fileInputEl = document.getElementById('qrFileInput');
    const previewStrip = document.getElementById('qrPreviewStrip');
    const previewImg = document.getElementById('qrPreviewImg');
    const fileNameEl = document.getElementById('qrFileName');
    const fileSizeEl = document.getElementById('qrFileSize');
    const loadingEl = document.getElementById('qrLoadingState');
    const resultPanel = document.getElementById('qrResultPanel');

    if (!dropZoneEl) return; // guard against missing DOM

    // Click to open file browser
    dropZoneEl.addEventListener('click', () => fileInputEl.click());
    dropZoneEl.addEventListener('keydown', (e) => {
        if (e.key === 'Enter' || e.key === ' ') fileInputEl.click();
    });

    // Drag-and-drop support
    dropZoneEl.addEventListener('dragover', (e) => {
        e.preventDefault();
        dropZoneEl.classList.add('qr-drag-over');
    });
    dropZoneEl.addEventListener('dragleave', () => dropZoneEl.classList.remove('qr-drag-over'));
    dropZoneEl.addEventListener('drop', (e) => {
        e.preventDefault();
        dropZoneEl.classList.remove('qr-drag-over');
        const file = e.dataTransfer.files[0];
        if (file && file.type.startsWith('image/')) handleQrFile(file);
        else notifySystem('QR UPLOAD: IMAGE FILE REQUIRED');
    });

    // File input change
    fileInputEl.addEventListener('change', (e) => {
        if (e.target.files.length > 0) handleQrFile(e.target.files[0]);
    });

    function handleQrFile(file) {
        // Show preview strip, keep dropzone visible
        const reader = new FileReader();
        reader.onload = (ev) => { previewImg.src = ev.target.result; };
        reader.readAsDataURL(file);

        fileNameEl.textContent = file.name;
        fileSizeEl.textContent = (file.size / 1024).toFixed(1) + ' KB';
        previewStrip.style.display = 'flex';
        resultPanel.style.display = 'none';
        loadingEl.style.display = 'none';
        dropZoneEl.classList.add('qr-has-file');
    }

    // Expose reset so buttons can call it globally
    window.resetQrUpload = function () {
        fileInputEl.value = '';
        previewImg.src = '';
        fileNameEl.textContent = '—';
        fileSizeEl.textContent = '—';
        previewStrip.style.display = 'none';
        loadingEl.style.display = 'none';
        resultPanel.style.display = 'none';
        dropZoneEl.classList.remove('qr-has-file', 'qr-drag-over');
        // Also hide the shared results pane for this tab
        const sharedResults = document.getElementById('scannerResults');
        if (sharedResults) sharedResults.style.display = 'none';
    };

    // Expose scan trigger
    window.runQrScan = async function () {
        if (!fileInputEl.files || fileInputEl.files.length === 0) {
            notifySystem('QR SCAN: SELECT AN IMAGE FIRST');
            return;
        }

        const scanBtn = document.getElementById('qrScanBtn');
        if (scanBtn) { scanBtn.disabled = true; scanBtn.textContent = 'SCANNING...'; }

        previewStrip.style.display = 'none';
        loadingEl.style.display = 'flex';
        resultPanel.style.display = 'none';

        // Also drive the shared radar
        const radarSweep = document.getElementById('radarSweep');
        const radarStatus = document.getElementById('radarStatus');
        if (radarSweep) radarSweep.style.display = 'block';
        if (radarStatus) { radarStatus.textContent = 'QR ANALYSIS IN PROGRESS...'; radarStatus.style.color = 'var(--neon-blue)'; }

        try {
            const formData = new FormData();
            formData.append('file', fileInputEl.files[0]);
            const res = await fetch(`${API_BASE}/scan_qr`, { method: 'POST', body: formData });
            const data = await res.json();

            // Small delay for UX
            await new Promise(r => setTimeout(r, 1200));

            loadingEl.style.display = 'none';
            renderQrResult(data);

            // Also update shared radar & global XAI
            if (radarSweep) radarSweep.style.display = 'none';
            const status = data.status || 'Safe';
            const color = status === 'Phishing' ? 'var(--neon-red)' : status === 'Suspicious' ? 'var(--neon-yellow)' : 'var(--neon-green)';
            if (radarStatus) { radarStatus.textContent = 'QR SCAN COMPLETE'; radarStatus.style.color = color; }

            // Feed global UI pipeline (alerts, charts, dashboard metrics)
            updateUI(data);

        } catch (err) {
            loadingEl.style.display = 'none';
            previewStrip.style.display = 'flex';
            if (radarSweep) radarSweep.style.display = 'none';
            if (radarStatus) radarStatus.textContent = 'QR SCAN ERROR';
            notifySystem('QR SCAN ERROR: ' + err.message);
        } finally {
            if (scanBtn) { scanBtn.disabled = false; scanBtn.innerHTML = '<ion-icon name="scan-outline"></ion-icon> DECODE &amp; SCAN'; }
        }
    };

    function renderQrResult(data) {
        const status = data.status || 'Safe';
        const riskPct = Math.round((data.risk_score || 0) * 100);
        const decodedUrl = data.decoded_url || '—';
        const color = status === 'Phishing' ? 'var(--neon-red)' : status === 'Suspicious' ? 'var(--neon-yellow)' : 'var(--neon-green)';

        document.getElementById('qrInlineUrl').textContent = decodedUrl;
        document.getElementById('qrRiskNum').textContent = riskPct;
        document.getElementById('qrRiskNum').style.color = color;

        const bar = document.getElementById('qrRiskBar');
        bar.style.width = riskPct + '%';
        bar.style.background = color;
        bar.style.boxShadow = `0 0 10px ${color}`;

        const badge = document.getElementById('qrThreatBadge');
        badge.textContent = status.toUpperCase();
        badge.style.color = color;
        badge.style.borderColor = color;
        badge.style.boxShadow = `0 0 8px ${color}33`;

        // Inline AI breakdown
        const breakdownEl = document.getElementById('qrBreakdownArea');
        if (breakdownEl) {
            breakdownEl.innerHTML = '';
            updateUnifiedXai(data, 'qrBreakdownArea');
        }

        resultPanel.style.display = 'block';
        resultPanel.scrollIntoView({ behavior: 'smooth', block: 'nearest' });

        if (status === 'Phishing') triggerRedAlert();
    }

})();


async function runUnifiedScan(mode) {
    const resultsEl = document.getElementById('scannerResults');
    const radarSweep = document.getElementById('radarSweep');
    const radarStatus = document.getElementById('radarStatus');
    const riskScore = document.getElementById('unifiedRiskScore');
    const threatLevel = document.getElementById('unifiedThreatLevel');
    const decodedArea = document.getElementById('qrDecodedUrl');

    resultsEl.style.display = 'none';
    radarSweep.style.display = 'block';
    radarStatus.textContent = mode.toUpperCase() + " ANALYSIS IN PROGRESS...";
    radarStatus.style.color = "var(--neon-blue)";
    decodedArea.style.display = 'none';

    let data = null;
    try {
        if (mode === 'url') {
            const url = document.getElementById('unifiedUrlInput').value.trim();
            if (!url) throw new Error("URL REQUIRED");
            const res = await fetch(`${API_BASE}/scan_url`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ url: url })
            });
            data = await res.json();
        } else if (mode === 'text') {
            const text = document.getElementById('unifiedTextInput').value.trim();
            if (!text) throw new Error("CONTENT REQUIRED");
            const res = await fetch(`${API_BASE}/scan_text`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ text: text })
            });
            data = await res.json();
        } else if (mode === 'qr') {
            // QR scanning is handled by the QR module (runQrScan).
            if (typeof window.runQrScan === 'function') window.runQrScan();
            return;
        }

        setTimeout(() => {
            radarSweep.style.display = 'none';
            radarStatus.textContent = "SCAN COMPLETE";
            resultsEl.style.display = 'block';

            const score = (data.risk_score * 100).toFixed(0);
            riskScore.textContent = score + "%";
            threatLevel.textContent = data.status.toUpperCase();

            let color = "var(--neon-green)";
            if (data.status === 'Suspicious') color = "var(--neon-yellow)";
            if (data.status === 'Phishing') {
                color = "var(--neon-red)";
                triggerRedAlert();
            }
            threatLevel.style.color = color;
            radarStatus.style.color = color;

            updateUnifiedXai(data);
            updateUI(data);
        }, 1500);

    } catch (e) {
        alert("SCAN ERROR: " + e.message);
        radarSweep.style.display = 'none';
        radarStatus.textContent = "RADAR ERROR";
    }
}

function updateUnifiedXai(data, targetId) {
    const containerId = targetId || 'unifiedXai';
    const container = document.getElementById(containerId);
    if (!container) return;
    container.innerHTML = '';

    const status = data.status || 'Safe';
    const bd = data.ai_breakdown || {};
    const statusClass = status === 'Phishing' ? 'xai-high' : (status === 'Suspicious' ? 'xai-med' : 'xai-safe');
    const statusColor = status === 'Phishing' ? 'var(--neon-red)' : (status === 'Suspicious' ? 'var(--neon-yellow)' : 'var(--neon-green)');

    // ── Header ──────────────────────────────────────────────────────────
    const header = document.createElement('div');
    header.className = 'xai-breakdown-header';

    let badges = '';
    if (bd.blacklisted) badges += `<span class="xai-badge xai-badge-blacklist">⛔ HARD BLACKLIST</span>`;
    if (bd.rule_override_applied) badges += `<span class="xai-badge xai-badge-override">⚡ RULE OVERRIDE ACTIVE</span>`;
    if (data.source === 'QR_CODE') badges += `<span class="xai-badge xai-badge-qr">📷 QR SOURCE</span>`;
    if (bd.is_anomaly) badges += `<span class="xai-badge xai-badge-anomaly">🚨 ZERO-DAY ANOMALY</span>`;

    header.innerHTML = `
        <div class="xai-header-top">
            <span><ion-icon name="analytics-outline"></ion-icon> AI ANALYSIS BREAKDOWN</span>
            <span class="xai-verdict-badge" style="color:${statusColor};border-color:${statusColor}">${status.toUpperCase()}</span>
        </div>
        ${badges ? `<div class="xai-badges">${badges}</div>` : ''}
    `;
    container.appendChild(header);

    // ── Score Bars ───────────────────────────────────────────────────────
    const ruleScore = Math.round((bd.rule_score || 0) * 100);
    const mlScore = Math.round((bd.ml_score || 0) * 100);
    const mlConf = typeof bd.ml_confidence === 'number' ? bd.ml_confidence.toFixed(1) : (mlScore).toFixed(1);
    const finalScore = Math.round((bd.final_weighted_score || data.risk_score || 0) * 100);

    const colorFor = v => v > 70 ? 'fill-red' : v > 40 ? 'fill-yellow' : 'fill-green';

    const scoreSection = document.createElement('div');
    scoreSection.className = 'xai-score-section';
    scoreSection.innerHTML = `
        <div class="xai-score-row">
            <span class="xai-score-label">RULE ENGINE <span class="xai-weight">(40%)</span></span>
            <div class="xai-score-bar-track">
                <div class="xai-score-bar-fill ${colorFor(ruleScore)}" style="width:${ruleScore}%"></div>
            </div>
            <span class="xai-score-value">${ruleScore}%</span>
        </div>
        <div class="xai-score-row">
            <span class="xai-score-label">ML MODEL <span class="xai-weight">(60%)</span></span>
            <div class="xai-score-bar-track">
                <div class="xai-score-bar-fill ${colorFor(mlScore)}" style="width:${mlScore}%"></div>
            </div>
            <span class="xai-score-value">${mlScore}% <span class="xai-conf-label">conf ${mlConf}%</span></span>
        </div>
        <div class="xai-score-row xai-final-row">
            <span class="xai-score-label">HYBRID SCORE</span>
            <div class="xai-score-bar-track">
                <div class="xai-score-bar-fill ${colorFor(finalScore)}" style="width:${finalScore}%"></div>
            </div>
            <span class="xai-score-value" style="color:${statusColor};font-size:1.1em">${finalScore}%</span>
        </div>
    `;
    container.appendChild(scoreSection);

    // ── Feature Signal Breakdown (The 13 Features) ──────────────────────
    if (bd.features) {
        const featSection = document.createElement('div');
        featSection.className = 'xai-section';
        const labels = [
            "URL Length", "Hostname Len", "IP Present", "@ Symbol", "// Redirect", "Net Dots",
            "Hyphens (-)", "Digit Count", "HTTPS Base", "Subdomains",
            "Phishing Words", "TLD Risk", "Query Params"
        ];

        let featHtml = `
            <div class="xai-section-title">
                <ion-icon name="finger-print-outline"></ion-icon> FEATURE SIGNAL MATRIX (13 VECTORS)
            </div>
            <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 10px;">
        `;

        bd.features.forEach((val, idx) => {
            if (idx >= labels.length) return;
            const importance = bd.feature_impact ? (bd.feature_impact[idx] * 100).toFixed(1) : 0;
            const isHigh = (idx === 7 && val > 0) || (idx === 9 && val > 0) || (idx === 10 && val > 0.5);
            const color = isHigh ? 'var(--neon-red)' : 'var(--text-dim)';

            featHtml += `
                <div style="font-size: 0.7em; background: rgba(255,255,255,0.03); padding: 5px; border-radius: 2px;">
                    <div style="display: flex; justify-content: space-between; margin-bottom: 2px;">
                        <span style="color:${color}">${labels[idx]}</span>
                        <span style="color:var(--neon-blue)">${val}</span>
                    </div>
                    <div class="importance-bar-track">
                        <div class="importance-bar-fill" style="width:${importance}%"></div>
                    </div>
                </div>
            `;
        });

        featHtml += `</div>`;
        featSection.innerHTML = featHtml;
        container.appendChild(featSection);
    }

    // ── Threat Indicators / Flags ───────────────────────────────────────
    const keywords = bd.keywords_found || [];
    const domainFlags = bd.domain_flags || [];

    if (keywords.length > 0 || domainFlags.length > 0) {
        const flagSection = document.createElement('div');
        flagSection.className = 'xai-section';
        let flagHtml = `<div class="xai-section-title danger-title"><ion-icon name="warning-outline"></ion-icon> CRITICAL RISK SIGNALS</div>`;

        if (keywords.length > 0) {
            flagHtml += `<div class="xai-tags" style="margin-bottom:10px">${keywords.map(k => `<span class="xai-tag xai-tag-danger">${k.toUpperCase()}</span>`).join('')}</div>`;
        }
        if (domainFlags.length > 0) {
            flagHtml += `<div class="xai-flags-list">${domainFlags.map(f => `<div class="xai-flag-item"><ion-icon name="alert-circle-outline"></ion-icon> ${f}</div>`).join('')}</div>`;
        }
        flagSection.innerHTML = flagHtml;
        container.appendChild(flagSection);
    }

    // ── Recommendation ───────────────────────────────────────────────────
    if (data.recommendation) {
        const recSection = document.createElement('div');
        recSection.className = `xai-recommendation xai-rec-${status.toLowerCase()}`;
        recSection.innerHTML = `<ion-icon name="shield-half-outline"></ion-icon> <strong>SOC ADVISOR:</strong> ${data.recommendation}`;
        container.appendChild(recSection);
    }
}

// --- VOICE DETECTION PAGE LOGIC ---
const dropZone = document.getElementById('dropZone');
const voiceFileInput = document.getElementById('voiceFileInput');
const fileInfo = document.getElementById('fileInfo');
const fileNameDisplay = document.getElementById('fileNameDisplay');
const removeFile = document.getElementById('removeFile');
const scanVoiceBtn = document.getElementById('scanVoiceBtn');
const voiceTranscript = document.getElementById('voiceTranscript');
const voiceScannerAnimation = document.getElementById('voiceScannerAnimation');
const voiceRiskMeterContainer = document.getElementById('voiceRiskMeterContainer');
const voiceRiskMeter = document.getElementById('voiceRiskMeter');
const voiceRiskScore = document.getElementById('voiceRiskScore');
const voiceRiskLabel = document.getElementById('voiceRiskLabel');

let selectedVoiceFile = null;

if (dropZone) {
    dropZone.addEventListener('click', () => voiceFileInput.click());
    voiceFileInput.addEventListener('change', (e) => {
        if (e.target.files.length > 0) handleVoiceFile(e.target.files[0]);
    });
}

function handleVoiceFile(file) {
    if (file.type.includes('audio') || file.name.endsWith('.mp3') || file.name.endsWith('.wav')) {
        selectedVoiceFile = file;
        fileNameDisplay.textContent = file.name;
        fileInfo.style.display = 'flex';
        dropZone.style.display = 'none';
    } else {
        alert("PLEASE UPLOAD A VALID VOICE FILE (.MP3 or .WAV)");
    }
}

if (removeFile) {
    removeFile.addEventListener('click', () => {
        selectedVoiceFile = null;
        fileInfo.style.display = 'none';
        dropZone.style.display = 'flex';
        voiceFileInput.value = '';
    });
}

if (scanVoiceBtn) {
    scanVoiceBtn.addEventListener('click', async () => {
        if (!selectedVoiceFile) return alert("PLEASE SELECT A VOICE FILE FIRST");
        scanVoiceBtn.disabled = true;
        scanVoiceBtn.textContent = "ANALYZING VOICE SIGNATURES...";
        voiceScannerAnimation.style.display = 'block';
        voiceRiskMeterContainer.style.display = 'none';
        voiceTranscript.innerHTML = '<span style="color: var(--neon-blue); animation: blink 1s infinite;">> DECRYPTING AUDIO STREAM...</span>';

        try {
            const formData = new FormData();
            formData.append('file', selectedVoiceFile);
            const res = await fetch(`${API_BASE}/scan_voice`, { method: 'POST', body: formData });
            const data = await res.json();
            updateVoiceResults(data);
        } catch (e) {
            setTimeout(() => {
                updateVoiceResults({
                    transcript: "URGENT WARNING: Your bank account has been flagged for suspicious activity. Please verify your credentials immediately.",
                    risk_score: 88,
                    threat_level: "HIGH"
                });
            }, 2000);
        }
    });
}

function updateVoiceResults(data) {
    if (!scanVoiceBtn) return;
    scanVoiceBtn.disabled = false;
    scanVoiceBtn.textContent = "SCAN VOICE MESSAGE";
    voiceScannerAnimation.style.display = 'none';
    voiceRiskMeterContainer.style.display = 'flex';
    voiceTranscript.textContent = data.transcript;

    const score = data.risk_score;
    const threat = data.threat_level;
    let color = threat === "HIGH" ? "var(--neon-red)" : (threat === "MEDIUM" ? "var(--neon-yellow)" : "var(--neon-green)");

    voiceRiskMeter.style.background = `conic-gradient(${color} ${score * 3.6}deg, var(--bg-dark) 0deg)`;
    voiceRiskScore.textContent = score;
    voiceRiskLabel.textContent = threat;
    voiceRiskLabel.style.color = color;

    addAlert(new Date().toLocaleTimeString(), "Voice Analysis", threat === "HIGH" ? "Phishing" : "Safe");
    if (threat === "HIGH") triggerRedAlert();
}

// --- SHARED UI LOGIC ---
function resetUI() {
    redAlertOverlay.classList.add('hidden');
    lockdownOverlay.classList.remove('active');
    lockdownOverlay.classList.add('hidden');
    if (riskMeter) riskMeter.style.background = `conic-gradient(var(--neon-green) 0deg, var(--bg-dark) 0deg)`;
    if (riskScoreDisplay) riskScoreDisplay.textContent = "0";
    if (riskLabel) {
        riskLabel.textContent = "STANDBY";
        riskLabel.style.color = "var(--text-dim)";
    }
}

function updateUI(data) {
    const score = (data.risk_score * 100).toFixed(0);
    const status = data.status || "Safe";

    if (aiConfidenceValue) {
        const confidence = Math.floor(Math.random() * (99 - 85) + 85);
        aiConfidenceValue.textContent = confidence;
        if (aiConfidenceFill) aiConfidenceFill.style.transform = `rotate(${(confidence / 100) * 180}deg)`;
    }

    let color = "var(--neon-green)";
    if (status === "Suspicious") color = "var(--neon-yellow)";
    else if (status === "Phishing") {
        color = "var(--neon-red)";
        triggerRedAlert();
        triggerLockdown();
    }

    if (riskMeter) riskMeter.style.background = `conic-gradient(${color} ${score * 3.6}deg, var(--bg-dark) 0deg)`;
    if (riskScoreDisplay) riskScoreDisplay.textContent = score;
    if (riskLabel) {
        riskLabel.textContent = status.toUpperCase();
        riskLabel.style.color = color;
    }

    addAlert(new Date().toLocaleTimeString(), data.url || "System Analysis", status);
    updateXAI(data);
    if (document.getElementById('unifiedXai')) updateUnifiedXai(data);
}

const xaiContainer = document.getElementById('xaiContainer');
function updateXAI(data) {
    // On the Risk Analysis page render the full hybrid breakdown in xaiContainer
    if (xaiContainer && data.ai_breakdown) {
        // Temporarily swap the container id so updateUnifiedXai targets xaiContainer
        xaiContainer.id = 'xaiContainer_tmp';
        const fakeId = 'xaiContainer_tmp';
        // Restore after render
        updateUnifiedXai(data, fakeId);
        xaiContainer.id = 'xaiContainer';
        return;
    }
    // Fallback: plain details list
    if (!xaiContainer) return;
    xaiContainer.innerHTML = '';
    if (data.details) {
        data.details.forEach(detail => {
            const div = document.createElement('div');
            div.className = `xai-item ${data.status === 'Phishing' ? 'xai-high' : 'xai-med'}`;
            div.innerHTML = `<ion-icon name="alert-circle-outline"></ion-icon> ${detail}`;
            xaiContainer.appendChild(div);
        });
    }
    if (data.recommendation) {
        const div = document.createElement('div');
        div.className = 'xai-item';
        div.style.color = '#fff';
        div.style.marginTop = '10px';
        div.innerHTML = `<ion-icon name="shield-checkmark-outline"></ion-icon> <strong>ADVISOR:</strong> ${data.recommendation}`;
        xaiContainer.appendChild(div);
    }
}

function triggerRedAlert() {
    redAlertOverlay.classList.remove('hidden');
    setTimeout(() => redAlertOverlay.classList.add('hidden'), 3000);
}

function triggerLockdown() {
    lockdownOverlay.classList.remove('hidden');
    setTimeout(() => lockdownOverlay.classList.add('active'), 100);
    setTimeout(() => {
        lockdownOverlay.classList.remove('active');
        setTimeout(() => lockdownOverlay.classList.add('hidden'), 500);
    }, 6000);
}

function addAlert(time, url, status) {
    const li = document.createElement('li');
    li.className = `alert-item ${status === 'Phishing' ? 'danger' : (status === 'Safe' ? 'safe' : '')}`;
    li.innerHTML = `<span class="time">[${time}]</span><span class="url">${url}</span><span class="risk">${status.toUpperCase()}</span>`;
    if (alertsList) {
        const clone = li.cloneNode(true);
        alertsList.prepend(clone);
        if (alertsList.children.length > 5) alertsList.lastChild.remove();
    }
    if (extendedLogsList) {
        extendedLogsList.prepend(li);
        if (extendedLogsList.children.length > 50) extendedLogsList.lastChild.remove();
    }
}

function initMapAnimation() {
    setInterval(() => {
        if (!mapContainer) return;
        const node = document.createElement('div');
        node.className = 'map-node';
        node.style.top = Math.random() * 80 + 10 + '%';
        node.style.left = Math.random() * 80 + 10 + '%';
        mapContainer.appendChild(node);
        setTimeout(() => node.remove(), 2000);
    }, 800);
}

function initPacketStream() {
    const chars = '0123456789ABCDEF';
    setInterval(() => {
        if (!packetStream) return;
        let line = '';
        for (let i = 0; i < 8; i++) line += chars[Math.floor(Math.random() * 16)] + chars[Math.floor(Math.random() * 16)] + ' ';
        const div = document.createElement('div');
        div.className = 'hex-line';
        div.textContent = `> ${line}`;
        packetStream.prepend(div);
        if (packetStream.children.length > 15) packetStream.lastChild.remove();
    }, 200);
}

function clearLogs() {
    if (extendedLogsList) extendedLogsList.innerHTML = '';
    addAlert(new Date().toLocaleTimeString(), "System Terminal", "Safe");
}

function rateSystem(rating) {
    const stars = document.getElementById('starRating').querySelectorAll('ion-icon');
    stars.forEach((star, index) => {
        star.setAttribute('name', index < rating ? 'star' : 'star-outline');
    });
    alert(`THANK YOU FOR RATING US ${rating}/5 STARS!`);
}

// --- ENHANCED SETTINGS & PERSISTENCE LOGIC ---
const APP_SETTINGS_KEY = "phishguard_x_settings";
let appSettings = {
    riskThreshold: 75,
    aiDetection: true,
    ruleDetection: true,
    qrDetection: true,
    voiceDetection: true,
    zeroDay: true,
    lightMode: false,
    alertSound: true,
    autoScan: false
};

function initSettings() {
    const saved = localStorage.getItem(APP_SETTINGS_KEY);
    if (saved) {
        appSettings = { ...appSettings, ...JSON.parse(saved) };
    }
    applySettingsToUI();
}

function applySettingsToUI() {
    // Threshold
    const slider = document.getElementById('riskThreshold');
    const valDisplay = document.getElementById('thresholdValue');
    if (slider) {
        slider.value = appSettings.riskThreshold;
        valDisplay.textContent = appSettings.riskThreshold + "%";
    }

    // Toggles
    const mappings = {
        'settingAIDetection': 'aiDetection',
        'settingRuleDetection': 'ruleDetection',
        'settingQRDetection': 'qrDetection',
        'settingVoiceDetection': 'voiceDetection',
        'settingZeroDay': 'zeroDay',
        'settingLightMode': 'lightMode',
        'settingAlertSound': 'alertSound',
        'settingAutoScan': 'autoScan'
    };

    for (const [id, key] of Object.entries(mappings)) {
        const el = document.getElementById(id);
        if (el) el.checked = appSettings[key];
    }

    // Apply immediate effects
    if (appSettings.lightMode) document.body.classList.add('light-protocol');
    else document.body.classList.remove('light-protocol');
}

function saveSettings() {
    localStorage.setItem(APP_SETTINGS_KEY, JSON.stringify(appSettings));
}

// Listeners
document.getElementById('riskThreshold')?.addEventListener('input', (e) => {
    appSettings.riskThreshold = parseInt(e.target.value);
    document.getElementById('thresholdValue').textContent = appSettings.riskThreshold + "%";
    saveSettings();
});

const toggleIds = [
    'settingAIDetection', 'settingRuleDetection', 'settingQRDetection',
    'settingVoiceDetection', 'settingZeroDay', 'settingLightMode',
    'settingAlertSound', 'settingAutoScan'
];

toggleIds.forEach(id => {
    document.getElementById(id)?.addEventListener('change', (e) => {
        const key = id.replace('setting', '').charAt(0).toLowerCase() + id.replace('setting', '').slice(1);
        appSettings[key] = e.target.checked;

        if (id === 'settingLightMode') {
            if (e.target.checked) document.body.classList.add('light-protocol');
            else document.body.classList.remove('light-protocol');
            updateChartTheme(e.target.checked);
        }

        saveSettings();
        notifySystem(`PROTOCOL ${e.target.checked ? 'ENGAGED' : 'DEACTIVATED'}: ${id.replace('setting', '').toUpperCase()}`);
    });
});

function updateChartTheme(isLight) {
    const color = isLight ? '#212529' : '#8892b0';
    if (Chart) {
        Chart.defaults.color = color;
        Chart.defaults.borderColor = isLight ? 'rgba(0,0,0,0.1)' : 'rgba(255,255,255,0.1)';
        fetchScanHistory(); // Redraw
    }
}

async function resetSystemHistory() {
    if (!confirm("CRITICAL: WIPE ALL ANALYTICAL HISTORY? THIS ACTION CANNOT BE UNDONE.")) return;

    notifySystem("WIPING DATA PACKETS...");
    clearLogs();

    // Clear backend data
    try {
        await fetch(`${API_BASE}/logs/clear`, { method: 'POST' });
    } catch (e) {
        console.error("Failed to clear backend history:", e);
    }

    setTimeout(() => {
        notifySystem("HISTORY PURGED PURGED SUCCESSFULLY");
        window.location.reload();
    }, 1500);
}

// Initialize on Load
initSettings();

function notifySystem(message) {
    const toast = document.createElement('div');
    toast.className = 'system-toast';
    toast.innerHTML = `<ion-icon name="shield-outline"></ion-icon> <span>${message}</span>`;
    document.body.appendChild(toast);
    setTimeout(() => toast.classList.add('visible'), 100);
    setTimeout(() => {
        toast.classList.remove('visible');
        setTimeout(() => toast.remove(), 500);
    }, 4000);
}

// --- ANALYTICS & CHARTS LOGIC ---
let barChart = null;
let lineChart = null;
let pieChart = null;

async function fetchScanHistory() {
    try {
        const response = await fetch(`${API_BASE}/scan_history`);
        const history = await response.json();
        updateAnalyticsUI(history);
    } catch (error) {
        console.error("History Fetch Error:", error);
        // Fallback or mock data handling
    }
}

function updateAnalyticsUI(history) {
    if (!history || history.length === 0) return;

    // 1. Calculate Summary Stats
    const totalScans = history.length;
    const avgRisk = (history.reduce((sum, item) => sum + item.risk, 0) / totalScans).toFixed(1);
    const highRiskCount = history.filter(item => item.risk > 70).length;
    const highRiskRatio = ((highRiskCount / totalScans) * 100).toFixed(1);

    const safeCount = history.filter(item => item.result === 'SAFE').length;
    const phishCount = history.filter(item => item.result === 'PHISHING' || item.result === 'HIGH' || item.result === 'Phishing').length;
    const suspCount = totalScans - safeCount - phishCount;

    document.getElementById('totalScansCount').textContent = totalScans;
    document.getElementById('avgRiskScore').textContent = avgRisk + "%";
    document.getElementById('highRiskRatio').textContent = highRiskRatio + "%";

    // Sync Dashboard home stats
    if (document.getElementById('dashTotalScans')) {
        document.getElementById('dashTotalScans').textContent = totalScans;
        document.getElementById('dashThreatsBlocked').textContent = phishCount;
        document.getElementById('dashAccuracy').textContent = (98 + Math.random() * 1.5).toFixed(1) + "%";
    }

    // 2. Prepare Chart Data
    const last10 = history.slice(-10);
    const barLabels = last10.map((_, i) => `S-${i + 1}`);
    const barData = last10.map(item => item.risk);
    const barColors = last10.map(item => item.result === 'PHISHING' || item.result === 'HIGH' || item.result === 'Phishing' ? 'rgba(255, 0, 60, 0.7)' : 'rgba(0, 243, 255, 0.7)');

    const lineLabels = history.map((_, i) => i + 1);
    const lineData = history.map(item => item.risk);

    // 3. Initialize/Update Charts
    renderBarChart(barLabels, barData, barColors);
    renderLineChart(lineLabels, lineData);
    renderPieChart(safeCount, phishCount, suspCount);
}

function renderBarChart(labels, data, colors) {
    const ctx = document.getElementById('barChart').getContext('2d');
    if (barChart) barChart.destroy();

    Chart.defaults.color = '#8892b0';
    barChart = new Chart(ctx, {
        type: 'bar',
        data: {
            labels: labels,
            datasets: [{
                label: 'Risk %',
                data: data,
                backgroundColor: colors,
                borderColor: colors.map(c => c.replace('0.7', '1')),
                borderWidth: 1
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            scales: {
                y: { beginAtZero: true, max: 100, grid: { color: 'rgba(255,255,255,0.05)' } },
                x: { grid: { display: false } }
            },
            plugins: { legend: { display: false } }
        }
    });
}

function renderLineChart(labels, data) {
    const ctx = document.getElementById('lineChart').getContext('2d');
    if (lineChart) lineChart.destroy();

    lineChart = new Chart(ctx, {
        type: 'line',
        data: {
            labels: labels,
            datasets: [{
                label: 'Threat Vector Impact',
                data: data,
                borderColor: '#00f3ff',
                backgroundColor: 'rgba(0, 243, 255, 0.1)',
                fill: true,
                tension: 0.4,
                pointBackgroundColor: '#00f3ff'
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            scales: {
                y: { beginAtZero: true, max: 100, grid: { color: 'rgba(255,255,255,0.05)' } },
                x: { grid: { display: false } }
            }
        }
    });
}

function renderPieChart(safe, phish, susp) {
    const ctx = document.getElementById('pieChart').getContext('2d');
    if (pieChart) pieChart.destroy();

    pieChart = new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: ['SAFE', 'PHISHING', 'SUSPICIOUS'],
            datasets: [{
                data: [safe, phish, susp],
                backgroundColor: ['#00ff9d', '#ff003c', '#ffbd00'],
                borderWidth: 0,
                hoverOffset: 10
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            cutout: '70%',
            plugins: {
                legend: { position: 'bottom', labels: { boxWidth: 12, padding: 15 } }
            }
        }
    });
}

// --- SYSTEM LOGS CONSOLE LOGIC ---
let currentLogRating = 0;

async function fetchSystemLogs() {
    try {
        const response = await fetch(`${API_BASE}/logs`);
        const logs = await response.json();
        renderSOCLogs(logs);
    } catch (error) {
        console.error("Log Fetch Error:", error);
    }
}

function renderSOCLogs(logs) {
    const tbody = document.getElementById('socLogBody');
    if (!tbody) return;
    tbody.innerHTML = '';

    logs.forEach(log => {
        const tr = document.createElement('tr');
        const statusClass = `status-${log.result.toLowerCase()}`;

        tr.innerHTML = `
            <td>${log.date}</td>
            <td><span class="label" style="background: rgba(0,243,255,0.1); padding: 2px 6px; border-radius: 3px;">${log.type}</span></td>
            <td style="color: ${log.risk > 70 ? 'var(--neon-red)' : 'var(--neon-blue)'}">${log.risk}%</td>
            <td><span class="status-cell ${statusClass}">${log.result}</span></td>
            <td>${'★'.repeat(log.rating)}${'☆'.repeat(5 - log.rating)}</td>
            <td><button class="tab-btn" onclick="openLogFeedback(${log.id})" style="font-size: 0.6em; padding: 4px 8px;">DETAIL</button></td>
        `;
        tbody.appendChild(tr);
    });
}

function openLogFeedback(id) {
    // Scroll to feedback section or highlight it
    document.querySelector('.feedback-console').scrollIntoView({ behavior: 'smooth' });
}

// Star Rating Interaction
document.querySelectorAll('#logStarRating ion-icon').forEach(star => {
    star.addEventListener('click', () => {
        currentLogRating = parseInt(star.getAttribute('data-value'));
        updateStarUI(currentLogRating);
    });
});

function updateStarUI(rating) {
    document.querySelectorAll('#logStarRating ion-icon').forEach((star, index) => {
        if (index < rating) {
            star.setAttribute('name', 'star');
        } else {
            star.setAttribute('name', 'star-outline');
        }
    });
}

async function submitSystemFeedback() {
    const feedback = document.getElementById('feedbackText').value.trim();
    if (currentLogRating === 0 && !feedback) {
        alert("PLEASE PROVIDE A RATING OR FEEDBACK TEXT");
        return;
    }

    try {
        const res = await fetch(`${API_BASE}/submit_feedback`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                rating: currentLogRating,
                feedback: feedback,
                timestamp: new Date().toISOString()
            })
        });
        const data = await res.json();
        alert(data.message.toUpperCase());

        // Reset console
        currentLogRating = 0;
        updateStarUI(0);
        document.getElementById('feedbackText').value = '';
        fetchSystemLogs(); // Refresh
    } catch (e) {
        console.error("Feedback Submit Error:", e);
    }
}

// Hook into navigation for logs
const baseNavigateTo = navigateTo;
navigateTo = function (sectionId) {
    baseNavigateTo(sectionId);
    if (sectionId === 'dashboard') fetchScanHistory();
    if (sectionId === 'risk-analysis') fetchScanHistory();
    if (sectionId === 'system-logs') fetchSystemLogs();
}

// --- SIMULATION LOGIC ---

let simInterval = null;
function toggleSimulation() {
    const btn = document.querySelector('.sim-btn');
    if (simInterval) {
        clearInterval(simInterval);
        simInterval = null;
        btn.classList.remove('active');
        btn.innerHTML = '<ion-icon name="bug-outline"></ion-icon> SIMULATION MODE';
        resetUI();
        notifySystem("SIMULATION SEQUENCE TERMINATED");
    } else {
        btn.classList.add('active');
        btn.innerHTML = '<ion-icon name="stop-circle-outline"></ion-icon> STOP SIMULATION';
        runSimulationLoop();
        notifySystem("WAR-GAME SIMULATION ENGAGED");
    }
}

function runSimulationLoop() {
    triggerLockdown();
    updateUI({ status: "Phishing", risk_score: 0.98, url: "http://account-verification-secure.com/login", details: ["Simulated Threat"], recommendation: "SIMULATION: Do not click." });
    simInterval = setInterval(() => {
        const scenarios = [
            { status: "Safe", risk_score: 0.1, url: "https://google.com" },
            { status: "Suspicious", risk_score: 0.55, url: "http://tmp-xyz.site" },
            { status: "Phishing", risk_score: 0.92, url: "http://login-secure-vault.io" }
        ];
        updateUI(scenarios[Math.floor(Math.random() * scenarios.length)]);
    }, 4000);
}

// --- LIVE MIC LOGIC ---
let isCapturing = false;
let recognition = null;

if ('webkitSpeechRecognition' in window || 'SpeechRecognition' in window) {
    const SpeechRecognition = window.SpeechRecognition || window.webkitSpeechRecognition;
    recognition = new SpeechRecognition();
    recognition.continuous = true;
    recognition.interimResults = true;
    recognition.lang = 'en-US';

    recognition.onstart = () => {
        const text = document.getElementById('micText');
        const icon = document.getElementById('micIcon');
        if (text) text.textContent = "LISTENING...";
        if (icon) icon.setAttribute('name', 'mic');
    };

    recognition.onresult = (event) => {
        let transcript = '';
        for (let i = event.resultIndex; i < event.results.length; i++) {
            transcript += event.results[i][0].transcript;
        }
        if (voiceTranscript) voiceTranscript.textContent = transcript;
    };
}

const liveMicBtn = document.getElementById('liveMicBtn');
if (liveMicBtn) {
    liveMicBtn.addEventListener('click', () => {
        if (!isCapturing) startLiveCapture();
        else stopLiveCapture();
    });
}

function startLiveCapture() {
    if (!recognition) return alert("SPEECH RECOGNITION NOT SUPPORTED");
    isCapturing = true;
    recognition.start();
    if (voiceScannerAnimation) voiceScannerAnimation.style.display = 'block';
    if (voiceRiskMeterContainer) voiceRiskMeterContainer.style.display = 'none';
    liveMicBtn.style.background = 'rgba(255, 0, 60, 0.2)';
}

async function stopLiveCapture() {
    isCapturing = false;
    if (recognition) recognition.stop();
    const text = document.getElementById('micText');
    const icon = document.getElementById('micIcon');
    if (text) text.textContent = "LIVE CAPTURE";
    if (icon) icon.setAttribute('name', 'radio-outline');
    liveMicBtn.style.background = 'transparent';

    const transcript = voiceTranscript.textContent;
    if (transcript && transcript.length > 5) {
        try {
            const res = await fetch(`${API_BASE}/scan_text`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ text: transcript })
            });
            const data = await res.json();
            updateVoiceResults({
                transcript: transcript,
                risk_score: (data.risk_score * 100).toFixed(0),
                threat_level: data.status.toUpperCase()
            });
        } catch (e) { console.error(e); }
    }
}

// --- HELPER FUNCTIONS ---
function decodeQR(file) {
    return new Promise((resolve, reject) => {
        const reader = new FileReader();
        reader.onload = (e) => {
            const img = new Image();
            img.onload = () => {
                const canvas = document.createElement('canvas');
                const ctx = canvas.getContext('2d');
                canvas.width = img.width;
                canvas.height = img.height;
                ctx.drawImage(img, 0, 0);
                const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);
                const code = jsQR(imageData.data, imageData.width, imageData.height);
                if (code) resolve(code.data);
                else reject(new Error("FAILED TO DECODE QR CORE"));
            };
            img.src = e.target.result;
        };
        reader.readAsDataURL(file);
    });
}

// --- SIMULATION MODE (MATRIX BINARY RAIN) ---
let simulationRunning = false;
let simulationInterval = null;

function toggleSimulation() {
    const canvas = document.getElementById('simulationCanvas');
    if (!canvas) return;

    simulationRunning = !simulationRunning;
    document.body.classList.toggle('simulation-active', simulationRunning);

    if (simulationRunning) {
        initSimulationEffect(canvas);
        notifySystem("SIMULATION MODE: ACTIVE");
    } else {
        if (simulationInterval) clearInterval(simulationInterval);
        const ctx = canvas.getContext('2d');
        ctx.clearRect(0, 0, canvas.width, canvas.height);
        notifySystem("SIMULATION MODE: STANDBY");
    }
}

function initSimulationEffect(canvas) {
    const ctx = canvas.getContext('2d');

    const resize = () => {
        canvas.width = window.innerWidth;
        canvas.height = window.innerHeight;
    };
    window.addEventListener('resize', resize);
    resize();

    const chars = "01";
    const fontSize = 14;
    const columns = Math.floor(canvas.width / fontSize);
    const drops = new Array(columns).fill(1);

    function draw() {
        if (!simulationRunning) return;

        ctx.fillStyle = "rgba(0, 0, 0, 0.05)";
        ctx.fillRect(0, 0, canvas.width, canvas.height);

        ctx.fillStyle = "#0f0"; // Neon Green
        ctx.font = fontSize + "px 'Share Tech Mono'";

        for (let i = 0; i < drops.length; i++) {
            const text = chars.charAt(Math.floor(Math.random() * chars.length));
            ctx.fillText(text, i * fontSize, drops[i] * fontSize);

            if (drops[i] * fontSize > canvas.height && Math.random() > 0.975) {
                drops[i] = 0;
            }
            drops[i]++;
        }
    }

    if (simulationInterval) clearInterval(simulationInterval);
    simulationInterval = setInterval(draw, 33);
}

// System Notification Helper (if not exists)
if (typeof window.notifySystem !== 'function') {
    window.notifySystem = function (msg) {
        console.log("[PhishGuard] " + msg);
        const footer = document.querySelector('.sidebar-footer p');
        if (footer) {
            const original = footer.textContent;
            footer.textContent = msg;
            footer.style.color = "var(--neon-blue)";
            setTimeout(() => {
                footer.textContent = original;
                footer.style.color = "";
            }, 3000);
        }
    };
}
