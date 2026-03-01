// DOM Elements
const urlInput = document.getElementById('urlInput');
const textInput = document.getElementById('textInput');
const scanBtn = document.getElementById('scanBtn');
// ... other elements ...

const API_BASE = "http://localhost:8000";

// Tabs
function switchTab(mode) {
    document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
    document.querySelectorAll('.scanner-interface').forEach(i => i.classList.add('hidden'));
    
    // Find button with specific text or onclick (simplified for now)
    const buttons = document.querySelectorAll('.tab-btn');
    if(mode === 'url') buttons[0].classList.add('active');
    if(mode === 'text') buttons[1].classList.add('active');
    if(mode === 'voice') buttons[2].classList.add('active');

    document.getElementById(`tab-${mode}`).classList.remove('hidden');
    document.getElementById(`tab-${mode}`).classList.add('active');
}

// URL Scan
async function initiateScan() {
    const url = urlInput.value.trim();
    if (!url) return alert("ENTER URL");
    
    updateStatus("SCANNING URL...", true);
    try {
        const res = await fetch(`${API_BASE}/scan/url`, {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({url})
        });
        const data = await res.json();
        renderResults(data);
    } catch (e) {
        console.error(e);
        updateStatus("CONNECTION ERROR", false);
    }
}

// Text Scan
async function initiateTextScan() {
    const text = textInput.value.trim();
    if (!text) return alert("ENTER TEXT");
    
    document.getElementById('textStatus').textContent = "ANALYZING TEXT...";
    try {
        const res = await fetch(`${API_BASE}/scan/text`, {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({text})
        });
        const data = await res.json();
        renderResults(data); // Re-use render logic? Needs adaptation.
        document.getElementById('textStatus').textContent = `RESULT: ${data.status} (${(data.risk_score*100).toFixed(0)}%)`;
    } catch (e) {
        document.getElementById('textStatus').textContent = "ERROR";
    }
}

// Voice Logic
let isRecording = false;
let recognition = null;

if ('webkitSpeechRecognition' in window) {
    recognition = new webkitSpeechRecognition();
    recognition.continuous = false;
    recognition.lang = 'en-US';
    
    recognition.onresult = function(event) {
        const transcript = event.results[0][0].transcript;
        document.getElementById('voiceStatus').textContent = `Heard: "${transcript}"`;
        // Send to text analyze
        textInput.value = transcript;
        switchTab('text');
        initiateTextScan();
    };
    
    recognition.onerror = function(event) {
        document.getElementById('voiceStatus').textContent = "Error recognition";
        toggleVoiceRecording();
    };
    
    recognition.onend = function() {
        if (isRecording) toggleVoiceRecording();
    };
}

function toggleVoiceRecording() {
    if (!recognition) return alert("Browser not supported");
    
    const viz = document.getElementById('voiceVisualizer');
    const btn = document.getElementById('recordBtn');
    
    if (!isRecording) {
        recognition.start();
        isRecording = true;
        viz.parentElement.classList.add('recording');
        btn.innerHTML = '<ion-icon name="stop-outline"></ion-icon> STOP LISTENING';
        document.getElementById('voiceStatus').textContent = "LISTENING...";
    } else {
        recognition.stop();
        isRecording = false;
        viz.parentElement.classList.remove('recording');
        btn.innerHTML = '<ion-icon name="mic-outline"></ion-icon> START LISTENING';
    }
}

function updateStatus(msg, isScanning) {
    // ... update UI ...
}

function renderResults(data) {
    // ... Update Risk Meter, Logs, Maps ...
    document.getElementById('riskScore').textContent = (data.risk_score * 100).toFixed(0);
    // ...
}

// ... Init ...
