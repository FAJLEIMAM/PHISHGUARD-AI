import io
from typing import Optional

from fastapi import APIRouter, File, HTTPException, UploadFile  # type: ignore
from pydantic import BaseModel  # type: ignore

from .. import database as db  # type: ignore
from ..core.detector import PhishingDetector  # type: ignore
from ..core.retrainer import ModelRetrainer  # type: ignore

# Attempt to import optional libraries
try:
    from PIL import Image  # type: ignore
    from pyzbar.pyzbar import decode  # type: ignore

    HAS_QR = True
except ImportError:
    HAS_QR = False

try:
    import speech_recognition as sr  # type: ignore

    HAS_SPEECH = True
except ImportError:
    HAS_SPEECH = False

router = APIRouter()
detector = PhishingDetector()
retrainer = ModelRetrainer(detector.ai_models)


class URLRequest(BaseModel):
    url: str


class TextRequest(BaseModel):
    text: str


class FeedbackSubmission(BaseModel):
    rating: int
    feedback: str
    timestamp: Optional[str] = None


# --- SCANNING ENDPOINTS ---


@router.post("/scan_url")
@router.post("/scan/url")  # Support both
def scan_url(request: URLRequest):
    if not request.url:
        raise HTTPException(status_code=400, detail="URL is required")

    result = detector.scan_url(request.url)

    # Log to database
    db.log_scan("URL", request.url, result["risk_score"] * 100, result["status"])

    return result


@router.post("/scan_text")
@router.post("/scan/text")  # Support both
def scan_text(request: TextRequest):
    if not request.text:
        raise HTTPException(status_code=400, detail="Text is required")

    result = detector.scan_text(request.text)

    # Log to database
    db.log_scan(
        "TEXT",
        request.text[:50] + "...",  # type: ignore
        float(result["risk_score"]) * 100,  # type: ignore
        result["status"],  # type: ignore
    )

    return result


@router.post("/scan_voice")
async def scan_voice(file: UploadFile = File(...)):
    """
    Analyzes a voice file for phishing content.
    Uses SpeechRecognition if available, otherwise uses a representative mock.
    """
    content = await file.read()
    transcript = ""

    if HAS_SPEECH:
        try:
            r = sr.Recognizer()
            with sr.AudioFile(io.BytesIO(content)) as source:
                audio = r.record(source)
                transcript = r.recognize_google(audio)
        except Exception as e:
            transcript = f"SCAN_ERROR: Could not transcribe audio. ({str(e)})"
    else:
        # High-fidelity mock for demo purposes if library missing
        transcript = (
            "URGENT NOTICE: Suspicious activity detected on your "
            "primary credit card. Unauthorized transaction of "
            "$1,240.50 at 'International Tech Store' is pending. "
            "To cancel this and secure your account, please call "
            "our automated support line at 800-555-0199 immediately."
        )

    # --- PART 2: Harmful Threat Detection (Unified Logic) ---
    # 1. Clean transcript: lowercase and remove extra spaces
    cleaned_transcript = " ".join(transcript.lower().split())

    # 2. Threat Keywords
    threat_keywords = [
        "hack",
        "attack",
        "breach",
        "exploit",
        "destroy",
        "shutdown",
        "virus",
        "malware",
        "ransomware",
        "steal",
        "compromise",
        "ddos",
    ]

    # 3. Threat Phrases
    threat_phrases = [
        "i will hack",
        "i will attack",
        "i will destroy",
        "i will breach",
        "i will shut down",
        "i will steal",
    ]

    # 4. Logic Rules
    detected_phrases = [p for p in threat_phrases if p in cleaned_transcript]
    detected_keywords = [k for k in threat_keywords if k in cleaned_transcript]

    final_risk_score = 0
    threat_level = "SAFE"
    reason = "No harmful intent detected"

    if detected_phrases:
        # If any full threat phrase is detected: risk_score = 90+, threat_level = "CRITICAL THREAT"
        final_risk_score = 95
        threat_level = "CRITICAL THREAT"
        reason = "Threatening intent detected in voice input"
    elif detected_keywords:
        # Else if any threat keyword is detected: risk_score = 70+, threat_level = "HARMFUL"
        final_risk_score = 70
        # If multiple keywords detected: Add +10 risk per extra keyword.
        if len(detected_keywords) > 1:
            final_risk_score += (len(detected_keywords) - 1) * 10

        final_risk_score = min(final_risk_score, 99)
        threat_level = "HARMFUL"
        reason = "Threatening intent detected in voice input"

    # Log to database
    db.log_scan(
        "VOICE",
        transcript[:50] + "...",  # type: ignore
        float(final_risk_score),
        threat_level,
    )

    return {
        "transcript": transcript,
        "risk_score": final_risk_score,
        "threat_level": threat_level,
        "reason": reason,
        "details": [f"Detected: {', '.join(detected_phrases + detected_keywords)}"]
        if (detected_phrases or detected_keywords)
        else ["No harmful intent detected"],
    }


@router.post("/scan_qr")
async def scan_qr(file: UploadFile = File(...)):
    """
    Decodes QR code image and runs decoded URL through the full
    hybrid phishing detection pipeline (rule engine + ML model).
    Returns identical structure to /scan_url for frontend consistency.
    """
    content = await file.read()
    decoded_url = ""

    if HAS_QR:
        try:
            img = Image.open(io.BytesIO(content))
            decoded_objects = decode(img)
            if decoded_objects:
                decoded_url = decoded_objects[0].data.decode("utf-8")
            else:
                raise Exception("No QR code found in image.")
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"QR Decode Error: {str(e)}")
    else:
        # Demo fallback: uses canonical suspicious URL for testing the pipeline
        decoded_url = "https://secure-login-verify.net/auth-update"

    # Route through the full hybrid pipeline (same as URL scanner)
    result = detector.scan_qr_url(decoded_url)

    # Log to database
    db.log_scan(
        "QR",
        decoded_url[:100],
        result["risk_score"] * 100,
        result["status"],
    )

    return {
        "decoded_url": decoded_url,
        "status": result["status"],
        "risk_score": result["risk_score"],
        "details": result.get("details", []),
        "explanation": result.get("explanation", []),
        "ai_breakdown": result.get("ai_breakdown", {}),
        "recommendation": result.get("recommendation", ""),
    }


# --- DATA & LOGS ---


@router.get("/scan_history")
def get_scan_history():
    """
    Returns a history of recent scans for analytics.
    """
    return db.get_scan_history()


@router.get("/logs")
def get_logs():
    """
    Returns complete scan logs for the SOC console.
    """
    return db.get_all_logs()


@router.post("/submit_feedback")
def submit_feedback_handler(data: FeedbackSubmission):
    """
    Handles user rating and feedback submission.
    """
    # In this implementation, we associate feedback with the LATEST scan for simplicity,
    # or the frontend should ideally pass the scan_id.
    # For now, we'll fetch the last scan id.
    history = db.get_scan_history(limit=1)
    if not history:
        raise HTTPException(
            status_code=400, detail="No scan history found to attach feedback."
        )

    scan_id = history[0]["id"]
    db.log_feedback(scan_id, data.rating, data.feedback)

    return {"status": "success", "message": "Feedback recorded in system database."}


@router.post("/retrain")
def manual_retrain():
    retrainer.retrain()
    return {"message": "Retraining triggered manually.", "status": "success"}


@router.post("/logs/clear")
def clear_all_history():
    """
    Wipes all scan and feedback history from the system.
    """
    db.clear_history()
    return {"status": "success", "message": "System history purged successfully."}


@router.get("/")
def home():
    return {"message": "PhishGuard AI X API is online and synchronized."}
