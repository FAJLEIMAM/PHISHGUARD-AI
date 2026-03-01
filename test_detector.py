import io
import sys

from backend.core.detector import PhishingDetector

# Force UTF-8
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8")

detector = PhishingDetector()
urls = [
    "https://google.com",
    "secure-login-verify.net/auth-update",
]

for url in urls:
    print(f"\nSCANNING: {url}")
    res = detector.scan_url(url)
    print(f"STATUS: {res['status']} | SCORE: {res['risk_score']}")
    print(f"DETAILS: {res['details']}")
    print(f"EXPLANATION: {res['explanation']}")
