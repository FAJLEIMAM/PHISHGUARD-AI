import io
import os
import sys

# Fix encoding for Windows terminals
if sys.platform == "win32":
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8")

# Add the project root to sys.path
sys.path.append(os.getcwd())

from backend.core.detector import PhishingDetector

detector = PhishingDetector()

test_url = "http://www.garage-pirene.be/index.php?option=com_content&view=article&id=70&vsig70_0=15"
test_text = f"please go through this link {test_url}"

print("=== TESTING URL SCANNER ===")
url_result = detector.scan_url(test_url)
print(f"Status: {url_result['status']}")
print(f"Risk Score: {url_result['risk_score']}")
if "ai_breakdown" in url_result:
    print(f"AI Breakdown: {url_result['ai_breakdown']}")

print("\n=== TESTING TEXT SCANNER ===")
text_result = detector.scan_text(test_text)
print(f"Status: {text_result['status']}")
print(f"Risk Score: {text_result['risk_score']}")
if "ai_breakdown" in text_result:
    print(f"AI Breakdown: {text_result['ai_breakdown']}")
else:
    print("AI Breakdown missing in text result!")
