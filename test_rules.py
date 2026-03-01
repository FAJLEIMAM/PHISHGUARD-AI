import io
import sys

from backend.core.rule_engine import RuleEngine

# Force UTF-8 for printing emojis on Windows
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8")

re = RuleEngine()
urls = [
    "https://google.com",
    "secure-login-verify.net/auth-update",  # Blacklisted
    "http://verify-account-update.xyz/signin",  # Keywords + Hyphens + TLD + No HTTPS
    "https://signin.paypal.com.secure-update.xyz/login",  # Keywords + Pattern + TLD
    "http://192.168.1.1/login",  # Keywords + No HTTPS (Note: IP detection is in detector.py details filter, but keywords are in RE)
    "https://secure-login.amazon.xyz",  # Pattern + TLD
]

for url in urls:
    print(f"\nTESTING: {url}")
    res = re.analyze(url)
    print(f"RESULT: {res['score']} | FLAGS: {res['flags']}")
