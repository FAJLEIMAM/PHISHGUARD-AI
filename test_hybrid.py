import json
import urllib.request

BASE = "http://localhost:8001"


def test_url(label, url):
    payload = json.dumps({"url": url}).encode()
    req = urllib.request.Request(
        f"{BASE}/scan_url",
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req) as r:
        result = json.loads(r.read())
    bd = result.get("ai_breakdown", {})
    print(f"\n=== {label} ===")
    print(f"  URL         : {url}")
    print(f"  Status      : {result['status']}")
    print(f"  Risk Score  : {result['risk_score'] * 100:.1f}%")
    print(f"  Rule Score  : {bd.get('rule_score', 'N/A')}")
    print(f"  ML Score    : {bd.get('ml_score', 'N/A')}")
    print(f"  Keywords    : {bd.get('keywords_found', [])}")
    print(f"  Domain Flags: {bd.get('domain_flags', [])}")
    print(f"  TLD Flag    : {bd.get('tld_flag', 'None')}")
    print(f"  Anomaly     : {bd.get('anomaly_detected', 'N/A')}")
    print(f"  Explanation : {result.get('explanation', [])}")
    print(f"  Recommend   : {result.get('recommendation', '')}")


print("\n" + "=" * 60)
print("PHISHGUARD HYBRID ENGINE - VALIDATION TESTS")
print("=" * 60)

test_url(
    "TEST 1: Malicious QR URL (should be PHISHING >75%)",
    "https://secure-login-verify.net/auth-update",
)

test_url("TEST 2: Safe Google (should be SAFE <40%)", "https://google.com")

test_url(
    "TEST 3: Suspicious .xyz bank URL (should be PHISHING)",
    "http://login-verify-account.xyz/reset-password",
)

test_url(
    "TEST 4: Normal GitHub (should be SAFE)", "https://github.com/microsoft/vscode"
)

test_url(
    "TEST 5: IP-based phishing (should be PHISHING)",
    "http://192.168.1.1/login/verify-account",
)

test_url(
    "TEST 6: Amazon impersonation (should be PHISHING)",
    "https://amazon-account-verify.net/signin/auth-update",
)
