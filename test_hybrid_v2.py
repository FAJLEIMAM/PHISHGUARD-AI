"""
Comprehensive validation of the PhishGuard Hybrid Detection Engine.
Tests all 7 requirements from the upgrade spec.
"""

import sys

sys.path.insert(0, ".")
from backend.core.detector import PhishingDetector
from backend.core.rule_engine import RuleEngine

d = PhishingDetector()
re_engine = RuleEngine()

PASS = "PASS"
FAIL = "FAIL"


def check(label, url, expected_status, min_risk=None, max_risk=None):
    result = d.scan_url(url)
    bd = result.get("ai_breakdown", {})
    status = result["status"]
    risk = result["risk_score"] * 100

    ok = status == expected_status
    if min_risk is not None:
        ok = ok and risk >= min_risk
    if max_risk is not None:
        ok = ok and risk <= max_risk

    verdict = PASS if ok else FAIL
    print(f"\n[{verdict}] {label}")
    print(f"  URL        : {url}")
    print(f"  Status     : {status}  (expected: {expected_status})")
    print(f"  Risk Score : {risk:.1f}%", end="")
    if min_risk or max_risk:
        lo = f">={min_risk}%" if min_risk else ""
        hi = f"<={max_risk}%" if max_risk else ""
        print(f"  [{lo}{' ' if lo and hi else ''}{hi}]", end="")
    print()
    print(f"  Rule Score : {bd.get('rule_score', 'N/A')}")
    print(f"  ML Score   : {bd.get('ml_score', 'N/A')}")
    print(f"  Keywords   : {bd.get('keywords_found', [])}")
    print(f"  Dom Flags  : {len(bd.get('domain_flags', []))} flag(s)")
    print(f"  Anomaly    : {bd.get('anomaly_detected', False)}")
    print(f"  Override   : {bd.get('rule_override_applied', False)}")
    print(f"  Recommend  : {result.get('recommendation', '')[:70]}...")
    return verdict == PASS


print("\n" + "=" * 65)
print("PHISHGUARD HYBRID ENGINE - FULL VALIDATION SUITE v2")
print("=" * 65)

results = []

# ----------------------------------------------------------------
# 1. Primary goal: Canonical malicious QR URL
# ----------------------------------------------------------------
results.append(
    check(
        "REQ-7 Canonical QR phishing URL (blacklisted)",
        "https://secure-login-verify.net/auth-update",
        "Phishing",
        min_risk=75,
    )
)

# ----------------------------------------------------------------
# 2. Non-blacklisted URLs with strong heuristic signals
# ----------------------------------------------------------------
results.append(
    check(
        "REQ-1/2/3 Non-blacklisted .net bank phishing",
        "https://secure-verify-mybank.net/auth-update",
        "Phishing",
        min_risk=70,
    )
)

results.append(
    check(
        "REQ-3 High-risk .xyz domain with phishing words",
        "https://verify-login-account.xyz/signin",
        "Phishing",
        min_risk=70,
    )
)

results.append(
    check(
        "REQ-3 Apple impersonation with .net",
        "https://apple-id-verify-secure.net/reset",
        "Phishing",
        min_risk=70,
    )
)

results.append(
    check(
        "REQ-2 Chase bank impersonation",
        "https://chase-bank-secure-login.com/verify/account",
        "Phishing",
        min_risk=70,
    )
)

# ----------------------------------------------------------------
# 3. Rule override floor: strong rule + weak ML -> still PHISHING
# ----------------------------------------------------------------
results.append(
    check(
        "REQ-1 Rule override floor - securebank.net (was Suspicious, should now be Phishing)",
        "https://securebank.net/login",
        "Phishing",
        min_risk=70,
    )
)

# ----------------------------------------------------------------
# 4. Blacklist hits with rich breakdown
# ----------------------------------------------------------------
results.append(
    check(
        "REQ-4 Hard blacklist - paypal impersonation",
        "https://paypal-secure-update.com/verify",
        "Phishing",
        min_risk=90,
    )
)

results.append(
    check(
        "REQ-4 Hard blacklist - amazon impersonation",
        "https://amazon-account-verify.net/signin/auth-update",
        "Phishing",
        min_risk=90,
    )
)

# ----------------------------------------------------------------
# 5. IP-based phishing
# ----------------------------------------------------------------
results.append(
    check(
        "REQ-1 IP-address URL phishing",
        "http://192.168.1.1/login/verify-account",
        "Phishing",
        min_risk=70,
    )
)

# ----------------------------------------------------------------
# 6. Safe URLs — must NOT be false positives
# ----------------------------------------------------------------
results.append(
    check("REQ-5 Safe - google.com", "https://google.com", "Safe", max_risk=40)
)

results.append(
    check(
        "REQ-5 Safe - GitHub (microsoft in path should not inflate)",
        "https://github.com/microsoft/vscode",
        "Safe",
        max_risk=40,
    )
)

results.append(
    check("REQ-5 Safe - LinkedIn", "https://linkedin.com/in/user", "Safe", max_risk=40)
)

results.append(
    check(
        "REQ-5 Safe - Amazon.com (real)",
        "https://amazon.com/product/12345",
        "Safe",
        max_risk=40,
    )
)

# ----------------------------------------------------------------
# 7. QR pipeline tag
# ----------------------------------------------------------------
qr_result = d.scan_qr_url("https://secure-login-verify.net/auth-update")
qr_ok = qr_result.get("source") == "QR_CODE" and qr_result["status"] == "Phishing"
verdict = PASS if qr_ok else FAIL
results.append(qr_ok)
print(f"\n[{verdict}] REQ-7 QR pipeline tag + phishing verdict")
print(f"  source: {qr_result.get('source')}  status: {qr_result['status']}")

# ----------------------------------------------------------------
# Summary
# ----------------------------------------------------------------
passed = sum(results)
total = len(results)
print(f"\n{'=' * 65}")
print(f"RESULTS: {passed}/{total} tests passed")
if passed == total:
    print("ALL TESTS PASSED - Hybrid engine is working correctly!")
else:
    print(f"WARNING: {total - passed} test(s) failed - review above")
print("=" * 65)
