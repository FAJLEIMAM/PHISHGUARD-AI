import json
import urllib.request

req = urllib.request.Request(
    "http://localhost:8000/scan_url",
    data=json.dumps({"url": "https://secure-login-verify.net/auth-update"}).encode(),
    headers={"Content-Type": "application/json"},
    method="POST",
)
with urllib.request.urlopen(req) as r:
    data = json.loads(r.read())

bd = data.get("ai_breakdown", {})
print("=== API RESPONSE FIELD CHECK ===")
print(f"  status            : {data['status']}")
print(f"  risk_score        : {data['risk_score']}")
print(f"  rule_score        : {bd.get('rule_score')}")
print(f"  ml_score          : {bd.get('ml_score')}")
print(f"  ml_confidence     : {bd.get('ml_confidence')}")
print(f"  final_weighted    : {bd.get('final_weighted_score')}")
print(f"  blacklisted       : {bd.get('blacklisted')}")
print(f"  rule_override_appl: {bd.get('rule_override_applied')}")
print(f"  anomaly_detected  : {bd.get('anomaly_detected')}")
print(f"  keywords_found    : {bd.get('keywords_found')}")
dom = bd.get("domain_flags", [])
print(f"  domain_flags      : {len(dom)} flag(s) -> {dom[:2]}")
exp = data.get("explanation", [])
print(f"  explanation       : {len(exp)} item(s)")
print(f"  recommendation    : {str(data.get('recommendation', ''))[:60]}...")

# Also check a non-blacklisted URL
req2 = urllib.request.Request(
    "http://localhost:8000/scan_url",
    data=json.dumps({"url": "https://secure-verify-mybank.net/auth-update"}).encode(),
    headers={"Content-Type": "application/json"},
    method="POST",
)
with urllib.request.urlopen(req2) as r2:
    data2 = json.loads(r2.read())
bd2 = data2.get("ai_breakdown", {})
print()
print("=== NON-BLACKLISTED PHISHING URL ===")
print(f"  status            : {data2['status']}")
print(f"  rule_override_appl: {bd2.get('rule_override_applied')}")
print(f"  keywords_found    : {bd2.get('keywords_found')}")
print(f"  domain_flags count: {len(bd2.get('domain_flags', []))}")
