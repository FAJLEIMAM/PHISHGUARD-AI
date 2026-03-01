import io
import sys

import requests  # type: ignore

# Fix encoding for Windows terminals
if sys.platform == "win32":
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8")

API_BASE = "http://localhost:8000"


def test_url(url):
    print(f"\n--- Testing URL Mode: {url} ---")
    try:
        res = requests.post(f"{API_BASE}/scan_url", json={"url": url})
        data = res.json()
        print(f"Status: {data['status']} ({data['risk_score'] * 100:.1f}%)")
        return data
    except Exception as e:
        print(f"URL Error: {e}")
        return None


def test_text(text):
    print(f"\n--- Testing Text Mode: {text[:50]}... ---")
    try:
        res = requests.post(f"{API_BASE}/scan_text", json={"text": text})
        data = res.json()
        print(f"Status: {data['status']} ({data['risk_score'] * 100:.1f}%)")
        return data
    except Exception as e:
        print(f"Text Error: {e}")
        return None


if __name__ == "__main__":
    target_url = "http://www.garage-pirene.be/index.php?option=com_content&view=article&id=70&vsig70_0=15"
    raw_domain = "signin.eby.de.zukruygxctzmmqi.civpro.co.za"

    # Test case 1: Standard URL
    url_data1 = test_url(target_url)
    text_data1 = test_text(f"Check this link: {target_url}")

    # Test case 2: Raw Domain (from user screenshot)
    url_data2 = test_url(raw_domain)
    text_data2 = test_text(raw_domain)

    print("\n=== FINAL VALIDATION ===")

    def check_match(d1, d2):
        if not d1 or not d2:
            return False
        return d1["status"] == d2["status"]

    match1 = check_match(url_data1, text_data1)
    match2 = check_match(url_data2, text_data2)

    if match1 and match2:
        print("\n✅ SUCCESS: All parity tests passed!")
    else:
        print("\n❌ FAILURE: Inconsistency detected!")
        if not match1:
            print(">> Failed on target_url consistency")
        if not match2:
            print(">> Failed on raw_domain consistency")
