"""
Threat Intelligence module.
Provides hard blocklist / allowlist checks before the ML/rule pipeline runs.
Extended blocklist covers known phishing domain patterns.
"""


class ThreatIntel:
    def __init__(self):
        # Hard blocklist — immediate PHISHING verdict if domain matched
        self.blocklist = {
            # Classic phishing domains
            "example-phishing.com",
            "verify-account-update.com",
            "login-attempt-secure.net",
            # Credential harvesting
            "secure-login-verify.net",
            "account-verification-secure.com",
            "auth-secure-login.xyz",
            "signin-verify-account.com",
            "update-security-alert.net",
            # Brand impersonation - PayPal
            "paypal-secure-update.com",
            "paypal-account-verify.net",
            "paypal-login-secure.xyz",
            # Brand impersonation - Amazon
            "amazon-account-verify.net",
            "amazon-security-alert.com",
            "amazon-login-verify.xyz",
            # Brand impersonation - Microsoft
            "microsoft-support-alert.com",
            "microsoft-account-verify.net",
            "microsoft-login-update.com",
            # Brand impersonation - Apple
            "apple-id-login.xyz",
            "apple-account-secure.net",
            "appleid-verify-account.com",
            # Brand impersonation - Netflix
            "netflix-billing-update.net",
            "netflix-account-verify.com",
            # Brand impersonation - Banking
            "bank-secure-verify.net",
            "bank-account-update.xyz",
            "secure-banking-verify.com",
            # Crypto / Wallet scams
            "crypto-wallet-secure.xyz",
            "bitcoin-wallet-verify.net",
            "eth-wallet-update.com",
            # Government impersonation
            "irs-refund-verify.com",
            "irs-tax-update.net",
            "gov-account-verify.xyz",
            # Generic phishing patterns
            "ebay-security-alert.net",
            "ebay-account-update.com",
        }

        # Trusted allowlist — skips full analysis if domain matched
        self.allowlist = {
            "google.com",
            "facebook.com",
            "amazon.com",
            "amazon.co.uk",
            "wikipedia.org",
            "github.com",
            "microsoft.com",
            "apple.com",
            "linkedin.com",
            "twitter.com",
            "instagram.com",
            "youtube.com",
            "netflix.com",
            "zoom.us",
            "dropbox.com",
            "salesforce.com",
        }

    def check_url(self, url: str) -> int:
        """
        Checks if the URL domain is in the blocklist or allowlist.
        Returns:
            -1  → Phishing (blocklist match)
             1  → Safe (allowlist match)
             0  → Unknown — continue to hybrid analysis
        """
        try:
            import tldextract

            extracted = tldextract.extract(url)
            domain = f"{extracted.domain}.{extracted.suffix}".lower()
            subdomain = extracted.subdomain.lower()
            full_registered = f"{subdomain}.{domain}" if subdomain else domain

            # Check hard blocklist (both registered and full domain)
            if domain in self.blocklist or full_registered in self.blocklist:
                return -1

            # Also check substring match for blocklist entries
            for entry in self.blocklist:
                if entry in url.lower():
                    return -1

            # Check allowlist
            if domain in self.allowlist:
                return 1

            return 0
        except Exception as e:
            print(f"[ThreatIntel] Error: {e}")
            return 0
