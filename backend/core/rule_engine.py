"""
Rule-Based Intelligence Engine for PhishGuard AI X.

Provides deterministic, interpretable scoring based on URL heuristics.
Works ALONGSIDE the ML model in a hybrid weighted combination.

Scoring outputs a 0.0-1.0 risk score with detailed breakdown.
"""

import re
from urllib.parse import urlparse

# ---------------------------------------------------------------------------
# Trusted second-level domain seeds — keyword scoring is suppressed for
# URLs whose registered domain seed is in this set.  This prevents
# github.com/microsoft/vscode from being penalised for the path token
# "microsoft" which is perfectly legitimate on a trusted host.
# ---------------------------------------------------------------------------
TRUSTED_DOMAIN_SEEDS = {
    "google",
    "facebook",
    "amazon",
    "wikipedia",
    "github",
    "microsoft",
    "apple",
    "linkedin",
    "twitter",
    "instagram",
    "youtube",
    "netflix",
    "zoom",
    "dropbox",
    "salesforce",
    "stackoverflow",
    "gitlab",
    "bitbucket",
    "adobe",
    "paypal",
    "bing",
    "yahoo",
    "twitch",
    "whatsapp",
}


# ---------------------------------------------------------------------------
# Detection Dictionaries
# ---------------------------------------------------------------------------

SUSPICIOUS_KEYWORDS = [
    "login",
    "verify",
    "secure",
    "update",
    "account",
    "auth",
    "reset",
    "confirm",
    "signin",
    "bank",
    "password",
    "credential",
    "validate",
    "unlock",
    "reactivate",
    "billing",
    "invoice",
    "urgent",
    "alert",
    "suspend",
    "limited",
    "expire",
    "wallet",
    "paypal",
    "amazon",
    "microsoft",
    "apple",
    "netflix",
    "ebay",
]

SUSPICIOUS_TLDS = {
    ".xyz",
    ".top",
    ".ru",
    ".tk",
    ".ml",
    ".ga",
    ".cf",
    ".gq",
    ".pw",
    ".cc",
    ".biz",
    ".info",
    ".su",
    ".click",
    ".link",
    ".online",
    ".site",
    ".space",
    ".fun",
    ".icu",
    ".live",
    ".net",  # .net alone is borderline but combined with phishing words = suspicious
}

# Domain segments that appear in phishing domains combined with hyphens
PHISHING_WORDS_IN_DOMAIN = [
    "secure",
    "login",
    "verify",
    "account",
    "update",
    "confirm",
    "auth",
    "bank",
    "signin",
    "reset",
    "service",
    "support",
    "helpdesk",
    "security",
    "validation",
    "wallet",
    "access",
    "portal",
    "alert",
    "weblogin",
    "userverify",
]

# High-risk TLDs that almost always indicate phishing when combined with suspicious words
HIGH_RISK_TLDS = {
    ".xyz",
    ".tk",
    ".ml",
    ".ga",
    ".cf",
    ".gq",
    ".top",
    ".ru",
    ".su",
    ".pw",
}

# Hard blacklist — immediate PHISHING if domain matches
HARD_BLACKLIST = {
    "secure-login-verify.net",
    "login-attempt-secure.net",
    "verify-account-update.com",
    "example-phishing.com",
    "account-verification-secure.com",
    "auth-secure-login.xyz",
    "paypal-secure-update.com",
    "amazon-account-verify.net",
    "microsoft-support-alert.com",
    "bank-secure-verify.net",
    "apple-id-login.xyz",
    "netflix-billing-update.net",
    "ebay-security-alert.net",
    "irs-refund-verify.com",
    "crypto-wallet-secure.xyz",
    # Additional entries from threat_intel.py for parity
    "login-attempt-secure.net",
    "account-verification-secure.com",
    "auth-secure-login.xyz",
    "signin-verify-account.com",
    "update-security-alert.net",
    "paypal-account-verify.net",
    "paypal-login-secure.xyz",
    "amazon-security-alert.com",
    "amazon-login-verify.xyz",
    "microsoft-account-verify.net",
    "microsoft-login-update.com",
    "apple-account-secure.net",
    "appleid-verify-account.com",
    "netflix-account-verify.com",
    "bank-account-update.xyz",
    "secure-banking-verify.com",
    "bitcoin-wallet-verify.net",
    "eth-wallet-update.com",
    "irs-tax-update.net",
    "gov-account-verify.xyz",
    "ebay-account-update.com",
}


# ---------------------------------------------------------------------------
# Main Rule Engine
# ---------------------------------------------------------------------------


class RuleEngine:
    """
    Deterministic rule-based URL risk scorer.
    Returns a structured analysis dict with score (0.0-1.0) and breakdown.
    """

    def __init__(self):
        # Expanded phishing keyword list as requested
        self.keywords = [
            "login",
            "verify",
            "update",
            "secure",
            "account",
            "bank",
            "password",
            "auth",
            "signin",
            "reset",
            "confirm",
            "httpclient",
            "client",
            "portal",
            "admin",
        ]

        # Suspicious TLDs
        self.suspicious_tlds = {
            ".xyz",
            ".top",
            ".ru",
            ".tk",
            ".ml",
            ".ga",
            ".cf",
            ".gq",
            ".pw",
            ".cc",
            ".biz",
            ".info",
            ".online",
            ".site",
            ".fun",
        }

        # Internal service exposure patterns
        self.service_patterns = ["/admin", "/auth", "/httpclient", "/api", "/backend"]

        self.blacklist = HARD_BLACKLIST
        self.trusted_seeds = TRUSTED_DOMAIN_SEEDS

    def analyze(self, url: str) -> dict:
        """
        Full rule-based analysis of a URL with advanced pattern detection.
        """
        url_lower = url.lower().strip()
        parsed = self._safe_parse(url_lower)
        domain = parsed.get("domain", "")
        port = parsed.get("port")

        print(f"[RE] ANALYZING: {url_lower}")

        flags = []
        keywords_found = []
        domain_flags = []
        suspicious_domain_flag = False
        risk_increments = []

        # 1. Blacklist Check
        if self._is_blacklisted(domain):
            return {
                "score": 1.0,
                "blacklisted": True,
                "flags": [f"⛔ Domain '{domain}' is in the hard blacklist"],
                "keywords_found": [],
                "domain_flags": ["BLACKLISTED DOMAIN"],
                "tld_flag": None,
                "suspicious_domain_flag": True,
            }

        # 2. Part 1 — Expanded Phishing Keyword Detection (Substring match)
        for kw in self.keywords:
            if kw in url_lower:
                keywords_found.append(kw)

        if keywords_found:
            kw_inc = min(len(keywords_found) * 0.20, 0.60)
            risk_increments.append(kw_inc)
            flags.append(f"🔑 Phishing Keywords Detected: {', '.join(keywords_found)}")

        # 3. Part 2 — Suspicious Domain Pattern Detection

        # 3a. Port checks
        if port:
            flags.append(f"🔌 Port number present explicitly: {port}")
            if port not in [80, 443]:
                suspicious_domain_flag = True
                risk_increments.append(0.25)
                flags.append("🚨 Suspicious Domain Patterns: Non-standard port")

            # Boost if http and port both present
            if url_lower.startswith("http://"):
                risk_increments.append(0.15)

        # 3b. Protocol check
        if url_lower.startswith("http://"):
            risk_increments.append(0.15)
            flags.append("🔓 Suspicious Domain Patterns: Insecure protocol")

        # 3c. Internal service exposure patterns
        exposed = [p for p in self.service_patterns if p in url_lower]
        if exposed:
            risk_increments.append(0.30)
            flags.append(
                f"🛠️ Suspicious Domain Patterns: Service endpoint exposure ({', '.join(exposed)})"
            )

        # 3d. Domain complexity: Multiple subdomains (>3 levels)
        if domain.count(".") >= 3:
            risk_increments.append(0.20)
            flags.append(
                "🌐 Suspicious Domain Patterns: Multiple subdomains detected (>3 levels)"
            )
            domain_flags.append("SUBDOMAIN_FLOOD")

        # 3e. Numeric-heavy domain
        digits = sum(c.isdigit() for c in domain)
        if len(domain) > 0 and (digits / len(domain)) > 0.4:
            risk_increments.append(0.25)
            flags.append("🔢 Suspicious Domain Patterns: Numeric-heavy domain name")
            domain_flags.append("NUMERIC_DOMAIN")
            suspicious_domain_flag = True

        # 3f. Random character patterns
        if len(domain) > 10:
            vowels = sum(c in "aeiou" for c in domain)
            if vowels / len(domain) < 0.15:
                risk_increments.append(0.30)
                flags.append(
                    "🎲 Suspicious Domain Patterns: Random character pattern detected"
                )
                domain_flags.append("RANDOM_PATTERN")
                suspicious_domain_flag = True

        # TLD check
        tld_flag = None
        for tld in self.suspicious_tlds:
            if domain.endswith(tld):
                tld_flag = tld
                risk_increments.append(0.20)
                flags.append(f"🚩 Suspicious TLD: {tld}")
                domain_flags.append(f"SUSPICIOUS_TLD_{tld.replace('.', '').upper()}")
                break

        # @ symbol check
        if "@" in url_lower:
            risk_increments.append(0.30)
            flags.append("⚠️ '@' symbol redirection pattern")

        # IP address check
        ip_pattern = (
            r"((?:[01]?\d\d?|2[0-4]\d|25[0-5])\.){3}(?:[01]?\d\d?|2[0-4]\d|25[0-5])"
        )
        if re.search(ip_pattern, url_lower):
            risk_increments.append(1.0)
            flags.append("🖥️ IP address used instead of domain name")
            suspicious_domain_flag = True

        # Final score calculation
        score = float(sum(risk_increments))
        score = float(f"{min(score, 1.0):.4f}")
        print(f"[RE] FINAL RULE SCORE: {score}")

        return {
            "score": score,
            "blacklisted": False,
            "flags": flags,
            "keywords_found": keywords_found,
            "domain_flags": domain_flags,
            "tld_flag": tld_flag,
            "suspicious_domain_flag": suspicious_domain_flag,
        }

    def _safe_parse(self, url: str) -> dict:
        """Safely parse URL into components using urlparse."""
        try:
            # Ensure scheme exists for urlparse
            if "://" not in url:
                check_url = "http://" + url
            else:
                check_url = url

            parsed = urlparse(check_url)
            netloc = parsed.netloc.lower()
            # Handle cases where path is interpreted as domain if scheme missing
            if not netloc and "://" not in url:
                if "/" in url:
                    parts = url.split("/", 1)
                    domain = parts[0].lower()
                    path = "/" + parts[1]
                else:
                    domain = url.lower()
                    path = ""
            else:
                # parsed.port provides the port if present, or None
                port = parsed.port
                domain = netloc.split(":")[0]  # Keep domain clean for pattern checks
                path = parsed.path

            return {
                "domain": domain,
                "path": path,
                "scheme": parsed.scheme,
                "port": port,
            }
        except Exception:
            return {"domain": url.split("/")[0], "path": "", "scheme": "", "port": None}

    def _is_blacklisted(self, domain: str) -> bool:
        """Check if domain matches the hard blacklist."""
        clean_domain = domain.replace("www.", "")
        if clean_domain in self.blacklist or domain in self.blacklist:
            return True
        for entry in self.blacklist:
            if entry == clean_domain or entry == domain:
                return True
        return False
