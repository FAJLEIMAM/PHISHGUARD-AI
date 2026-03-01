import re
from urllib.parse import urlparse


class FeatureExtractor:
    def __init__(self):
        pass

    def extract_features(self, url):
        """Extracts 13 features from a URL string."""
        url_lower = url.lower().strip()
        parsed = urlparse(url_lower)
        hostname = parsed.netloc
        path = parsed.path
        query = parsed.query
        features = []

        # 1. URL Length
        features.append(len(url_lower))

        # 2. Hostname Length
        features.append(len(hostname))

        # 3. Has IP Address in URL
        features.append(1 if self.has_ip_address(url_lower) else 0)

        # 4. Count of '@'
        features.append(url_lower.count("@"))

        # 5. Count of '//' (redirects) - checking after protocol
        features.append(url_lower.count("//") - 1 if url_lower.count("//") > 0 else 0)

        # 6. Count of '.'
        features.append(url_lower.count("."))

        # 7. Count of '-' (often used in phishing domains)
        features.append(url_lower.count("-"))

        # 8. Count of numeric characters in URL
        features.append(sum(c.isdigit() for c in url_lower))

        # 9. HTTPS in URL (Binary)
        features.append(1 if url_lower.startswith("https") else 0)

        # 10. Subdomain Count (Dots in hostname)
        features.append(hostname.count("."))

        # 11. Phishing Word Count (Keywords in path/query)
        phish_keywords = [
            "login",
            "verify",
            "secure",
            "update",
            "account",
            "auth",
            "bank",
        ]
        kw_count = sum(1 for kw in phish_keywords if kw in path or kw in query)
        features.append(kw_count)

        # 12. TLD Risk (High-risk TLDs)
        high_risk_tlds = [
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
        ]
        tld_risk = 1 if any(hostname.endswith(tld) for tld in high_risk_tlds) else 0
        features.append(tld_risk)

        # 13. Query Parameter Count
        # Count non-empty segments in query string split by & or =
        param_count = len([p for p in re.split(r"[&=]", query) if p])
        features.append(param_count)

        return features

    def has_ip_address(self, url):
        # Regex for IPv4 address
        ip_pattern = (
            r"(([01]?\d\d?|2[0-4]\d|25[0-5])\."
            r"([01]?\d\d?|2[0-4]\d|25[0-5])\."
            r"([01]?\d\d?|2[0-4]\d|25[0-5])\."
            r"([01]?\d\d?|2[0-4]\d|25[0-5])(\/|$))"
        )
        match = re.search(ip_pattern, url)
        return bool(match)
