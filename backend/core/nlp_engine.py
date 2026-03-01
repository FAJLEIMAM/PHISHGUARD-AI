from typing import Any, Dict


class NLPEngine:
    def __init__(self) -> None:
        # Placeholder for actual NLP model (TF-IDF / BERT)
        pass

    def analyze_text(self, text: str) -> Dict[str, Any]:
        """
        Analyzes text for phishing attempts.
        Returns: risk_score, status, keywords
        """
        keywords = ["urgent", "verify", "password", "bank", "suspended", "account"]
        found_keywords = [word for word in keywords if word in text.lower()]

        risk_score = 0.0
        if found_keywords:
            risk_score = 0.3 + (len(found_keywords) * 0.1)

        risk_score = min(risk_score, 0.95)

        status = "Safe"
        if risk_score > 0.7:
            status = "Phishing"
        elif risk_score > 0.4:
            status = "Suspicious"

        return {
            "status": status,
            "risk_score": risk_score,
            "keywords": found_keywords,
            "details": [f"Suspicious keyword: {k}" for k in found_keywords],
        }
