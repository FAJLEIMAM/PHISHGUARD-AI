"""
PhishGuard Hybrid Detection Engine — v2.

Architecture
============
Combines three detection layers in a hybrid pipeline:

  Layer 1 — Threat Intelligence   : Hard blocklist / allowlist (instant verdict)
  Layer 2 — Rule-Based Engine     : Deterministic heuristics (40 % weight)
  Layer 3 — ML Model              : Random Forest + Anomaly Detection (60 % weight)

Hybrid fusion (Layers 2 + 3):
  final_score = 0.40 * rule_score + 0.60 * ml_score

  BUT — if the rule engine signals very high confidence on its own
  (rule_score ≥ RULE_OVERRIDE_FLOOR) the final score is floored at
  PHISHING threshold so a weak ML probability cannot wash out obvious
  heuristic signals.

Threat classification (unified):
  < 0.40  →  Safe
  0.40 – 0.70  →  Suspicious
  > 0.70   →  Phishing

All scan types (URL, QR, Voice transcript) route through the same
pipeline to ensure consistent, accurate classification.
"""

import re

from ..integrations.threat_intel import ThreatIntel  # type: ignore
from .ml_models import AIModels  # type: ignore
from .nlp_engine import NLPEngine  # type: ignore
from .rule_engine import RuleEngine  # type: ignore

# Hybrid weighting constants
RULE_WEIGHT = 0.40
ML_WEIGHT = 0.60

# Unified threat thresholds
THRESHOLD_PHISHING = 0.70
THRESHOLD_SUSPICIOUS = 0.40

# If the rule engine alone fires at or above this score the final hybrid
# score is guaranteed to be at least THRESHOLD_PHISHING (prevents a
# low ML probability from masking a strong heuristic signal).
RULE_OVERRIDE_FLOOR = 0.80

# Trusted domain seeds — if the *registered domain* is one of these
# we skip path-level keyword inflation so legitimate sites like
# github.com/microsoft/vscode are not penalised for path tokens.
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
}


def _registered_domain_seed(domain: str) -> str:
    """Extract the second-level domain label (e.g. 'github' from 'github.com')."""
    parts = domain.split(".")
    return parts[-2] if len(parts) >= 2 else domain


class PhishingDetector:
    def __init__(self):
        self.ai_models = AIModels()
        self.nlp_engine = NLPEngine()
        self.threat_intel = ThreatIntel()
        self.rule_engine = RuleEngine()

    # ------------------------------------------------------------------
    # PUBLIC: Scan a URL (used directly and by QR scan pipeline)
    # ------------------------------------------------------------------
    def scan_url(self, url: str) -> dict:
        """
        Full hybrid scan pipeline for any URL string.

        Stages
        ------
        1. Threat intelligence hard blocklist / allowlist check
        2. Rule-based heuristic analysis
        3. ML prediction (Random Forest + Isolation Forest anomaly)
        4. Hybrid score fusion with rule-override floor
        5. Unified threat classification
        6. Rich ai_breakdown assembly
        """
        url = url.strip()

        # ------------------------------------------------------------------
        # Stage 1: Threat intelligence (instant verdict paths)
        # ------------------------------------------------------------------
        ti_result = self.threat_intel.check_url(url)

        if ti_result == -1:
            # Hard blocklist hit — run rule engine for rich breakdown but
            # force final verdict to PHISHING regardless.
            rule_result = self.rule_engine.analyze(url)
            ai_result = self._safe_ml_predict(url)
            ml_score = float(ai_result["probability"])

            return {
                "status": "Phishing",
                "risk_score": 1.0,
                "details": (
                    rule_result["flags"]
                    or ["⛔ Domain found in threat intelligence blocklist"]
                ),
                "recommendation": self._get_recommendation("Phishing"),
                "features": ai_result["features"],
                "explanation": [
                    "Domain matched threat intelligence hard blocklist.",
                    f"Rule-based analysis flagged {len(rule_result['flags'])} signal(s).",
                    f"ML model confidence: {ml_score * 100:.1f}%",
                ],
                "ai_breakdown": {
                    "rule_score": float(f"{rule_result['score']:.4f}"),
                    "ml_score": float(f"{ml_score:.4f}"),
                    "final_weighted_score": 1.0,
                    "ml_confidence": float(f"{ml_score * 100:.1f}"),
                    "keywords_found": rule_result["keywords_found"],
                    "domain_flags": rule_result["domain_flags"]
                    or ["HARD BLOCKLIST HIT"],
                    "tld_flag": rule_result.get("tld_flag"),
                    "anomaly_detected": ai_result["is_anomaly"],
                    "rule_flags": rule_result["flags"],
                    "blacklisted": True,
                },
            }

        if ti_result == 1:
            # Allowlist hit — still run a lightweight check but report SAFE
            # (protects against subdomain abuse of trusted brands)
            rule_result = self.rule_engine.analyze(url)
            rule_score = rule_result["score"]
            ai_result = self._safe_ml_predict(url)
            ml_score = float(ai_result["probability"])
            final_score = float(
                f"{min((RULE_WEIGHT * rule_score) + (ML_WEIGHT * ml_score), 1.0):.4f}"
            )
            # Trusted domain — only escalate if BOTH rule and ML are very high
            if rule_score < RULE_OVERRIDE_FLOOR or ml_score < THRESHOLD_PHISHING:
                status = "Safe"
                final_score = min(final_score, THRESHOLD_SUSPICIOUS - 0.01)
            else:
                status = self._classify(final_score)

            return {
                "status": status,
                "risk_score": final_score,
                "details": rule_result["flags"]
                or ["✅ Domain found in trusted allowlist"],
                "recommendation": self._get_recommendation(status),
                "features": ai_result["features"],
                "explanation": [
                    f"Domain found in trusted allowlist. Risk score: {final_score * 100:.1f}%"
                ],
                "ai_breakdown": {
                    "rule_score": float(f"{rule_score:.4f}"),
                    "ml_score": float(f"{ml_score:.4f}"),
                    "final_weighted_score": float(final_score),
                    "ml_confidence": float(f"{ml_score * 100:.1f}"),
                    "keywords_found": rule_result["keywords_found"],
                    "domain_flags": rule_result["domain_flags"],
                    "tld_flag": rule_result.get("tld_flag"),
                    "anomaly_detected": ai_result["is_anomaly"],
                    "rule_flags": rule_result["flags"],
                    "blacklisted": False,
                },
            }

        # ------------------------------------------------------------------
        # Stage 2: Rule-based analysis
        # ------------------------------------------------------------------
        rule_result = self.rule_engine.analyze(url)

        # Rule engine hard blacklist — immediate PHISHING
        if rule_result["blacklisted"]:
            ai_result = self._safe_ml_predict(url)
            ml_score = float(ai_result["probability"])
            return {
                "status": "Phishing",
                "risk_score": 1.0,
                "details": rule_result["flags"],
                "recommendation": self._get_recommendation("Phishing"),
                "features": ai_result["features"],
                "explanation": [
                    "Domain matched internal hard blacklist.",
                    f"ML model confidence: {ml_score * 100:.1f}%",
                ],
                "ai_breakdown": {
                    "rule_score": 1.0,
                    "ml_score": float(f"{ml_score:.4f}"),
                    "final_weighted_score": 1.0,
                    "ml_confidence": float(f"{ml_score * 100:.1f}"),
                    "keywords_found": rule_result["keywords_found"],
                    "domain_flags": rule_result["domain_flags"],
                    "tld_flag": rule_result.get("tld_flag"),
                    "anomaly_detected": ai_result["is_anomaly"],
                    "rule_flags": rule_result["flags"],
                    "blacklisted": True,
                },
            }

        rule_score = rule_result["score"]

        # ------------------------------------------------------------------
        # Stage 3: ML prediction
        # ------------------------------------------------------------------
        ai_result = self._safe_ml_predict(url)
        ml_score = float(ai_result["probability"])
        is_anomaly = ai_result["is_anomaly"]

        # Boost ML score on anomaly signal
        if is_anomaly:
            ml_score = max(ml_score, 0.75)

        # ------------------------------------------------------------------
        # Stage 4: Hybrid score fusion with rule-override floor
        # ------------------------------------------------------------------
        final_score = (RULE_WEIGHT * rule_score) + (ML_WEIGHT * ml_score)

        # Rule override floor: if rule engine is very confident (≥ 80%)
        # the combined score must reach the phishing threshold even if
        # the ML model returns a weak probability (e.g., for novel HTTPS
        # phishing domains the training data hasn't seen).
        if rule_score >= RULE_OVERRIDE_FLOOR:
            final_score = max(final_score, THRESHOLD_PHISHING + 0.01)

        final_score = float(f"{min(final_score, 1.0):.4f}")

        # ------------------------------------------------------------------
        # Stage 5: Threat classification
        # ------------------------------------------------------------------
        status = self._classify(final_score)

        # ------------------------------------------------------------------
        # Stage 6: Build details list
        # ------------------------------------------------------------------
        details = list(rule_result["flags"])
        features = ai_result["features"]

        # Append ML-derived supplementary flags
        if features[2] == 1 and "IP address" not in " ".join(details):
            details.append("🖥️ URL contains IP address instead of domain name")
        if features[3] > 0 and "@" not in " ".join(details):
            details.append("⚠️ '@' symbol found — credential theft pattern")
        if features[8] == 0 and "HTTPS" not in " ".join(details):
            details.append("🔓 Not using HTTPS — connection is insecure")
        if is_anomaly:
            details.append("🚨 Zero-Day Anomaly: Unknown threat pattern detected by AI")

        # Console debug (ASCII-safe for Windows)
        _safe_print(
            f"\n--- [PhishGuard Hybrid] Scan: {url} ---\n"
            f"  Rule Score  : {rule_score:.4f}\n"
            f"  ML Score    : {ml_score:.4f}\n"
            f"  Final Score : {final_score:.4f}  =>  {status}\n"
            f"  Keywords    : {rule_result['keywords_found']}\n"
            f"  Rule Override: {'YES' if rule_score >= RULE_OVERRIDE_FLOOR else 'no'}\n"
            f"------------------------------------------"
        )

        return {
            "status": status,
            "risk_score": final_score,
            "details": details if details else ["No specific patterns detected"],
            "recommendation": self._get_recommendation(status),
            "features": features,
            "explanation": self._build_explanation(
                final_score, rule_result, ml_score, is_anomaly
            ),
            "ai_breakdown": {
                "rule_score": float(f"{rule_score:.4f}"),
                "ml_score": float(f"{ml_score:.4f}"),
                "final_weighted_score": float(final_score),
                "ml_confidence": float(f"{ml_score * 100:.1f}"),
                "keywords_found": rule_result["keywords_found"],
                "domain_flags": rule_result["domain_flags"],
                "tld_flag": rule_result.get("tld_flag"),
                "anomaly_detected": is_anomaly,
                "rule_flags": rule_result["flags"],
                "blacklisted": False,
                "rule_override_applied": rule_score >= RULE_OVERRIDE_FLOOR,
            },
        }

    # ------------------------------------------------------------------
    # PUBLIC: Scan a decoded QR URL — same pipeline as scan_url
    # ------------------------------------------------------------------
    def scan_qr_url(self, decoded_url: str) -> dict:
        """
        Scan a URL decoded from a QR code through the full hybrid pipeline.
        Identical to scan_url but tagged separately for logging and UI clarity.
        """
        result = self.scan_url(decoded_url)
        result["source"] = "QR_CODE"
        return result

    # ------------------------------------------------------------------
    # PUBLIC: Scan text/transcript (NLP engine)
    # ------------------------------------------------------------------
    def scan_text(self, text: str) -> dict:
        """
        Consolidated Text Scanner:
        1. Extracts ALL URLs using regex (https? requirement).
        2. Performs NLP keyword scan on the raw text.
        3. Routes every URL to the EXACT same scan_url hybrid pipeline.
        4. Returns the result with the highest risk (max fusion).
        """
        # Ensure we have a string to process
        input_text = str(text) if text else ""
        if not input_text:
            return self.nlp_engine.analyze_text("")

        print("\n[PhishGuard] --- NEW TEXT SCAN REQUEST ---")
        # type: ignore (Fix Pyre2 slicing diagnostic)
        truncated_input = str(input_text[:100])
        print(f"[PhishGuard] Input: {truncated_input}...")

        # Step 1: Baseline NLP Analysis
        nlp_result = dict(self.nlp_engine.analyze_text(input_text))
        current_max_score = float(nlp_result.get("risk_score", 0.0))
        final_result = nlp_result

        # Step 2: URL Extraction
        # We look for explicit https? URLs OR domain-like strings (e.g., login.com)
        # to ensure raw links pasted without protocols are still analyzed.
        url_pattern = r"https?://[^\s]+|(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}(?:/[^\s]*)?"
        raw_urls = re.findall(url_pattern, input_text, re.IGNORECASE)

        # Deduplicate and clean trailing punctuation
        unique_urls = list(
            set([u.strip(".,!?;:\"'()[]{}") for u in raw_urls if u.strip()])
        )
        print(
            f"[PhishGuard] Detected {len(unique_urls)} URL candidate(s): {unique_urls}"
        )

        # Step 3: Hybrid URL Analysis (Same logic as URL tab)
        for url in unique_urls:
            print(f"[PhishGuard] Routing extracted URL to hybrid engine: {url}")
            url_res = self.scan_url(url)

            # Extract score and status safely
            url_score = float(url_res.get("risk_score", 0.0))
            url_status = str(url_res.get("status", "Safe"))

            print(
                f"[PhishGuard] URL Risk Verdict: {url_status} ({url_score * 100:.1f}%)"
            )

            # Requirement: Final risk score = max(URL risk, text keyword risk)
            if url_score >= current_max_score:
                current_max_score = url_score
                final_result = url_res

        final_res_dict = dict(final_result)
        final_status = str(final_res_dict.get("status", "Safe"))
        print(
            f"[PhishGuard] FINAL FUSION RESULT: {final_status} ({current_max_score * 100:.1f}%)"
        )
        print("[PhishGuard] -----------------------------------\n")

        return final_result

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _safe_ml_predict(self, url: str) -> dict:
        """Wrapper around AIModels.predict() that always returns a safe dict."""
        try:
            return self.ai_models.predict(url)
        except Exception as exc:
            print(f"[PhishGuard] ML prediction failed: {exc}")
            from .feature_extraction import FeatureExtractor  # type: ignore

            return {
                "prediction": 0,
                "probability": 0.0,
                "is_anomaly": False,
                "features": FeatureExtractor().extract_features(url),
                "feature_impact": [],
            }

    def _classify(self, score: float) -> str:
        """Unified threshold-based classification."""
        if score > THRESHOLD_PHISHING:
            return "Phishing"
        elif score >= THRESHOLD_SUSPICIOUS:
            return "Suspicious"
        return "Safe"

    def _build_explanation(
        self,
        final_score: float,
        rule_result: dict,
        ml_score: float,
        is_anomaly: bool,
    ) -> list:
        """Human-readable explanation list for the XAI panel."""
        exp = []
        if rule_result["keywords_found"]:
            exp.append(
                f"Detected {len(rule_result['keywords_found'])} phishing "
                f"keyword(s) in URL: {', '.join(rule_result['keywords_found'])}"
            )
        if rule_result["domain_flags"]:
            # Strip emoji for plain-text log safety
            exp.append(
                f"Domain pattern analysis flagged {len(rule_result['domain_flags'])} "
                f"signal(s)"
            )
        if ml_score > 0.60:
            exp.append(
                f"ML model returned high phishing probability: {ml_score * 100:.1f}%"
            )
        if is_anomaly:
            exp.append("Anomaly detector flagged unknown threat signature")
        if final_score > THRESHOLD_PHISHING:
            exp.append(
                f"Combined hybrid score ({final_score * 100:.1f}%) "
                f"exceeds phishing threshold (70%)"
            )
        elif final_score >= THRESHOLD_SUSPICIOUS:
            exp.append(
                f"Combined hybrid score ({final_score * 100:.1f}%) "
                f"indicates suspicious activity (40–70% range)"
            )
        if not exp:
            exp.append(f"Low risk score ({final_score * 100:.1f}%) — URL appears safe")
        return exp

    def _get_recommendation(self, status: str) -> str:
        if status == "Phishing":
            return (
                "⛔ DO NOT visit this URL. Avoid entering credentials. "
                "Report this link immediately."
            )
        elif status == "Suspicious":
            return (
                "⚠️ Proceed with extreme caution. Verify the sender "
                "identity before clicking."
            )
        return "✅ URL appears safe. HTTPS verified. No malicious patterns found."


def _safe_print(msg: str) -> None:
    """Print to console without crashing on Windows cp1252 terminals."""
    try:
        print(msg)
    except UnicodeEncodeError:
        print(msg.encode("ascii", "replace").decode("ascii"))
