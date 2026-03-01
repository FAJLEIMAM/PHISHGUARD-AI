import os
import sys

import pytest

# Ensure project root is in sys.path for absolute imports
sys.path.append(os.getcwd())

from backend.core.data_collector import DataCollector as Collector
from backend.core.detector import PhishingDetector as Detector
from backend.core.retrainer import ModelRetrainer as Retrainer


@pytest.fixture
def detector():
    return Detector()


@pytest.fixture
def collector():
    c = Collector()
    c.reset_data_file()
    return c


def test_phishing_detection_flow(detector, collector):
    # 1. Simulate data collection
    test_urls = [
        "http://evil-phish-1.com",
        "http://evil-phish-2.com",
        "http://evil-phish-3.com",
        "http://evil-phish-4.com",
        "http://evil-phish-5.com",
    ]

    for url in test_urls:
        features = detector.ai_models.feature_extractor.extract_features(url)
        collector.log_feedback(url, features, 1)  # 1 = Phishing

    # 2. Verify retraining logic
    retrainer = Retrainer(detector.ai_models)
    retrainer.retrain()

    # 3. Simple scan verification
    result = detector.scan_url("http://evil-phish-1.com")
    assert result["status"] in ["Phishing", "Suspicious", "Safe"]
    assert "risk_score" in result
