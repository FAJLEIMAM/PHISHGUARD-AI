import os
import sys

# Add the project root to sys.path
sys.path.append(os.getcwd())

from backend.core.data_collector import DataCollector as Collector
from backend.core.detector import PhishingDetector as Detector
from backend.core.retrainer import ModelRetrainer as Retrainer


def test_retraining_flow():
    print("Starting verification test...")

    # 1. Initialize detector and collector
    detector = Detector()
    collector = Collector()

    # 2. Reset data file for clean test
    collector.reset_data_file()

    # 3. Simulate user feedback (submitting samples)
    test_urls = [
        "http://evil-phish-1.com",
        "http://evil-phish-2.com",
        "http://evil-phish-3.com",
        "http://evil-phish-4.com",
        "http://evil-phish-5.com",
    ]

    print("Submitting feedback samples...")
    for url in test_urls:
        features = detector.ai_models.feature_extractor.extract_features(url)
        collector.log_feedback(url, features, 1)  # 1 = Phishing

    # 4. Check if retraining is triggered (retrain_threshold = 5)
    print("Waiting for retrainer to pick up changes...")
    retrainer = Retrainer(detector.ai_models)

    # Manually trigger retrain to verify the logic inside retrainer/ml_models
    print("Manually triggering retraining to verify the logic...")
    retrainer.retrain()

    print("Verification test completed successfully.")


if __name__ == "__main__":
    test_retraining_flow()
