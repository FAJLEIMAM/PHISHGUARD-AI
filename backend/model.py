import os
from typing import Optional, Tuple

import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier

from backend.core.feature_extraction import FeatureExtractor

MODEL_PATH = "model.pkl"


class PhishingModel:
    def __init__(self):
        self.model: Optional[RandomForestClassifier] = None
        self.feature_extractor = FeatureExtractor()
        self.load_model()

    def train_dummy_model(self):
        """Trains a dummy Random Forest model for demonstration purposes."""
        print("Training dummy model...")
        # 0: Safe, 1: Phishing
        # Features: [length, domain_len, has_ip, count_@, count_//,
        #            count_., count_-, count_digits, is_https]
        x_train = np.array(
            [
                [20, 10, 0, 0, 0, 2, 0, 0, 1],  # Safe: google.com
                [25, 12, 0, 0, 0, 2, 0, 0, 1],  # Safe: facebook.com
                [50, 15, 0, 1, 1, 4, 2, 5, 0],  # Phishing: secure-login.example.com
                [60, 20, 1, 1, 1, 3, 3, 10, 0],  # Phishing: http://192.168.1.1/login
                [30, 15, 0, 0, 0, 3, 0, 0, 1],  # Safe: wikipedia.org
                [45, 10, 0, 1, 0, 2, 1, 2, 0],  # Phishing
                [22, 11, 0, 0, 0, 2, 0, 0, 1],  # Safe
            ]
        )
        y_train = np.array([0, 0, 1, 1, 0, 1, 0])

        model = RandomForestClassifier(n_estimators=10)
        model.fit(x_train, y_train)
        self.model = model
        joblib.dump(model, MODEL_PATH)
        print(f"Model saved to {MODEL_PATH}")

    def load_model(self):
        """Loads the trained model from disk."""
        if os.path.exists(MODEL_PATH):
            self.model = joblib.load(MODEL_PATH)
        else:
            print("Model not found. Training a new one...")
            self.train_dummy_model()

    def predict(self, url: str) -> Tuple[int, float]:
        """Predicts if a URL is phishing or safe."""
        model = self.model
        if model is None:
            self.load_model()
            model = self.model

        if model is not None:
            features = self.feature_extractor.extract_features(url)
            prediction = model.predict([features])[0]
            probability = model.predict_proba([features])[0][
                1
            ]  # Probability of being Phishing
            return int(prediction), float(probability)

        return 0, 0.0


if __name__ == "__main__":
    pm = PhishingModel()
    pm.train_dummy_model()
