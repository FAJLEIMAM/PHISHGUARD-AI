import os
from typing import Any, Dict, Optional, cast

import joblib  # type: ignore
from sklearn.ensemble import IsolationForest, RandomForestClassifier  # type: ignore

from .feature_extraction import FeatureExtractor  # type: ignore

# Use paths relative to this file so they work regardless of CWD
_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH_RF = os.path.join(_DIR, "model_rf.pkl")
MODEL_PATH_IF = os.path.join(_DIR, "model_if.pkl")
SEED_DATA_PATH = os.path.join(_DIR, "..", "data", "seed_data.csv")
DYNAMIC_DATA_PATH = os.path.join(_DIR, "..", "..", "training_data_log.csv")


class AIModels:
    def __init__(self):
        self.rf_model: Optional[RandomForestClassifier] = None
        self.if_model: Optional[IsolationForest] = None
        self.feature_extractor = FeatureExtractor()
        self.load_models()

    def _load_all_data(self):
        """Loads and combines seed data and dynamic user feedback data."""
        import pandas as pd

        # 1. Load Seed Data
        try:
            df_seed = pd.read_csv(SEED_DATA_PATH)
        except Exception as e:
            print(f"[AIModels] Error loading seed data: {e}")
            df_seed = pd.DataFrame()

        # 2. Load Dynamic User Feedback Data
        try:
            if os.path.exists(DYNAMIC_DATA_PATH):
                df_dynamic = pd.read_csv(DYNAMIC_DATA_PATH)
            else:
                df_dynamic = pd.DataFrame()
        except Exception as e:
            print(f"[AIModels] Error loading dynamic data: {e}")
            df_dynamic = pd.DataFrame()

        # 3. Combine Data
        if df_seed.empty and df_dynamic.empty:
            print("[AIModels] CRITICAL: No training data found!")
            return None, None

        # Filter out empty dataframes and combine
        dfs = [df for df in [df_seed, df_dynamic] if not df.empty]
        df_all = pd.concat(dfs, ignore_index=True)

        # Extract features (f1..f13) and labels
        # Assuming format: url, f1, f2, f3, f4, f5, f6, f7, f8, f9, f10, f11, f12, f13, label, ...
        x = df_all.iloc[:, 1:14].values
        y = df_all["label"].values

        return x, y

    def train_models(self):
        """Trains both Supervised (RF) and Anomaly Detection (IF) models."""
        print("Training AI models (PERSISTENT DATA - 13 FEATURES)...")

        x_train, y_train = self._load_all_data()

        if x_train is None:
            print("[AIModels] Training aborted due to missing data.")
            return

        print(f"Training Data Shape: {x_train.shape}, Label Shape: {y_train.shape}")

        # 1. Random Forest (Supervised)
        rf = RandomForestClassifier(n_estimators=100, max_depth=10, random_state=42)
        rf.fit(x_train, y_train)
        self.rf_model = rf
        # Save models using absolute paths derived from this file's location
        joblib.dump(rf, MODEL_PATH_RF)

        # 2. Isolation Forest (Anomaly/Unsupervised)
        # Cast contamination to Any to avoid weird Pyright error if it persists
        if_ = IsolationForest(contamination=cast(Any, 0.1), random_state=42)
        if_.fit(x_train)
        self.if_model = if_
        joblib.dump(if_, MODEL_PATH_IF)

        print("Models saved.")

    def load_models(self):
        """Loads models from disk or trains if missing."""
        if os.path.exists(MODEL_PATH_RF) and os.path.exists(MODEL_PATH_IF):
            try:
                self.rf_model = joblib.load(MODEL_PATH_RF)
                self.if_model = joblib.load(MODEL_PATH_IF)
                print("Models loaded from disk.")
            except Exception as e:
                print(f"Error loading models ({e}), retraining...")
                self.train_models()
        else:
            print(f"Models not found at {MODEL_PATH_RF}. Training new ones...")
            self.train_models()

    def train_models_incremental(self, x_new, y_new):
        """Retrains the models by combining existing logic with new data."""
        print(f"[AIModels] Incremental update requested with {len(x_new)} new samples.")

        # Re-run train_models which includes the base dataset for simplicity.
        # In a production system, we'd load the full historical dataset + new samples.
        # Here we will simulate incremental growth by retraining with the core data.
        self.train_models()
        print("[AIModels] Models retrained and updated in-memory.")

    def predict(self, url: str) -> Dict[str, Any]:
        rf = self.rf_model
        if_ = self.if_model

        if rf is None or if_ is None:
            self.load_models()
            rf = self.rf_model
            if_ = self.if_model

        if rf is not None and if_ is not None:
            features = self.feature_extractor.extract_features(url)

            # Supervised Prediction
            prediction = rf.predict([features])[0]
            # Get probability of CLASS 1 (Phishing)
            try:
                phish_index = list(rf.classes_).index(1)
                probability = rf.predict_proba([features])[0][phish_index]
            except (ValueError, IndexError, AttributeError) as e:
                print(f"Warning: could not get phishing prob ({e}). Defaulting to 0.0.")
                probability = 0.0

            # Anomaly Detection (1 = normal, -1 = anomaly)
            anomaly_score = if_.predict([features])[0]
            is_anomaly = True if anomaly_score == -1 else False

            feature_importances = rf.feature_importances_

            return {
                "prediction": int(prediction),
                "probability": float(probability),
                "is_anomaly": is_anomaly,
                "features": features,
                "feature_impact": feature_importances.tolist(),
            }

        # Fallback if loading failed
        return {
            "prediction": 0,
            "probability": 0.0,
            "is_anomaly": False,
            "features": self.feature_extractor.extract_features(url),
            "feature_impact": [],
        }
