import threading
import time

from backend.core.data_collector import DataCollector
from backend.core.ml_models import AIModels


class ModelRetrainer:
    def __init__(self, ai_models: AIModels):
        self.ai_models = ai_models
        self.collector = DataCollector()
        self.is_retraining = False
        self.retrain_threshold = 5  # Small for demo

        # Start background loop
        self.thread = threading.Thread(target=self._check_for_retrain, daemon=True)
        self.thread.start()

    def _check_for_retrain(self):
        while True:
            time.sleep(10)  # Check every 10s
            count = self.collector.get_new_data_count()
            print(f"[Auto-Learn] New samples: {count}/{self.retrain_threshold}")

            if count >= self.retrain_threshold and not self.is_retraining:
                self.retrain()

    def retrain(self):
        print("[Auto-Learn] Starting retraining process...")
        self.is_retraining = True

        # Load new data — returns None when file is empty or missing
        result = self.collector.load_new_data()

        if result is not None:
            x_new, y_new = result
            # Trigger model update (simulated for now, essentially re-fit)
            # In real-world, we'd combine old + new.
            self.ai_models.train_models_incremental(x_new, y_new)
            print("[Auto-Learn] Model updated and hot-swapped.")

            # Reset the log file so we don't retrain on the same data again
            self.collector.reset_data_file()
        else:
            print("[Auto-Learn] No new data to train on.")

        self.is_retraining = False
