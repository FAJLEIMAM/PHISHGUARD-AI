import csv
import os
import time

import pandas as pd

DATA_FILE = "training_data_log.csv"


class DataCollector:
    def __init__(self):
        self.data_file = DATA_FILE
        self._init_file()

    def _init_file(self):
        if not os.path.exists(self.data_file):
            with open(self.data_file, mode="w", newline="") as file:
                writer = csv.writer(file)
                # Header: url,f1..f13,label,timestamp
                header = (
                    ["url"] + [f"f{i}" for i in range(1, 14)] + ["label", "timestamp"]
                )
                writer.writerow(header)

    def log_feedback(self, url, features, label):
        """
        Logs a verified sample from user feedback.
        label: 0 (Safe), 1 (Phishing)
        """
        try:
            with open(self.data_file, mode="a", newline="") as file:
                writer = csv.writer(file)
                row = [url] + features + [label, int(time.time())]
                writer.writerow(row)
            print(f"Logged feedback for: {url} -> {label}")
            return True
        except Exception as e:
            print(f"Error logging data: {e}")
            return False

    def get_new_data_count(self):
        try:
            with open(self.data_file, mode="r") as file:
                return sum(1 for line in file) - 1  # exclude header
        except Exception:
            return 0

    def load_new_data(self):
        """Loads collected data for retraining."""
        if not os.path.exists(self.data_file):
            return None

        try:
            df = pd.read_csv(self.data_file)
            if df.empty:
                return None

            # Extract features (f1..f9) and label
            x = df.iloc[:, 1:10].values
            y = df["label"].values
            return x, y
        except Exception as e:
            print(f"Error loading new data: {e}")
            return None

    def reset_data_file(self):
        """Resets the CSV log file to header-only after retraining."""
        try:
            with open(self.data_file, mode="w", newline="") as file:
                writer = csv.writer(file)
                header = (
                    ["url"] + [f"f{i}" for i in range(1, 14)] + ["label", "timestamp"]
                )
                writer.writerow(header)
            print("[DataCollector] Log file reset after retraining.")
        except Exception as e:
            print(f"Error resetting data file: {e}")
