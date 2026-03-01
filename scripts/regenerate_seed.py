import os
import sys

import pandas as pd

# Add project root to sys.path
sys.path.append(os.getcwd())

from backend.core.feature_extraction import FeatureExtractor


def regenerate_seed_data():
    seed_path = "backend/data/seed_data.csv"
    if not os.path.exists(seed_path):
        print("Seed data not found.")
        return

    df = pd.read_csv(seed_path)
    extractor = FeatureExtractor()

    new_rows = []
    for _, row in df.iterrows():
        url = row["url"]
        label = row["label"]
        features = extractor.extract_features(url)
        new_row = [url] + features + [label]
        new_rows.append(new_row)

    new_df = pd.DataFrame(
        new_rows,
        columns=[
            "url",
            "f1",
            "f2",
            "f3",
            "f4",
            "f5",
            "f6",
            "f7",
            "f8",
            "f9",
            "f10",
            "f11",
            "f12",
            "f13",
            "label",
        ],
    )
    new_df.to_csv(seed_path, index=False)
    print(f"Regenerated seed data with {len(new_rows)} samples and 13 features.")


if __name__ == "__main__":
    regenerate_seed_data()
