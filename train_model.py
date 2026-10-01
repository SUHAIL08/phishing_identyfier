"""
train_model.py
Trains a Random Forest classifier on the phishing URL dataset and
saves the trained model + evaluation report.
"""
import json
import pickle

import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (accuracy_score, classification_report,
                              confusion_matrix, precision_score,
                              recall_score, f1_score)
from sklearn.model_selection import train_test_split

from feature_extraction import FEATURE_ORDER, extract_features

DATA_PATH = "urls_labeled.csv"
MODEL_PATH = "model.pkl"
REPORT_PATH = "model_report.json"


def main():
    df = pd.read_csv(DATA_PATH)

    feature_rows = [extract_features(u) for u in df["url"]]
    X = pd.DataFrame(feature_rows)[FEATURE_ORDER]
    y = df["label"]

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    candidates = {
        "RandomForest": RandomForestClassifier(
            n_estimators=200, max_depth=None, random_state=42, n_jobs=-1
        ),
        "LogisticRegression": LogisticRegression(max_iter=1000),
    }

    results = {}
    best_name, best_model, best_acc = None, None, -1

    for name, model in candidates.items():
        model.fit(X_train, y_train)
        preds = model.predict(X_test)
        acc = accuracy_score(y_test, preds)
        results[name] = {
            "accuracy": acc,
            "precision": precision_score(y_test, preds),
            "recall": recall_score(y_test, preds),
            "f1": f1_score(y_test, preds),
            "confusion_matrix": confusion_matrix(y_test, preds).tolist(),
        }
        print(f"\n=== {name} ===")
        print(classification_report(y_test, preds,
                                     target_names=["Legitimate", "Phishing"]))
        if acc > best_acc:
            best_name, best_model, best_acc = name, model, acc

    print(f"\nBest model: {best_name} (accuracy={best_acc:.4f})")

    with open(MODEL_PATH, "wb") as f:
        pickle.dump({"model": best_model, "model_name": best_name,
                     "features": FEATURE_ORDER}, f)

    # feature importance (RandomForest only)
    if best_name == "RandomForest":
        importances = dict(zip(FEATURE_ORDER, best_model.feature_importances_.tolist()))
        results["feature_importance"] = dict(
            sorted(importances.items(), key=lambda x: -x[1])
        )

    results["best_model"] = best_name
    with open(REPORT_PATH, "w") as f:
        json.dump(results, f, indent=2)

    print(f"\nSaved model -> {MODEL_PATH}")
    print(f"Saved report -> {REPORT_PATH}")


if __name__ == "__main__":
    main()
