from __future__ import annotations

import csv
import json
from pathlib import Path

import xgboost as xgb
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
)
from sklearn.model_selection import train_test_split


DATASET_PATH = Path("data") / "ml_dataset.csv"
MODEL_PATH = Path("data") / "xgboost_risk_model.json"
METRICS_PATH = Path("data") / "ml_metrics.json"


FEATURE_NAMES = [
    "total_findings",
    "critical_count",
    "high_count",
    "medium_count",
    "low_count",
    "privileged",
    "root_user",
    "dangerous_capabilities",
    "docker_socket",
    "host_network",
    "host_pid",
    "host_ipc",
    "sensitive_mount",
    "missing_memory_limit",
    "missing_cpu_limit",
    "unsafe_add",
    "possible_secret",
    "remote_shell_download",
]


LABELS = {
    "SECURE": 0,
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4,
}


def load_dataset():
    rows = []

    with DATASET_PATH.open(
        newline="",
        encoding="utf-8",
    ) as file:
        reader = csv.DictReader(file)

        for row in reader:
            rows.append(row)

    X = [
        [
            int(row[name])
            for name in FEATURE_NAMES
        ]
        for row in rows
    ]

    y = [
        LABELS[row["label"]]
        for row in rows
    ]

    return X, y


def train_model():
    X, y = load_dataset()

    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=0.2,
        random_state=42,
        stratify=y,
    )

    model = xgb.XGBClassifier(
        objective="multi:softprob",
        num_class=5,
        n_estimators=100,
        max_depth=4,
        learning_rate=0.1,
        subsample=0.9,
        colsample_bytree=0.9,
        random_state=42,
        eval_metric="mlogloss",
    )

    model.fit(
        X_train,
        y_train,
    )

    predictions = model.predict(X_test)

    accuracy = accuracy_score(
        y_test,
        predictions,
    )

    report = classification_report(
        y_test,
        predictions,
        target_names=list(LABELS.keys()),
        output_dict=True,
        zero_division=0,
    )

    matrix = confusion_matrix(
        y_test,
        predictions,
    ).tolist()

    model_path = MODEL_PATH

    model_path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    model.save_model(model_path)

    metrics = {
        "model": "XGBoost",
        "samples": len(X),
        "training_samples": len(X_train),
        "test_samples": len(X_test),
        "accuracy": round(
            float(accuracy),
            4,
        ),
        "classification_report": report,
        "confusion_matrix": matrix,
        "labels": LABELS,
        "features": FEATURE_NAMES,
    }

    METRICS_PATH.write_text(
        json.dumps(
            metrics,
            indent=2,
        ),
        encoding="utf-8",
    )

    return metrics


if __name__ == "__main__":
    metrics = train_model()

    print("\n[XGBoost] Training complete.")
    print(
        f"Accuracy: "
        f"{metrics['accuracy'] * 100:.2f}%"
    )

    print(
        f"Model: {MODEL_PATH}"
    )

    print(
        f"Metrics: {METRICS_PATH}"
    )