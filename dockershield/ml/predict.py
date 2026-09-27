from __future__ import annotations

from pathlib import Path
from typing import Iterable

import xgboost as xgb

from dockershield.models import Finding
from dockershield.ml.features import (
    extract_features,
    feature_names,
)


MODEL_PATH = Path("data") / "xgboost_risk_model.json"


LABELS = {
    0: "SECURE",
    1: "LOW",
    2: "MEDIUM",
    3: "HIGH",
    4: "CRITICAL",
}


def load_model() -> xgb.XGBClassifier:
    """
    Load the trained DockerShield XGBoost model.
    """

    if not MODEL_PATH.exists():
        raise FileNotFoundError(
            f"XGBoost model not found: {MODEL_PATH}"
        )

    model = xgb.XGBClassifier()

    model.load_model(MODEL_PATH)

    return model


def predict_risk(
    findings: Iterable[Finding],
) -> dict:
    """
    Predict risk using the trained XGBoost model.
    """

    findings = list(findings)

    features = extract_features(findings)

    names = feature_names()

    values = [
        features[name]
        for name in names
    ]

    model = load_model()

    prediction = int(
        model.predict([values])[0]
    )

    probabilities = model.predict_proba(
        [values]
    )[0]

    probabilities_by_label = {
        LABELS[index]: round(
            float(probabilities[index]),
            4,
        )
        for index in range(
            len(probabilities)
        )
    }

    return {
        "model": "XGBoost",
        "predicted_class": LABELS[prediction],
        "predicted_class_id": prediction,
        "confidence": round(
            float(probabilities[prediction]),
            4,
        ),
        "probabilities": probabilities_by_label,
        "features": features,
    }