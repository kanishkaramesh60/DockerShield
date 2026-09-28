from __future__ import annotations

import json
from pathlib import Path

import streamlit as st

from dockershield.dashboard.components.cards import (
    metric_card,
    section_header,
)
from dockershield.dashboard.state import require_scan

METRICS_PATH = Path("data") / "ml_metrics.json"


def render_ml(scan: dict):
    prediction = scan.get("ml_prediction")

    if not prediction:
        st.warning(
            "[ML] XGBoost model unavailable. Train the model "
            "(data/xgboost_risk_model.json) to enable predictions."
        )
        return

    a, b, c = st.columns(3)
    with a:
        metric_card("Model", prediction.get("model", "XGBoost"), "", "purple")
    with b:
        metric_card(
            "Predicted Risk",
            prediction.get("predicted_class", "UNKNOWN"),
            "",
            "red" if prediction.get("predicted_class") in ("HIGH", "CRITICAL")
            else "green",
        )
    with c:
        metric_card(
            "Confidence",
            f"{prediction.get('confidence', 0) * 100:.2f}%",
            "model confidence",
            "blue",
        )

    st.markdown("<br>", unsafe_allow_html=True)

    left, right = st.columns(2)

    with left:
        section_header("Class Probabilities", "")
        probs = prediction.get("probabilities", {})
        st.bar_chart(
            {
                "Class": list(probs.keys()),
                "Probability %": [v * 100 for v in probs.values()],
            },
            x="Class",
            y="Probability %",
            height=260,
        )
        for label, value in probs.items():
            st.markdown(f"`{label:<9}` {value * 100:6.2f}%")

    with right:
        section_header("Input Features", "Values extracted from findings.")
        features = prediction.get("features", {})
        st.dataframe(
            [{"Feature": k, "Value": v} for k, v in features.items()],
            use_container_width=True,
            hide_index=True,
            height=360,
        )

    st.caption(
        "The XGBoost prediction is an additional assessment. The "
        "deterministic rules remain the source of individual findings."
    )


def _model_metrics():
    if not METRICS_PATH.exists():
        return

    metrics = json.loads(METRICS_PATH.read_text(encoding="utf-8"))

    section_header("Model Performance", "From data/ml_metrics.json.")

    a, b, c = st.columns(3)
    with a:
        metric_card("Accuracy", f"{metrics.get('accuracy', 0) * 100:.1f}%", "", "green")
    with b:
        metric_card("Training Samples", metrics.get("training_samples", "—"), "", "blue")
    with c:
        metric_card("Test Samples", metrics.get("test_samples", "—"), "", "blue")

    report = metrics.get("classification_report", {})
    rows = [
        {
            "Class": label,
            "Precision": round(vals["precision"], 3),
            "Recall": round(vals["recall"], 3),
            "F1": round(vals["f1-score"], 3),
            "Support": int(vals["support"]),
        }
        for label, vals in report.items()
        if isinstance(vals, dict)
    ]

    st.dataframe(rows, use_container_width=True, hide_index=True)


def render(api):
    section_header(
        "ML Analysis",
        "XGBoost risk prediction for the latest scan.",
    )

    scan = require_scan()
    if scan:
        render_ml(scan)

    st.markdown("<br>", unsafe_allow_html=True)
    _model_metrics()
