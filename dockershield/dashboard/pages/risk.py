from __future__ import annotations

import streamlit as st

from dockershield.dashboard.components.cards import (
    metric_card,
    section_header,
    severity_color,
)
from dockershield.dashboard.components.charts import (
    risk_gauge,
    severity_chart,
)
from dockershield.dashboard.state import require_scan


def render_risk(scan: dict):
    risk = scan.get("risk", {})
    counts = risk.get("severity_counts", {})
    level = risk.get("level", "SECURE")

    left, right = st.columns([1, 1])

    with left:
        risk_gauge(risk.get("score", 0))

    with right:
        metric_card(
            "Risk Level",
            level,
            f"Risk score {risk.get('score', 0)}/100",
            "red" if level in ("CRITICAL", "HIGH")
            else "yellow" if level == "MEDIUM"
            else "green",
        )
        st.markdown("<br>", unsafe_allow_html=True)
        metric_card(
            "Total Findings",
            risk.get("total_findings", 0),
            "Counted in the score",
            "blue",
        )

    st.markdown("<br>", unsafe_allow_html=True)
    section_header("Severity Breakdown", "Same values as the CLI.")

    c = st.columns(4)
    for col, sev, accent in zip(
        c,
        ["CRITICAL", "HIGH", "MEDIUM", "LOW"],
        ["red", "orange", "yellow", "blue"],
    ):
        with col:
            metric_card(sev, counts.get(sev, 0), "findings", accent)

    severity_chart(counts)

    st.caption(
        "Score weights: CRITICAL 25 · HIGH 15 · MEDIUM 7 · LOW 2 "
        "(capped at 100). Levels: ≥80 CRITICAL, ≥60 HIGH, ≥30 MEDIUM, "
        ">0 LOW."
    )


def render(api):
    section_header(
        "Risk Analysis",
        "Overall risk score and severity distribution.",
    )

    scan = require_scan()
    if scan:
        render_risk(scan)
