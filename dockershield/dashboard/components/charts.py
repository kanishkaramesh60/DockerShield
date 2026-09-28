from __future__ import annotations

import streamlit as st


def severity_chart(severity_counts: dict[str, int]):
    labels = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]

    values = [
        severity_counts.get("CRITICAL", 0),
        severity_counts.get("HIGH", 0),
        severity_counts.get("MEDIUM", 0),
        severity_counts.get("LOW", 0),
    ]

    chart_data = {
        "Severity": labels,
        "Findings": values,
    }

    st.bar_chart(
        chart_data,
        x="Severity",
        y="Findings",
        horizontal=True,
        height=280,
    )


def risk_gauge(score: int):
    percentage = max(0, min(score, 100))

    st.markdown(
        f"""
        <div class="risk-gauge">
            <div class="risk-number">{score}</div>
            <div class="risk-label">/ 100</div>
            <div class="risk-track">
                <div class="risk-fill" style="width:{percentage}%"></div>
            </div>
            <div class="risk-caption">Unified Security Risk Score</div>
        </div>
        """,
        unsafe_allow_html=True,
    )