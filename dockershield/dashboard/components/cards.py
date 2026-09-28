from __future__ import annotations

import streamlit as st


def metric_card(
    title: str,
    value: str | int,
    subtitle: str = "",
    accent: str = "blue",
):
    accents = {
        "blue": "#38bdf8",
        "green": "#22c55e",
        "yellow": "#facc15",
        "orange": "#fb923c",
        "red": "#ef4444",
        "purple": "#a78bfa",
    }

    color = accents.get(
        accent,
        accents["blue"],
    )

    st.markdown(
        f"""
        <div class="metric-card" style="--accent:{color};">
            <div class="metric-accent"></div>

            <div class="metric-title">
                {title}
            </div>

            <div class="metric-value">
                {value}
            </div>

            <div class="metric-subtitle">
                {subtitle}
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def severity_badge(severity: str):
    severity = severity.upper()

    classes = {
        "CRITICAL": "critical",
        "HIGH": "high",
        "MEDIUM": "medium",
        "LOW": "low",
        "SECURE": "secure",
    }

    css_class = classes.get(
        severity,
        "medium",
    )

    st.markdown(
        f"""
        <span class="severity-badge {css_class}">
            {severity}
        </span>
        """,
        unsafe_allow_html=True,
    )


def status_badge(
    label: str,
    healthy: bool,
):
    css_class = (
        "status-online"
        if healthy
        else "status-offline"
    )

    st.markdown(
        f"""
        <span class="status-badge {css_class}">
            <span class="status-dot">●</span>
            {label}
        </span>
        """,
        unsafe_allow_html=True,
    )


def section_header(
    title: str,
    description: str = "",
):
    st.markdown(
        f"""
        <div class="section-header">

            <h2>
                {title}
            </h2>

            <p>
                {description}
            </p>

        </div>
        """,
        unsafe_allow_html=True,
    )