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

SEVERITY_COLORS = {
    "CRITICAL": "#ef4444",
    "HIGH": "#fb923c",
    "MEDIUM": "#facc15",
    "LOW": "#38bdf8",
    "SECURE": "#22c55e",
}


def severity_color(severity: str) -> str:
    return SEVERITY_COLORS.get(str(severity).upper(), "#38bdf8")


def finding_card(finding: dict):
    """Render one finding exactly as the CLI prints it."""

    from html import escape

    severity = str(finding.get("severity", "UNKNOWN")).upper()

    st.markdown(
        f"""
        <div class="finding-row"
             style="border-left:3px solid {severity_color(severity)};">
            <div class="finding-rule">
                {escape(str(finding.get("rule_id", "UNKNOWN")))}
                &nbsp;/&nbsp;
                <span style="color:{severity_color(severity)};">
                    {escape(severity)}
                </span>
            </div>
            <div class="finding-title">
                {escape(str(finding.get("title", "Security finding")))}
            </div>
            <div class="finding-meta">
                {escape(str(finding.get("container", "N/A")))}
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    with st.expander(f"View {finding.get('rule_id', 'finding')} details"):
        st.markdown("**Description**")
        st.write(finding.get("description", "No description."))

        st.markdown("**Evidence**")
        st.code(str(finding.get("evidence", "No evidence.")))

        st.markdown("**Impact**")
        st.write(finding.get("impact", "No impact information."))

        st.markdown("**Remediation**")
        st.write(finding.get("remediation", "No remediation information."))


def chain(steps: list[str]):
    """Render an attack-path chain: a -> b -> c."""

    from html import escape

    html = '<div class="chain">'

    for index, step in enumerate(steps):
        last = index == len(steps) - 1
        cls = "chain-node end" if last else "chain-node"
        html += f'<span class="{cls}">{escape(str(step))}</span>'

        if not last:
            html += '<span class="chain-arrow">→</span>'

    html += "</div>"

    st.markdown(html, unsafe_allow_html=True)
