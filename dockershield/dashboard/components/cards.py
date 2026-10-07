from __future__ import annotations

from html import escape

import streamlit as st


ACCENTS = {
    "blue": "#38bdf8",
    "green": "#22c55e",
    "yellow": "#facc15",
    "orange": "#fb923c",
    "red": "#ef4444",
    "purple": "#a78bfa",
}

SEVERITY_COLORS = {
    "CRITICAL": "#ef4444",
    "HIGH": "#fb923c",
    "MEDIUM": "#facc15",
    "LOW": "#38bdf8",
    "SECURE": "#22c55e",
}


def metric_card(
    title: str,
    value: str | int,
    subtitle: str = "",
    accent: str = "blue",
) -> None:
    """Render a styled dashboard metric card."""

    color = ACCENTS.get(accent, ACCENTS["blue"])

    safe_title = escape(str(title))
    safe_value = escape(str(value))
    safe_subtitle = escape(str(subtitle))

    html = f"""
    <div class="metric-card" style="--accent: {color};">
        <div class="metric-accent"></div>
        <div class="metric-title">{safe_title}</div>
        <div class="metric-value">{safe_value}</div>
        <div class="metric-subtitle">{safe_subtitle}</div>
    </div>
    """

    st.markdown(html, unsafe_allow_html=True)


def severity_badge(severity: str) -> None:
    """Render a severity badge."""

    severity = str(severity).upper()

    classes = {
        "CRITICAL": "critical",
        "HIGH": "high",
        "MEDIUM": "medium",
        "LOW": "low",
        "SECURE": "secure",
    }

    css_class = classes.get(severity, "medium")

    st.markdown(
        f"""
        <span class="severity-badge {css_class}">
            {escape(severity)}
        </span>
        """,
        unsafe_allow_html=True,
    )


def status_badge(
    label: str,
    healthy: bool,
) -> None:
    """Render an online/offline status badge."""

    css_class = "status-online" if healthy else "status-offline"

    dot = "●"

    st.markdown(
        f"""
        <span class="status-badge {css_class}">
            <span class="status-dot">{dot}</span>
            {escape(str(label))}
        </span>
        """,
        unsafe_allow_html=True,
    )


def section_header(
    title: str,
    description: str = "",
) -> None:
    """Render a dashboard section heading."""

    st.markdown(
        f"""
        <div class="section-header">
            <h2>{escape(str(title))}</h2>
            <p>{escape(str(description))}</p>
        </div>
        """,
        unsafe_allow_html=True,
    )


def severity_color(severity: str) -> str:
    """Return the display color for a severity."""

    return SEVERITY_COLORS.get(
        str(severity).upper(),
        SEVERITY_COLORS["LOW"],
    )


def finding_card(finding: dict) -> None:
    """Render one security finding."""

    severity = str(
        finding.get("severity", "UNKNOWN")
    ).upper()

    color = severity_color(severity)

    rule_id = escape(
        str(finding.get("rule_id", "UNKNOWN"))
    )

    title = escape(
        str(finding.get("title", "Security finding"))
    )

    container = escape(
        str(finding.get("container", "N/A"))
    )

    st.markdown(
        f"""
        <div class="finding-row"
             style="border-left: 3px solid {color};">

            <div class="finding-rule">
                {rule_id}
                &nbsp;/&nbsp;
                <span style="color: {color};">
                    {escape(severity)}
                </span>
            </div>

            <div class="finding-title">
                {title}
            </div>

            <div class="finding-meta">
                {container}
            </div>

        </div>
        """,
        unsafe_allow_html=True,
    )

    with st.expander(
        f"View {finding.get('rule_id', 'finding')} details"
    ):
        st.markdown("**Description**")
        st.write(
            finding.get(
                "description",
                "No description.",
            )
        )

        st.markdown("**Evidence**")
        st.code(
            str(
                finding.get(
                    "evidence",
                    "No evidence.",
                )
            )
        )

        st.markdown("**Impact**")
        st.write(
            finding.get(
                "impact",
                "No impact information.",
            )
        )

        st.markdown("**Remediation**")
        st.write(
            finding.get(
                "remediation",
                "No remediation information.",
            )
        )


def chain(steps: list[str]) -> None:
    """Render an attack-path chain."""

    html = '<div class="chain">'

    for index, step in enumerate(steps):
        last = index == len(steps) - 1

        css_class = (
            "chain-node end"
            if last
            else "chain-node"
        )

        html += (
            f'<span class="{css_class}">'
            f"{escape(str(step))}"
            "</span>"
        )

        if not last:
            html += '<span class="chain-arrow">→</span>'

    html += "</div>"

    st.markdown(
        html,
        unsafe_allow_html=True,
    )