from __future__ import annotations

import streamlit as st

from dockershield.dashboard.components.cards import (
    metric_card,
    section_header,
    severity_badge,
)
from dockershield.dashboard.components.charts import (
    risk_gauge,
    severity_chart,
)
from dockershield.dashboard.state import get_paths


def render(api):
    render_overview(
        api,
        st.session_state.get("scan_data"),
    )


def render_overview(api, scan_data=None):
    section_header(
        "Security Overview",
        "Central security posture for your Docker environment.",
    )

    try:
        health = api.health()
    except Exception as exc:
        st.error(
            f"Unable to connect to DockerShield API: {exc}"
        )
        return

    docker_connected = health.get("docker") == "connected"

    if docker_connected:
        st.success("Docker Engine connected")
    else:
        st.warning(
            "Docker Engine is not connected. Start Docker Desktop "
            "before performing runtime scans."
        )

    if not scan_data:
        _empty_dashboard(api)
        return

    risk = scan_data.get("risk", {})
    compliance = scan_data.get("compliance", {})
    correlations = scan_data.get("correlations", {})
    findings = scan_data.get("findings", [])
    ml_prediction = scan_data.get("ml_prediction")

    attack_paths = get_paths(scan_data)

    score = risk.get("score", 0)
    level = risk.get("level", "SECURE")

    critical_attack_paths = sum(
        1
        for path in attack_paths
        if path.get("severity", "").upper() == "CRITICAL"
    )

    if isinstance(correlations, dict):
        correlation_items = correlations.get(
            "correlations",
            [],
        )
    elif isinstance(correlations, list):
        correlation_items = correlations
    else:
        correlation_items = []

    critical_correlations = sum(
        1
        for correlation in correlation_items
        if correlation.get("severity", "").upper() == "CRITICAL"
    )

    st.markdown(
        f"""
        <div class="hero-panel">
            <div>
                <div class="hero-eyebrow">
                    DOCKERSHIELD SECURITY CENTER
                </div>

                <h1>Container Security Posture</h1>

                <p>
                    Continuous analysis of runtime configuration,
                    Dockerfiles, Compose files, compliance controls,
                    attack paths and remediation opportunities.
                </p>
            </div>

            <div class="hero-status">
                <div class="hero-status-label">
                    CURRENT RISK
                </div>

                <div class="hero-status-value">
                    {level}
                </div>

                <div class="hero-status-score">
                    {score}/100
                </div>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    st.markdown("###")

    c1, c2, c3, c4 = st.columns(4)

    with c1:
        metric_card(
            "Risk Score",
            f"{score}/100",
            level,
            "red" if score >= 60 else "green",
        )

    with c2:
        compliance_percentage = compliance.get(
            "compliance_percentage",
            compliance.get("percentage", 100),
        )

        failed_controls = compliance.get(
            "failed",
            0,
        )

        metric_card(
            "Compliance",
            f"{compliance_percentage}%",
            f"{failed_controls} controls failed",
            "green" if failed_controls == 0 else "yellow",
        )

    with c3:
        total_findings = risk.get(
            "total_findings",
            len(findings),
        )

        metric_card(
            "Findings",
            total_findings,
            "Security findings detected",
            "red" if findings else "green",
        )

    with c4:
        metric_card(
            "Attack Paths",
            len(attack_paths),
            f"{critical_attack_paths} critical",
            "red" if critical_attack_paths else "green",
        )

    st.markdown("###")

    left, right = st.columns([1, 1])

    with left:
        section_header(
            "Risk Distribution",
            "Findings grouped by severity.",
        )

        risk_gauge(score)

        severity_chart(
            risk.get(
                "severity_counts",
                {
                    "CRITICAL": 0,
                    "HIGH": 0,
                    "MEDIUM": 0,
                    "LOW": 0,
                },
            )
        )

    with right:
        section_header(
            "Security Intelligence",
            "Correlations and attack-path analysis.",
        )

        metric_card(
            "Correlations",
            len(correlation_items),
            f"{critical_correlations} critical correlations",
            "purple",
        )

        st.markdown("###")

        metric_card(
            "Critical Attack Paths",
            critical_attack_paths,
            "Potential host-impact chains",
            "red" if critical_attack_paths else "green",
        )

        st.markdown("###")

        if ml_prediction:
            prediction = ml_prediction.get(
                "predicted_class",
                "UNKNOWN",
            )

            confidence = (
                ml_prediction.get(
                    "confidence",
                    0,
                )
                * 100
            )

            metric_card(
                "ML Risk Prediction",
                prediction,
                f"{confidence:.1f}% model confidence",
                "purple",
            )

    st.markdown("###")

    section_header(
        "Critical Findings",
        "Security issues requiring attention.",
    )

    critical_findings = [
        finding
        for finding in findings
        if finding.get(
            "severity",
            "",
        ).upper()
        == "CRITICAL"
    ]

    if not critical_findings:
        st.success(
            "No critical findings detected."
        )
    else:
        for finding in critical_findings[:5]:
            with st.container():
                col1, col2 = st.columns([1, 5])

                with col1:
                    severity_badge("CRITICAL")

                with col2:
                    st.markdown(
                        f"**{finding.get('rule_id', 'N/A')} — "
                        f"{finding.get('title', 'Unknown finding')}**"
                    )

                    st.caption(
                        f"{finding.get('container', 'Unknown target')}"
                    )

                    st.write(
                        finding.get(
                            "description",
                            "No description available.",
                        )
                    )

                st.divider()


def _empty_dashboard(api):
    section_header(
        "No Scan Loaded",
        "Run your first security scan to populate the dashboard.",
    )

    st.markdown(
        """
        <div class="empty-state">
            <div class="empty-icon">◈</div>

            <h2>DockerShield is ready</h2>

            <p>
                Select <b>Scan Center</b> from the sidebar to scan a
                running container, Dockerfile or Compose project.
            </p>
        </div>
        """,
        unsafe_allow_html=True,
    )

    try:
        containers = api.containers()
        count = len(containers)

        metric_card(
            "Docker Containers",
            count,
            "Available for runtime scanning",
            "blue",
        )

    except Exception:
        pass