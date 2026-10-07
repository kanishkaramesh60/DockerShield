from __future__ import annotations

import time

import streamlit as st

from dockershield.dashboard.components.cards import metric_card
from dockershield.dashboard.pages.attack_paths import render_attack_paths
from dockershield.dashboard.pages.compliance import render_compliance
from dockershield.dashboard.pages.correlations import render_correlations
from dockershield.dashboard.pages.findings import render_findings
from dockershield.dashboard.pages.ml import render_ml
from dockershield.dashboard.pages.remediation import render_remediation
from dockershield.dashboard.pages.risk import render_risk
from dockershield.dashboard.state import (
    get_paths,
    get_remediations,
    set_scan,
)


# -------------------------------------------------------------------
# PIPELINE
# -------------------------------------------------------------------

def _pipeline():
    steps = [
        "DISCOVERY",
        "INSPECTION",
        "RULE ENGINE",
        "RISK",
        "ML",
        "COMPLIANCE",
        "CORRELATION",
        "ATTACK PATH",
        "REMEDIATION",
    ]

    html = '<div class="pipeline">'

    for index, step in enumerate(steps):
        html += f"""
        <div class="pipeline-step">
            <div class="pipeline-number">{index + 1}</div>
            <div class="pipeline-label">{step}</div>
        </div>
        """

        if index < len(steps) - 1:
            html += '<div class="pipeline-arrow">→</div>'

    html += "</div>"

    st.markdown(html, unsafe_allow_html=True)


# -------------------------------------------------------------------
# FULL SCAN
# -------------------------------------------------------------------

def _run_full_scan(api):
    """Run the complete DockerShield security analysis pipeline."""

    progress = st.progress(0)
    status = st.empty()

    try:
        status.write("Preparing Docker environment discovery...")
        progress.progress(10)
        time.sleep(0.15)

        status.write("Scanning runtime containers...")
        progress.progress(25)

        status.write("Scanning Dockerfile and Compose configuration...")
        progress.progress(40)

        result = api.full_scan()

        status.write("Calculating deterministic risk score...")
        progress.progress(55)
        time.sleep(0.15)

        status.write("Running ML-assisted risk classification...")
        progress.progress(65)
        time.sleep(0.15)

        status.write("Evaluating compliance controls...")
        progress.progress(75)
        time.sleep(0.15)

        status.write("Correlating findings and analyzing attack paths...")
        progress.progress(85)
        time.sleep(0.15)

        status.write("Generating remediation recommendations...")
        progress.progress(95)
        time.sleep(0.15)

        set_scan(
            result,
            "full",
            "Docker runtime + Dockerfile + Docker Compose",
        )

        progress.progress(100)
        status.success("Full DockerShield security analysis completed.")

        return result

    except Exception as exc:
        progress.empty()
        status.empty()
        st.error(f"Full scan failed: {exc}")
        return None


# -------------------------------------------------------------------
# RESULTS
# -------------------------------------------------------------------

def _render_results(result: dict):
    findings = result.get("findings", [])
    risk = result.get("risk", {})
    compliance = result.get("compliance", {})
    ml = result.get("ml_prediction", {})

    a, b, c, d, e = st.columns(5)

    with a:
        metric_card(
            "Risk Score",
            f"{risk.get('score', 0)}/100",
            risk.get("level", "SECURE"),
            "red" if risk.get("score", 0) >= 60 else "green",
        )

    with b:
        metric_card(
            "Compliance",
            f"{compliance.get('compliance_percentage', 100)}%",
            f"{compliance.get('passed', 0)} controls passing",
            "green" if compliance.get("compliance_percentage", 0) >= 80 else "yellow",
        )

    with c:
        metric_card(
            "Findings",
            len(findings),
            "security findings",
            "red" if findings else "green",
        )

    with d:
        metric_card(
            "Attack Paths",
            len(get_paths(result)),
            "potential paths",
            "purple" if get_paths(result) else "green",
        )

    with e:
        metric_card(
            "ML Risk",
            ml.get("predicted_class", "UNKNOWN"),
            f"{ml.get('confidence', 0) * 100:.2f}% confidence",
            "red" if ml.get("predicted_class") == "CRITICAL" else "yellow",
        )

    st.markdown("<br>", unsafe_allow_html=True)

    summary = result.get("scan_summary", {})

    if summary:
        st.markdown("### Scan Coverage")

        x, y, z, w = st.columns(4)

        with x:
            metric_card(
                "Runtime",
                summary.get("runtime_findings", 0),
                "findings",
                "blue",
            )

        with y:
            metric_card(
                "Dockerfile",
                summary.get("dockerfile_findings", 0),
                "findings",
                "blue",
            )

        with z:
            metric_card(
                "Compose",
                summary.get("compose_findings", 0),
                "findings",
                "blue",
            )

        with w:
            metric_card(
                "Total",
                summary.get("total_findings", 0),
                "findings",
                "red" if summary.get("total_findings", 0) else "green",
            )

    st.markdown("<br>", unsafe_allow_html=True)

    tabs = st.tabs(
        [
            "FINDINGS",
            "RISK",
            "COMPLIANCE",
            "CORRELATIONS",
            "ATTACK PATHS",
            "REMEDIATION",
            "ML",
        ]
    )

    with tabs[0]:
        render_findings(result, key="full_scan_findings")

    with tabs[1]:
        render_risk(result)

    with tabs[2]:
        render_compliance(result)

    with tabs[3]:
        render_correlations(result)

    with tabs[4]:
        render_attack_paths(result)

    with tabs[5]:
        render_remediation(result)

    with tabs[6]:
        render_ml(result)


# -------------------------------------------------------------------
# PAGE
# -------------------------------------------------------------------

def render(api):
    st.markdown(
        """
        <div class="page-hero">
            <div class="hero-eyebrow">
                SECURITY OPERATIONS / UNIFIED ANALYSIS
            </div>
            <h1>Scan Center</h1>
            <p>
                Run one complete DockerShield security assessment across
                the Docker runtime, Dockerfile and Compose configuration.
                The same backend pipeline powers the CLI, API and dashboard.
            </p>
        </div>
        """,
        unsafe_allow_html=True,
    )

    st.markdown(
        """
        <div class="workspace">
            <div class="workspace-header">
                <div>
                    <div class="workspace-title">
                        FULL SECURITY ASSESSMENT
                    </div>
                    <div class="workspace-subtitle">
                        Runtime + Dockerfile + Compose + risk intelligence
                    </div>
                </div>
            </div>
            <div class="workspace-body">
        """,
        unsafe_allow_html=True,
    )

    _pipeline()

    st.markdown(
        """
        <div class="target-card">
            <div class="target-icon">◈</div>
            <div class="target-name">
                Unified Docker Environment Scan
            </div>
            <div class="target-description">
                Scans running Docker containers, the project Dockerfile and
                the selected Compose configuration, then performs risk,
                ML, compliance, correlation, attack-path and remediation
                analysis.
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    st.markdown("<br>", unsafe_allow_html=True)

    compose_path = st.text_input(
        "COMPOSE TARGET",
        value="test-data/vulnerable/compose.yml",
        help="Docker Compose file used by the full security scan.",
    )

    dockerfile_path = st.text_input(
        "DOCKERFILE TARGET",
        value="test-data/Dockerfile",
        help="Dockerfile used by the full security scan.",
    )

    st.markdown("<br>", unsafe_allow_html=True)

    if st.button(
        "▶  RUN FULL SECURITY SCAN",
        type="primary",
        use_container_width=True,
        key="run_full_scan",
    ):
        # The current API client accepts these paths through full_scan().
        result = None

        progress = st.progress(0)
        status = st.empty()

        try:
            status.write("Preparing Docker environment discovery...")
            progress.progress(10)

            status.write("Running complete DockerShield scan...")
            progress.progress(25)

            result = api.full_scan(
                compose_path=compose_path.strip(),
                dockerfile_path=dockerfile_path.strip(),
            )

            status.write("Processing security intelligence...")
            progress.progress(75)

            set_scan(
                result,
                "full",
                "Docker runtime + Dockerfile + Docker Compose",
            )

            progress.progress(100)
            status.success(
                "Full DockerShield security analysis completed."
            )

        except Exception as exc:
            progress.empty()
            status.empty()
            st.error(f"Full scan failed: {exc}")

    st.markdown(
        """
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    # ---------------------------------------------------------------
    # Latest result
    # ---------------------------------------------------------------

    if st.session_state.get("scan_data"):
        st.markdown("<br>", unsafe_allow_html=True)

        st.markdown(
            "**LATEST FULL ANALYSIS** · "
            f"`{st.session_state.get('scan_target', '')}`"
        )

        _render_results(st.session_state.scan_data)