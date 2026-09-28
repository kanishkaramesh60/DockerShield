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
from dockershield.dashboard.state import get_paths, get_remediations, set_scan


def _pipeline():
    steps = [
        "DISCOVERY",
        "INSPECTION",
        "RULE ENGINE",
        "RISK",
        "ATTACK PATH",
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


def _run_scan(label: str, scan_type: str, target: str, fn):
    """Run a scan with a progress bar and store the result."""

    progress = st.progress(0)
    status = st.empty()

    try:
        status.write(f"Preparing {label}...")
        progress.progress(20)
        time.sleep(0.15)

        status.write("Running DockerShield security rules...")
        progress.progress(50)

        result = fn()

        status.write("Calculating risk, compliance and attack paths...")
        progress.progress(85)
        time.sleep(0.15)

        progress.progress(100)

        set_scan(result, scan_type, target)

        status.success("Security analysis completed.")

    except Exception as exc:
        progress.empty()
        status.empty()
        st.error(f"Scan failed: {exc}")


def _runtime(api):
    with st.container(border=True):
        st.markdown("**RUNTIME CONTAINER** — analyze live Docker containers")

        try:
            containers = api.containers()
        except Exception as exc:
            st.error(f"Could not list containers: {exc}")
            return

        names = [c.get("name") for c in containers if c.get("name")]

        if not names:
            st.warning("No Docker containers are currently available.")
            return

        running = [c for c in containers if c.get("status") == "running"]

        mode = st.radio(
            "MODE",
            ["Single container", "All running containers"],
            horizontal=True,
        )

        _pipeline()

        if mode == "Single container":
            name = st.selectbox("TARGET CONTAINER", names)

            selected = next(
                (c for c in containers if c.get("name") == name),
                {},
            )

            st.caption(
                f"ID: `{selected.get('id', 'unknown')}` · "
                f"STATUS: `{selected.get('status', 'unknown')}` · "
                f"IMAGE: `{selected.get('image', 'unknown')}`"
            )

            if st.button(
                "▶  START SECURITY SCAN",
                type="primary",
                use_container_width=True,
                key="run_runtime",
            ):
                _run_scan(
                    "container inspection",
                    "runtime",
                    name,
                    lambda: api.runtime_scan(name),
                )

        else:
            st.caption(
                f"{len(running)} running container(s) will be scanned and "
                "combined (same as the CLI `scan` command)."
            )

            if st.button(
                "▶  SCAN ALL RUNNING CONTAINERS",
                type="primary",
                use_container_width=True,
                key="run_runtime_all",
                disabled=not running,
            ):
                _run_scan(
                    "container inspection",
                    "runtime",
                    f"all running containers ({len(running)})",
                    api.runtime_scan_all,
                )


def _file_scan(api, scan_type, title, subtitle, default_path, fn):
    with st.container(border=True):
        st.markdown(f"**{title}** — {subtitle}")

        path = st.text_input(
            "TARGET FILE",
            value=default_path,
            key=f"path_{scan_type}",
        )

        _pipeline()

        if st.button(
            "▶  START SECURITY SCAN",
            type="primary",
            use_container_width=True,
            key=f"run_{scan_type}",
        ):
            if not path.strip():
                st.error("A target path is required.")
                return

            _run_scan(
                "target configuration",
                scan_type,
                path.strip(),
                lambda: fn(path.strip()),
            )


def _render_results(result: dict):
    findings = result.get("findings", [])
    risk = result.get("risk", {})
    compliance = result.get("compliance", {})

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
            "green",
        )
    with c:
        metric_card("Findings", len(findings), "security findings", "blue")
    with d:
        metric_card(
            "Attack Paths",
            len(get_paths(result)),
            "potential paths",
            "purple",
        )
    with e:
        metric_card(
            "Remediation",
            len(get_remediations(result)),
            "recommended actions",
            "yellow",
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
        render_findings(result, key="scan_findings")
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


def render(api):
    st.markdown(
        """
        <div class="page-hero">
            <div class="hero-eyebrow">
                SECURITY OPERATIONS / ANALYSIS WORKBENCH
            </div>
            <h1>Scan Center</h1>
            <p>
                Inspect Docker runtime environments, image build definitions
                and Compose deployments through the unified DockerShield
                security analysis pipeline.
            </p>
        </div>
        """,
        unsafe_allow_html=True,
    )

    target = st.radio(
        "Analysis target",
        ["Runtime Container", "Dockerfile", "Docker Compose"],
        horizontal=True,
    )

    st.markdown("<br>", unsafe_allow_html=True)

    if target == "Runtime Container":
        _runtime(api)

    elif target == "Dockerfile":
        _file_scan(
            api,
            "dockerfile",
            "DOCKERFILE",
            "inspect build instructions and image configuration",
            "test-data/Dockerfile",
            api.dockerfile_scan,
        )

    else:
        _file_scan(
            api,
            "compose",
            "DOCKER COMPOSE",
            "inspect privileges, namespaces, capabilities, mounts and limits",
            "test-data/compose.yml",
            api.compose_scan,
        )

    if st.session_state.get("scan_data"):
        st.markdown("<br>", unsafe_allow_html=True)

        st.markdown(
            f"**LATEST ANALYSIS / "
            f"{st.session_state.get('scan_type', 'unknown').upper()}** "
            f"· `{st.session_state.get('scan_target', '')}`"
        )

        _render_results(st.session_state.scan_data)
