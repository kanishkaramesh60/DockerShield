from __future__ import annotations

import streamlit as st

from dockershield.dashboard.components.cards import (
    metric_card,
    section_header,
    severity_badge,
)
from dockershield.dashboard.state import (
    get_paths,
    get_remediations,
    require_scan,
)


def _risk_value(risk: dict) -> str:
    return f"{risk.get('score', 0)}/100"


def _risk_level(risk: dict) -> str:
    return risk.get("level", "SECURE")


def _count(value, key: str) -> int:
    if isinstance(value, dict):
        return len(value.get(key, []))
    if isinstance(value, list):
        return len(value)
    return 0


def _extract_before_after(result: dict):
    """
    Normalize the simulator response into before/after sections.

    The existing simulator returns:
      before
      after
      resolved_attack_paths
      remaining_attack_paths
    """
    before = result.get("before", {})
    after = result.get("after", {})

    return before, after


def _show_comparison(before: dict, after: dict):
    st.markdown("### Security Impact")

    before_risk = before.get("risk", {})
    after_risk = after.get("risk", {})

    before_findings = before.get("findings", [])
    after_findings = after.get("findings", [])

    before_correlations = before.get("correlations", {})
    after_correlations = after.get("correlations", {})

    before_paths = before.get("attack_paths", {})
    after_paths = after.get("attack_paths", {})

    before_compliance = before.get("compliance", {})
    after_compliance = after.get("compliance", {})

    before_compliance_value = before_compliance.get(
        "percentage",
        before_compliance.get("compliance_percentage", 0),
    )

    after_compliance_value = after_compliance.get(
        "percentage",
        after_compliance.get("compliance_percentage", 0),
    )

    columns = st.columns(5)

    with columns[0]:
        metric_card(
            "Risk",
            _risk_value(after_risk),
            f"Before: {_risk_value(before_risk)}",
            "red" if after_risk.get("score", 0) >= 80 else "green",
        )

    with columns[1]:
        metric_card(
            "Findings",
            len(after_findings),
            f"Before: {len(before_findings)}",
            "orange" if len(after_findings) else "green",
        )

    with columns[2]:
        metric_card(
            "Compliance",
            f"{after_compliance_value:.2f}%",
            f"Before: {before_compliance_value:.2f}%",
            "green",
        )

    with columns[3]:
        metric_card(
            "Correlations",
            _count(after_correlations, "correlations"),
            f"Before: {_count(before_correlations, 'correlations')}",
            "purple",
        )

    with columns[4]:
        metric_card(
            "Attack Paths",
            _count(after_paths, "paths"),
            f"Before: {_count(before_paths, 'paths')}",
            "red" if _count(after_paths, "paths") else "green",
        )


def _show_attack_path_changes(result: dict):
    resolved = result.get("resolved_attack_paths", [])
    remaining = result.get("remaining_attack_paths", [])

    section_header(
        "Attack-Path Impact",
        "Shows which attack paths would disappear if the selected remediations were applied.",
    )

    col1, col2 = st.columns(2)

    with col1:
        st.markdown("#### Resolved Attack Paths")

        if resolved:
            for path_id in resolved:
                st.success(f"✓ {path_id}")
        else:
            st.info("No attack paths would be fully resolved.")

    with col2:
        st.markdown("#### Remaining Attack Paths")

        if remaining:
            for path_id in remaining:
                st.warning(f"• {path_id}")
        else:
            st.success("✓ No remaining attack paths.")


def _show_finding_changes(before: dict, after: dict):
    before_findings = {
        finding.get("rule_id"): finding
        for finding in before.get("findings", [])
    }

    after_findings = {
        finding.get("rule_id"): finding
        for finding in after.get("findings", [])
    }

    resolved = [
        rule_id
        for rule_id in before_findings
        if rule_id not in after_findings
    ]

    remaining = list(after_findings.keys())

    section_header(
        "Finding Impact",
        "The simulator removes findings affected by the selected remediation actions.",
    )

    col1, col2 = st.columns(2)

    with col1:
        st.markdown("#### Resolved Findings")

        if resolved:
            for rule_id in resolved:
                finding = before_findings[rule_id]
                st.success(
                    f"✓ {rule_id} — {finding.get('title', 'Resolved finding')}"
                )
        else:
            st.info("No findings would be resolved.")

    with col2:
        st.markdown("#### Remaining Findings")

        if remaining:
            for rule_id in remaining:
                finding = after_findings[rule_id]
                severity = finding.get("severity", "LOW")
                st.markdown(
                    f"{severity_badge(severity)} "
                    f"**{rule_id}** — {finding.get('title', '')}",
                    unsafe_allow_html=True,
                )
        else:
            st.success("✓ No findings would remain.")


def render(api):
    section_header(
        "What-If Remediation Simulator",
        "Simulate remediation changes before modifying the Docker environment.",
    )

    scan = require_scan()

    if not scan:
        return

    st.markdown(
        """
        Select one or more remediation actions to see their projected
        security impact. The simulation is performed in memory and does
        **not** modify your Docker environment.
        """
    )

    remediations = get_remediations(scan)

    if not remediations:
        st.warning("No remediation recommendations are available.")
        return

    compose_path = (
        scan.get("scan_targets", {}).get(
            "compose",
            "test-data\\vulnerable\\compose.yml",
        )
    )

    st.caption(f"Simulation target: `{compose_path}`")

    st.markdown("### Select Remediations")

    options = {}

    for remediation in remediations:
        remediation_id = remediation.get("id")

        if not remediation_id:
            continue

        title = remediation.get(
            "title",
            remediation.get("description", remediation_id),
        )

        priority = remediation.get(
            "priority",
            remediation.get("severity", "MEDIUM"),
        )

        attack_path_impact = remediation.get(
            "attack_path_impact",
            remediation.get("affects_attack_path", False),
        )

        label = f"{remediation_id} — {title} [{priority}]"

        if attack_path_impact:
            label += " • ATTACK PATH"

        options[label] = remediation_id

    selected_labels = st.multiselect(
        "Remediation actions",
        options=list(options.keys()),
        help="Choose one or more remediation actions to simulate.",
    )

    selected_ids = [options[label] for label in selected_labels]

    if not selected_ids:
        st.info(
            "Select at least one remediation to run a what-if simulation."
        )
        return

    st.markdown("### Selected Actions")

    for remediation_id in selected_ids:
        st.success(f"✓ {remediation_id}")

    if st.button(
        "RUN WHAT-IF SIMULATION",
        type="primary",
        use_container_width=True,
    ):
        try:
            with st.spinner("Simulating remediation impact..."):
                result = api.simulate(
                    compose_path,
                    selected_ids,
                )

            st.session_state.simulation_result = result

        except Exception as exc:
            st.error(f"Simulation failed: {exc}")
            return

    result = st.session_state.get("simulation_result")

    if not result:
        return

    st.divider()

    before, after = _extract_before_after(result)

    if not before or not after:
        st.error(
            "The simulator returned an unexpected response. "
            "Expected before/after analysis results."
        )
        return

    section_header(
        "Simulation Result",
        "Projected security posture after applying the selected remediations.",
    )

    _show_comparison(before, after)

    st.divider()

    _show_attack_path_changes(result)

    st.divider()

    _show_finding_changes(before, after)

    st.divider()

    section_header(
        "Selected Remediations",
        "Actions included in this simulation.",
    )

    for remediation_id in selected_ids:
        st.markdown(f"- **{remediation_id}**")

    st.caption(
        "Simulation only. Docker containers, images, Compose files, "
        "and the host environment were not modified."
    )