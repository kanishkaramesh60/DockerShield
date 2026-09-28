from __future__ import annotations

import streamlit as st

from dockershield.dashboard.components.cards import (
    metric_card,
    section_header,
)
from dockershield.engine.remediation import REMEDIATION_RULES


def _delta(before, after, unit: str = "") -> str:
    diff = after - before
    return f"{before}{unit} → {after}{unit} ({diff:+g}{unit})"


def render_simulation_result(result: dict):
    before = result["before"]
    after = result["after"]

    st.caption(
        "Remediations: " + ", ".join(result.get("requested_remediations", []))
    )

    a, b, c, d = st.columns(4)

    with a:
        metric_card(
            "Findings",
            f"{before['findings']} → {after['findings']}",
            "before → after",
            "blue",
        )
    with b:
        metric_card(
            "Risk",
            f"{before['risk']['score']} → {after['risk']['score']}",
            f"{before['risk']['level']} → {after['risk']['level']}",
            "green" if after["risk"]["score"] < before["risk"]["score"]
            else "yellow",
        )
    with c:
        metric_card(
            "Compliance",
            f"{before['compliance']['compliance_percentage']}% → "
            f"{after['compliance']['compliance_percentage']}%",
            "controls passing",
            "green",
        )
    with d:
        metric_card(
            "Attack Paths",
            f"{before['attack_paths']['total']} → "
            f"{after['attack_paths']['total']}",
            "before → after",
            "purple",
        )

    st.markdown("<br>", unsafe_allow_html=True)

    left, right = st.columns(2)

    with left:
        section_header("Resolved Attack Paths", "")
        resolved = result.get("resolved_attack_paths", [])
        if resolved:
            for path_id in resolved:
                st.success(path_id)
        else:
            st.info("None")

    with right:
        section_header("Remaining Attack Paths", "")
        remaining = result.get("remaining_attack_paths", [])
        if remaining:
            for path_id in remaining:
                st.warning(path_id)
        else:
            st.success("None")

    st.caption(
        "Rules removed in simulation: "
        + (", ".join(result.get("selected_rule_ids", [])) or "none")
    )


def render(api):
    section_header(
        "Remediation Simulator",
        "What-if analysis. Nothing is modified — files and Docker stay "
        "untouched.",
    )

    scan_type = st.session_state.get("scan_type")
    scan_target = st.session_state.get("scan_target", "")

    default_path = (
        scan_target if scan_type == "compose" else "test-data/compose.yml"
    )

    path = st.text_input("COMPOSE FILE", value=default_path)

    options = {
        f"{rule.remediation_id} · {rule.rule_id} · {rule.title}":
            rule.remediation_id
        for rule in REMEDIATION_RULES
    }

    present = set()
    scan = st.session_state.get("scan_data")
    if scan and scan_type == "compose":
        remediations = scan.get("remediations", {})
        items = (
            remediations.get("remediations", [])
            if isinstance(remediations, dict) else remediations
        )
        present = {item["remediation_id"] for item in items}

    chosen = st.multiselect(
        "REMEDIATIONS TO SIMULATE",
        list(options.keys()),
        default=[label for label, rid in options.items() if rid in present],
    )

    if st.button(
        "▶  RUN SIMULATION",
        type="primary",
        use_container_width=True,
    ):
        if not path.strip():
            st.error("A Compose file path is required.")
            return

        if not chosen:
            st.error("Select at least one remediation.")
            return

        try:
            with st.spinner("Simulating remediation..."):
                st.session_state.simulation = api.simulate(
                    path.strip(),
                    [options[label] for label in chosen],
                )
        except Exception as exc:
            st.session_state.pop("simulation", None)
            st.error(f"Simulation failed: {exc}")

    if "simulation" in st.session_state:
        st.markdown("<br>", unsafe_allow_html=True)
        render_simulation_result(st.session_state.simulation)
