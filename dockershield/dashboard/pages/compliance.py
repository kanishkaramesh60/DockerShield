from __future__ import annotations

import streamlit as st

from dockershield.dashboard.components.cards import (
    metric_card,
    section_header,
)
from dockershield.dashboard.state import require_scan


def render_compliance(scan: dict):
    compliance = scan.get("compliance", {})
    controls = compliance.get("controls", [])

    pct = compliance.get("compliance_percentage", 100)

    a, b, c, d = st.columns(4)
    with a:
        metric_card(
            "Compliance", f"{pct}%", "of controls passing",
            "green" if pct >= 80 else "yellow" if pct >= 50 else "red",
        )
    with b:
        metric_card(
            "Controls Checked",
            compliance.get("total_controls", 0),
            "CIS Docker Benchmark",
            "blue",
        )
    with c:
        metric_card("Passed", compliance.get("passed", 0), "controls", "green")
    with d:
        metric_card(
            "Failed", compliance.get("failed", 0), "controls",
            "red" if compliance.get("failed", 0) else "green",
        )

    st.progress(min(max(float(pct) / 100, 0.0), 1.0))

    st.markdown("<br>", unsafe_allow_html=True)
    section_header("Control Status", "Result of each CIS control.")

    for control in controls:
        passed = control.get("status") == "PASS"

        with st.container(border=True):
            c1, c2, c3 = st.columns([1.2, 5, 1.5])

            with c1:
                st.markdown(f"`{control.get('control_id')}`")

            with c2:
                st.markdown(f"**{control.get('title')}**")
                st.caption(
                    "Rules: " + ", ".join(control.get("rule_ids", []))
                )

            with c3:
                tag = "pass-tag" if passed else "fail-tag"
                st.markdown(
                    f'<span class="{tag}">{control.get("status")}</span>'
                    f'<span class="kv"> · '
                    f'{control.get("finding_count", 0)} finding(s)</span>',
                    unsafe_allow_html=True,
                )


def render(api):
    section_header(
        "Compliance",
        "CIS-aligned control assessment for the latest scan.",
    )

    scan = require_scan()
    if scan:
        render_compliance(scan)
