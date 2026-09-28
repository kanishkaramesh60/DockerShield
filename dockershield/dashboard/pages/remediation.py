from __future__ import annotations

import streamlit as st

from dockershield.dashboard.components.cards import (
    metric_card,
    section_header,
    severity_badge,
)
from dockershield.dashboard.state import (
    get_remediations,
    require_scan,
    summary,
)


def render_remediation(scan: dict):
    info = summary(scan, "remediations")
    items = get_remediations(scan)

    a, b = st.columns(2)
    with a:
        metric_card(
            "Remediations Available",
            info.get("total", len(items)),
            "recommended actions",
            "blue",
        )
    with b:
        metric_card(
            "Attack-Path Fixes",
            info.get("attack_path_fixes", 0),
            "fixes that break an attack path",
            "red" if info.get("attack_path_fixes", 0) else "green",
        )

    st.markdown("<br>", unsafe_allow_html=True)

    if not items:
        st.success("No remediation recommendations.")
        return

    for item in items:
        with st.container(border=True):
            c1, c2 = st.columns([1, 6])

            with c1:
                severity_badge(item.get("severity", "MEDIUM"))

            with c2:
                st.markdown(
                    f"**{item.get('remediation_id')} · "
                    f"{item.get('rule_id')} — {item.get('title')}**"
                )

            st.markdown(f"**Action:** {item.get('action', '')}")
            st.markdown(f"**Why:** {item.get('rationale', '')}")
            st.markdown(f"**Verify:** {item.get('verification', '')}")

            if item.get("affects_attack_path"):
                st.error("Attack Path Impact: YES")
            else:
                st.caption("Attack Path Impact: NO")


def render(api):
    section_header(
        "Remediation",
        "Prioritised fixes, attack-path fixes first.",
    )

    scan = require_scan()
    if scan:
        render_remediation(scan)
