from __future__ import annotations

import streamlit as st

from dockershield.dashboard.components.cards import (
    metric_card,
    section_header,
    severity_badge,
)
from dockershield.dashboard.state import (
    get_correlations,
    require_scan,
    summary,
)


def render_correlations(scan: dict):
    info = summary(scan, "correlations")
    items = get_correlations(scan)

    a, b, c = st.columns(3)
    with a:
        metric_card(
            "Correlations Detected",
            info.get("total", len(items)),
            "correlated conditions",
            "purple",
        )
    with b:
        metric_card("Critical", info.get("critical", 0), "correlations", "red")
    with c:
        metric_card("High", info.get("high", 0), "correlations", "orange")

    st.markdown("<br>", unsafe_allow_html=True)

    if not items:
        st.success("No correlated security conditions detected.")
        return

    section_header("Correlated Conditions", "")

    for item in items:
        with st.container(border=True):
            c1, c2 = st.columns([1, 6])

            with c1:
                severity_badge(item.get("severity", "HIGH"))

            with c2:
                st.markdown(
                    f"**{item.get('correlation_id')} — "
                    f"{item.get('title')}**"
                )

            st.write(item.get("description", ""))
            st.caption(
                "Matched rules: "
                + ", ".join(item.get("matched_rules", []))
            )


def render(api):
    section_header(
        "Correlations",
        "Findings that are more serious in combination.",
    )

    scan = require_scan()
    if scan:
        render_correlations(scan)
