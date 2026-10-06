from __future__ import annotations

import streamlit as st

from dockershield.dashboard.components.attack_graph import (
    render_attack_graph,
)

from dockershield.dashboard.components.cards import (
    chain,
    metric_card,
    section_header,
    severity_badge,
)
from dockershield.dashboard.state import get_paths, require_scan, summary


def render_attack_paths(scan: dict):
    info = summary(scan, "attack_paths")
    paths = get_paths(scan)

    a, b, c = st.columns(3)
    with a:
        metric_card(
            "Attack Paths Detected",
            info.get("total", len(paths)),
            "potential paths",
            "red" if paths else "green",
        )
    with b:
        metric_card("Critical", info.get("critical", 0), "paths", "red")
    with c:
        metric_card("High", info.get("high", 0), "paths", "orange")

    st.markdown("<br>", unsafe_allow_html=True)

    if not paths:
        st.success("No potential attack paths detected.")
        return

    section_header("Potential Attack Paths", "")

    for path in paths:
        with st.container(border=True):
            c1, c2 = st.columns([1, 6])

            with c1:
                severity_badge(path.get("severity", "HIGH"))

            with c2:
                st.markdown(
                    f"**{path.get('path_id')} — {path.get('title')}**"
                )

            st.write(path.get("description", ""))
            st.caption(
                "Matched rules: "
                + ", ".join(path.get("matched_rules", []))
            )
            chain(path.get("steps", []))
    st.markdown("<br>", unsafe_allow_html=True)

    section_header(
        "Attack-Path Visualization",
        "Explore how individual findings combine into potential security impact.",
    )

    render_attack_graph(paths)

def render(api):
    section_header(
        "Attack Paths",
        "Chains of findings that could combine into host impact.",
    )

    scan = require_scan()
    if scan:
        render_attack_paths(scan)
