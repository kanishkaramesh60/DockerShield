from __future__ import annotations

from pathlib import Path

import streamlit as st
import streamlit.components.v1 as components

from dockershield.dashboard.components.cards import section_header
from dockershield.dashboard.state import findings_as_objects, require_scan


def render(api):
    section_header(
        "Reports",
        "Generate the same standalone HTML report as the CLI report "
        "command.",
    )

    scan = require_scan()

    if not scan:
        return

    output = st.text_input("OUTPUT PATH", value="data/report.html")

    if st.button(
        "▣  GENERATE HTML REPORT",
        type="primary",
        use_container_width=True,
    ):
        try:
            path = api.generate_report(
                findings_as_objects(scan),
                output.strip() or "data/report.html",
            )
            st.session_state.report_path = path
            st.success(f"[OK] HTML security report generated: {path}")
        except Exception as exc:
            st.error(f"Report generation failed: {exc}")

    path = st.session_state.get("report_path")

    if path and Path(path).exists():
        html = Path(path).read_text(encoding="utf-8")

        st.download_button(
            "⬇  Download report",
            html,
            file_name=Path(path).name,
            mime="text/html",
            use_container_width=True,
        )

        st.markdown("<br>", unsafe_allow_html=True)
        section_header("Preview", "")
        components.html(html, height=900, scrolling=True)
