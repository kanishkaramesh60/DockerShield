from __future__ import annotations

from pathlib import Path

import streamlit as st
import streamlit.components.v1 as components

from dockershield.dashboard.components.cards import section_header
from dockershield.dashboard.state import findings_as_objects, require_scan


def render(api):
    section_header(
        "Reports",
        "Generate and preview the standalone DockerShield HTML security report.",
    )

    scan = require_scan()

    if not scan:
        return

    st.markdown(
        """
        Generate a complete security report from the latest scan.

        The report includes findings, deterministic risk scoring,
        XGBoost risk classification, compliance, correlations,
        attack paths, and remediation recommendations.
        """
    )

    output = st.text_input(
        "OUTPUT PATH",
        value="data/report.html",
    )

    if st.button(
        "GENERATE HTML REPORT",
        type="primary",
        use_container_width=True,
    ):
        try:
            findings = findings_as_objects(scan)

            path = api.generate_report(
                findings,
                output.strip() or "data/report.html",
            )

            st.session_state.report_path = str(path)

            st.success(
                f"[OK] HTML security report generated: {path}"
            )

        except Exception as exc:
            st.error(
                f"Report generation failed: {exc}"
            )

    path = st.session_state.get("report_path")

    if not path:
        return

    report_path = Path(path)

    if not report_path.exists():
        st.warning(
            "The previously generated report could not be found."
        )
        return

    st.divider()

    section_header(
        "Report Ready",
        "Download the generated HTML report or preview it below.",
    )

    col1, col2 = st.columns(2)

    with col1:
        st.metric(
            "Report File",
            report_path.name,
        )

    with col2:
        st.metric(
            "Size",
            f"{report_path.stat().st_size / 1024:.1f} KB",
        )

    html = report_path.read_text(
        encoding="utf-8"
    )

    st.download_button(
        "DOWNLOAD HTML REPORT",
        data=html,
        file_name=report_path.name,
        mime="text/html",
        use_container_width=True,
    )

    st.markdown("<br>", unsafe_allow_html=True)

    section_header(
        "Preview",
        "Interactive preview of the generated standalone report.",
    )

    components.html(
        html,
        height=900,
        scrolling=True,
    )