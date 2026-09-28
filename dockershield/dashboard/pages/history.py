from __future__ import annotations

import streamlit as st

from dockershield.dashboard.components.cards import (
    metric_card,
    section_header,
)
from dockershield.dashboard.state import findings_as_objects


def _baseline_section(api):
    section_header(
        "Security Baseline",
        "Save the loaded scan as the baseline, then compare later scans "
        "against it (same engine as the CLI baseline/compare commands).",
    )

    scan = st.session_state.get("scan_data")

    if not scan:
        st.info("Run a scan first to save or compare a baseline.")
        return

    c1, c2 = st.columns(2)

    with c1:
        if st.button(
            "💾  Save current scan as baseline",
            use_container_width=True,
        ):
            try:
                api.save_baseline(findings_as_objects(scan))
                st.success("[OK] Security baseline saved: data/baseline.json")
            except Exception as exc:
                st.error(f"Could not save baseline: {exc}")

    with c2:
        compare = st.button(
            "⇄  Compare with baseline",
            use_container_width=True,
        )

    if not compare:
        return

    try:
        comparison = api.compare_baseline(findings_as_objects(scan))
    except FileNotFoundError as exc:
        st.error(f"{exc}")
        return
    except Exception as exc:
        st.error(f"Comparison failed: {exc}")
        return

    a, b, c, d = st.columns(4)
    with a:
        metric_card(
            "Baseline Findings", comparison["baseline_findings"],
            "", "blue",
        )
    with b:
        metric_card(
            "Current Findings", comparison["current_findings"],
            "", "blue",
        )
    with c:
        metric_card(
            "Risk Change", f"{comparison['risk_change']:+d}",
            "score delta",
            "red" if comparison["risk_change"] > 0 else "green",
        )
    with d:
        metric_card(
            "Compliance Change",
            f"{comparison['compliance_change']:+.1f}%",
            "",
            "green" if comparison["compliance_change"] >= 0 else "red",
        )

    if comparison["regression"]:
        st.error("Regression: YES — new findings were introduced.")
    else:
        st.success("Regression: NO")

    x, y, z = st.columns(3)

    with x:
        st.markdown(f"**Resolved ({len(comparison['resolved'])})**")
        for item in comparison["resolved"]:
            st.markdown(f"- {item}")

    with y:
        st.markdown(f"**New ({len(comparison['new'])})**")
        for item in comparison["new"]:
            st.markdown(f"- {item}")

    with z:
        st.markdown(f"**Unchanged ({len(comparison['unchanged'])})**")
        for item in comparison["unchanged"]:
            st.markdown(f"- {item}")


def render(api):
    section_header(
        "History",
        "Scans run in this dashboard session, plus baseline tracking.",
    )

    history = st.session_state.get("scan_history", [])

    if not history:
        st.info("No scans yet in this session.")
    else:
        st.dataframe(
            [
                {
                    "Time": item["time"],
                    "Type": item["type"],
                    "Target": item["target"],
                    "Risk": item["score"],
                    "Level": item["level"],
                    "Findings": item["findings"],
                }
                for item in reversed(history)
            ],
            use_container_width=True,
            hide_index=True,
        )

        labels = [
            f"#{i + 1} · {h['time']} · {h['type']} · {h['target']}"
            for i, h in enumerate(history)
        ]

        pick = st.selectbox("Reload a previous scan", labels, index=len(labels) - 1)

        if st.button("Load selected scan"):
            item = history[labels.index(pick)]
            st.session_state.scan_data = item["result"]
            st.session_state.scan_type = item["type"]
            st.session_state.scan_target = item["target"]
            st.success("Scan loaded. Open any analysis page to view it.")

    st.markdown("<br>", unsafe_allow_html=True)
    _baseline_section(api)
