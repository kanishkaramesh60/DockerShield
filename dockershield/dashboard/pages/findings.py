from __future__ import annotations

import csv
import io
import json

import streamlit as st

from dockershield.dashboard.components.cards import (
    finding_card,
    metric_card,
    section_header,
)
from dockershield.dashboard.state import require_scan

SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]


def render_findings(scan: dict, key: str = "findings"):
    findings = scan.get("findings", [])

    # CLI "SECURITY SUMMARY"
    counts = {s: 0 for s in SEVERITIES}
    for item in findings:
        sev = str(item.get("severity", "")).upper()
        if sev in counts:
            counts[sev] += 1

    cols = st.columns(5)
    accents = ["red", "orange", "yellow", "blue", "purple"]
    for col, (label, value), accent in zip(
        cols,
        [*counts.items(), ("TOTAL", len(findings))],
        accents,
    ):
        with col:
            metric_card(label, value, "findings", accent)

    st.markdown("<br>", unsafe_allow_html=True)

    if not findings:
        st.success("[OK] No security findings detected.")
        return

    st.warning(f"[!] {len(findings)} security finding(s) detected.")

    left, right = st.columns([2, 3])

    with left:
        chosen = st.multiselect(
            "Severity",
            SEVERITIES,
            default=SEVERITIES,
            key=f"{key}_sev",
        )

    with right:
        query = st.text_input(
            "Search",
            placeholder="Search rule, title, container or evidence...",
            key=f"{key}_search",
        ).lower().strip()

    shown = 0

    for item in findings:
        severity = str(item.get("severity", "")).upper()

        if severity not in chosen:
            continue

        haystack = " ".join(
            str(item.get(k, ""))
            for k in (
                "rule_id", "title", "container",
                "description", "evidence",
            )
        ).lower()

        if query and query not in haystack:
            continue

        finding_card(item)
        shown += 1

    st.caption(f"Showing {shown} of {len(findings)} finding(s).")

    # Export
    buffer = io.StringIO()
    writer = csv.DictWriter(
        buffer,
        fieldnames=[
            "rule_id", "severity", "title", "container",
            "description", "evidence", "impact", "remediation",
        ],
    )
    writer.writeheader()
    writer.writerows(findings)

    d1, d2 = st.columns(2)
    with d1:
        st.download_button(
            "Download findings (CSV)",
            buffer.getvalue(),
            "dockershield_findings.csv",
            "text/csv",
            key=f"{key}_csv",
            use_container_width=True,
        )
    with d2:
        st.download_button(
            "Download findings (JSON)",
            json.dumps(findings, indent=2),
            "dockershield_findings.json",
            "application/json",
            key=f"{key}_json",
            use_container_width=True,
        )


def render(api):
    section_header(
        "Findings",
        "All security findings from the latest scan.",
    )

    scan = require_scan()
    if scan:
        render_findings(scan)
