from __future__ import annotations

from datetime import datetime
from typing import Any

import streamlit as st

from dockershield.models import Finding


def set_scan(result: dict, scan_type: str, target: str) -> None:
    """Store the latest scan and append it to the session history."""

    st.session_state.scan_data = result
    st.session_state.scan_type = scan_type
    st.session_state.scan_target = target

    history = st.session_state.setdefault("scan_history", [])

    risk = result.get("risk", {})
    history.append(
        {
            "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "type": scan_type,
            "target": target,
            "score": risk.get("score", 0),
            "level": risk.get("level", "SECURE"),
            "findings": len(result.get("findings", [])),
            "result": result,
        }
    )


def get_scan() -> dict | None:
    return st.session_state.get("scan_data")


def require_scan() -> dict | None:
    """Return the loaded scan, or show an empty state and return None."""

    scan = get_scan()

    if scan:
        target = st.session_state.get("scan_target", "")
        scan_type = st.session_state.get("scan_type", "")
        st.caption(f"Analysis source: `{scan_type}` · `{target}`")
        return scan

    st.markdown(
        """
        <div class="empty-state">
            <div class="empty-icon">◈</div>
            <h2>No scan loaded</h2>
            <p>
                Open <b>Scan Center</b> and run a runtime, Dockerfile
                or Compose scan. Every analysis page will then show
                the same results the DockerShield CLI produces.
            </p>
        </div>
        """,
        unsafe_allow_html=True,
    )
    return None


# ---------------------------------------------------------------
# Normalizers (API returns summary dicts; be tolerant of lists)
# ---------------------------------------------------------------

def _section(scan: dict, key: str, inner: str) -> list[dict]:
    value = scan.get(key)

    if isinstance(value, dict):
        return value.get(inner, [])

    if isinstance(value, list):
        return value

    return []


def get_paths(scan: dict) -> list[dict]:
    return _section(scan, "attack_paths", "paths")


def get_correlations(scan: dict) -> list[dict]:
    return _section(scan, "correlations", "correlations")


def get_remediations(scan: dict) -> list[dict]:
    return _section(scan, "remediations", "remediations")


def summary(scan: dict, key: str) -> dict[str, Any]:
    value = scan.get(key)
    return value if isinstance(value, dict) else {}


def findings_as_objects(scan: dict) -> list[Finding]:
    """Rebuild Finding objects from the API's JSON findings."""

    return [Finding(**item) for item in scan.get("findings", [])]
