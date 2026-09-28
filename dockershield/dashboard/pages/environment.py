from __future__ import annotations

import streamlit as st

from dockershield.dashboard.components.cards import (
    metric_card,
    section_header,
)
from dockershield.docker_client import try_get_client


def render(api):
    section_header(
        "Docker Environment",
        "Equivalent of the CLI doctor and discover commands.",
    )

    client = try_get_client()

    if client is None:
        st.error(
            "[ERROR] Docker health check failed. Could not connect to "
            "Docker Engine. Make sure Docker Desktop is running."
        )
        return

    st.success("[OK] Docker Engine is reachable. DockerShield is ready.")

    try:
        version = client.version()
        info = client.info()
    except Exception as exc:
        st.error(f"Environment discovery failed: {exc}")
        return

    section_header("Docker Engine", "")
    a, b, c, d = st.columns(4)
    with a:
        metric_card("Version", version.get("Version", "Unknown"), "", "blue")
    with b:
        metric_card("API Version", version.get("ApiVersion", "Unknown"), "", "blue")
    with c:
        metric_card("OS", version.get("Os", "Unknown"), "", "purple")
    with d:
        metric_card("Architecture", version.get("Arch", "Unknown"), "", "purple")

    st.markdown("<br>", unsafe_allow_html=True)
    section_header("Docker Host", "")
    a, b, c, d, e = st.columns(5)
    with a:
        metric_card("Containers", info.get("Containers", "Unknown"), "", "blue")
    with b:
        metric_card("Running", info.get("ContainersRunning", "Unknown"), "", "green")
    with c:
        metric_card("Paused", info.get("ContainersPaused", "Unknown"), "", "yellow")
    with d:
        metric_card("Stopped", info.get("ContainersStopped", "Unknown"), "", "red")
    with e:
        metric_card("Images", info.get("Images", "Unknown"), "", "blue")

    st.markdown("<br>", unsafe_allow_html=True)
    section_header("Storage & System", "")
    a, b, c = st.columns(3)
    with a:
        metric_card("Storage Driver", info.get("Driver", "Unknown"), "", "purple")
    with b:
        metric_card("CPUs", info.get("NCPU", "Unknown"), "", "blue")
    with c:
        mem = info.get("MemTotal")
        metric_card(
            "Memory",
            f"{mem / 1024**3:.1f} GB" if isinstance(mem, int) else "Unknown",
            f"{mem} bytes" if mem else "",
            "blue",
        )
