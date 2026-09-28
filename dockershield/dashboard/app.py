from __future__ import annotations

import streamlit as st

from dockershield.dashboard.api_client import DockerShieldAPI
from dockershield.dashboard.components.cards import status_badge


st.set_page_config(
    page_title="DockerShield SOC",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# -------------------------------------------------------------------
# GLOBAL STATE
# -------------------------------------------------------------------

if "api" not in st.session_state:
    st.session_state.api = DockerShieldAPI()

api = st.session_state.api


# -------------------------------------------------------------------
# GLOBAL CSS
# -------------------------------------------------------------------

st.markdown(
    """
<style>

@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;600&display=swap');

:root {
    --bg: #070b12;
    --panel: #0c121c;
    --panel2: #101824;
    --border: #1c2938;
    --border2: #243447;
    --text: #e6edf5;
    --muted: #8190a5;
    --cyan: #38bdf8;
    --green: #22c55e;
    --yellow: #facc15;
    --orange: #fb923c;
    --red: #ef4444;
    --purple: #a78bfa;
}

html, body, [class*="css"] {
    font-family: 'Inter', sans-serif;
}

.stApp {
    background:
        radial-gradient(circle at 15% 0%, rgba(56,189,248,.055), transparent 28%),
        radial-gradient(circle at 85% 10%, rgba(167,139,250,.045), transparent 25%),
        var(--bg);
    color: var(--text);
}

/* Hide Streamlit chrome */
#MainMenu {
    visibility: hidden;
}

footer {
    visibility: hidden;
}

header {
    background: transparent !important;
}

/* Sidebar */

[data-testid="stSidebar"] {
    background: #080d15;
    border-right: 1px solid var(--border);
}

[data-testid="stSidebar"] > div:first-child {
    padding-top: 1rem;
}

.sidebar-brand {
    padding: 8px 8px 20px 8px;
}

.sidebar-logo {
    width: 42px;
    height: 42px;
    border: 1px solid #24506a;
    background: #0b1b27;
    border-radius: 12px;
    display: flex;
    align-items: center;
    justify-content: center;
    color: var(--cyan);
    font-size: 22px;
    box-shadow: 0 0 25px rgba(56,189,248,.08);
}

.sidebar-title {
    margin-top: 12px;
    font-size: 18px;
    font-weight: 700;
    letter-spacing: -.4px;
}

.sidebar-subtitle {
    color: var(--muted);
    font-family: 'JetBrains Mono', monospace;
    font-size: 10px;
    letter-spacing: 1.4px;
    margin-top: 4px;
}

.nav-label {
    color: #536277;
    font-family: 'JetBrains Mono', monospace;
    font-size: 10px;
    letter-spacing: 1.5px;
    margin: 20px 0 7px 4px;
}

/* Main */

.block-container {
    padding-top: 1.5rem;
    padding-bottom: 3rem;
    max-width: 1600px;
}

/* Top bar */

.topbar {
    height: 58px;
    border-bottom: 1px solid var(--border);
    margin-bottom: 25px;
    display: flex;
    align-items: center;
    justify-content: space-between;
}

.topbar-left {
    color: var(--muted);
    font-family: 'JetBrains Mono', monospace;
    font-size: 11px;
    letter-spacing: .8px;
}

.topbar-right {
    color: #66758a;
    font-family: 'JetBrains Mono', monospace;
    font-size: 10px;
}

/* Hero */

.page-hero {
    border: 1px solid var(--border);
    background:
        linear-gradient(120deg, rgba(56,189,248,.055), transparent 45%),
        linear-gradient(90deg, #0b111a, #0c131e);
    padding: 28px 30px;
    border-radius: 16px;
    margin-bottom: 25px;
    position: relative;
    overflow: hidden;
}

.page-hero:after {
    content: "";
    position: absolute;
    right: -100px;
    top: -100px;
    width: 280px;
    height: 280px;
    border: 1px solid rgba(56,189,248,.08);
    border-radius: 50%;
}

.hero-eyebrow {
    color: var(--cyan);
    font-family: 'JetBrains Mono', monospace;
    font-size: 10px;
    letter-spacing: 2px;
    margin-bottom: 7px;
}

.page-hero h1 {
    margin: 0;
    font-size: 29px;
    letter-spacing: -.8px;
}

.page-hero p {
    color: var(--muted);
    margin: 8px 0 0 0;
    max-width: 800px;
}

/* Scan workspace */

.workspace {
    background: #0a1019;
    border: 1px solid var(--border);
    border-radius: 16px;
    overflow: hidden;
}

.workspace-header {
    padding: 18px 22px;
    border-bottom: 1px solid var(--border);
    display: flex;
    justify-content: space-between;
    align-items: center;
}

.workspace-title {
    font-size: 14px;
    font-weight: 600;
}

.workspace-subtitle {
    color: var(--muted);
    font-size: 11px;
    margin-top: 3px;
}

.workspace-body {
    padding: 24px;
}

/* Target cards */

.target-card {
    background: #0d1520;
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 18px;
    min-height: 130px;
}

.target-card:hover {
    border-color: #31506a;
}

.target-icon {
    color: var(--cyan);
    font-size: 19px;
}

.target-name {
    font-weight: 600;
    margin-top: 10px;
}

.target-description {
    color: var(--muted);
    font-size: 11px;
    line-height: 1.5;
    margin-top: 6px;
}

/* Pipeline */

.pipeline {
    display: flex;
    align-items: center;
    margin: 25px 0;
    padding: 18px;
    background: #090f17;
    border: 1px solid var(--border);
    border-radius: 12px;
}

.pipeline-step {
    flex: 1;
    text-align: center;
}

.pipeline-number {
    width: 28px;
    height: 28px;
    margin: auto;
    border-radius: 50%;
    background: #101b28;
    border: 1px solid #294057;
    display: flex;
    align-items: center;
    justify-content: center;
    color: var(--cyan);
    font-family: 'JetBrains Mono', monospace;
    font-size: 11px;
}

.pipeline-label {
    margin-top: 8px;
    color: #8d9aae;
    font-size: 10px;
}

.pipeline-arrow {
    color: #304153;
    font-size: 16px;
}

/* Result metrics */

.result-metric {
    background: #0c131d;
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 17px;
}

.result-label {
    color: #68778b;
    font-family: 'JetBrains Mono', monospace;
    font-size: 9px;
    letter-spacing: 1.2px;
}

.result-value {
    font-size: 25px;
    font-weight: 700;
    margin-top: 7px;
}

.result-sub {
    color: var(--muted);
    font-size: 10px;
    margin-top: 3px;
}

/* Finding */

.finding-row {
    background: #0c131d;
    border: 1px solid var(--border);
    border-radius: 10px;
    padding: 14px 16px;
    margin-bottom: 8px;
}

.finding-rule {
    color: var(--cyan);
    font-family: 'JetBrains Mono', monospace;
    font-size: 10px;
}

.finding-title {
    font-size: 13px;
    font-weight: 600;
    margin-top: 4px;
}

.finding-meta {
    color: var(--muted);
    font-size: 10px;
    margin-top: 4px;
}

/* Status */

.engine-status {
    background: #09131a;
    border: 1px solid #17372b;
    border-radius: 10px;
    padding: 10px 12px;
    margin-top: 20px;
}

.engine-dot {
    color: var(--green);
}

.engine-text {
    color: #8ca49a;
    font-family: 'JetBrains Mono', monospace;
    font-size: 10px;
}

/* Buttons */

.stButton > button {
    border-radius: 9px;
    border: 1px solid #254057;
    background: #0d1a27;
    color: #dce9f5;
    font-weight: 600;
    min-height: 42px;
}

.stButton > button:hover {
    border-color: var(--cyan);
    color: white;
    background: #102333;
}

.stButton > button[kind="primary"] {
    background: #0b2534;
    border-color: #21617e;
}

/* Inputs */

.stTextInput input,
.stSelectbox div[data-baseweb="select"] > div,
.stMultiSelect div[data-baseweb="select"] > div {
    background: #0b121c !important;
    border-color: var(--border) !important;
    color: var(--text) !important;
}

/* Tabs */

.stTabs [data-baseweb="tab-list"] {
    gap: 5px;
    border-bottom: 1px solid var(--border);
}

.stTabs [data-baseweb="tab"] {
    color: #728096;
    font-size: 12px;
}

.stTabs [aria-selected="true"] {
    color: var(--cyan) !important;
}

/* Expander */

.streamlit-expanderHeader {
    background: #0b121b;
    border: 1px solid var(--border);
    border-radius: 9px;
}

/* Dividers */

hr {
    border-color: var(--border) !important;
}

</style>
""",
    unsafe_allow_html=True,
)


# -------------------------------------------------------------------
# NAVIGATION
# -------------------------------------------------------------------

pages = {
    "OPERATIONS": [
        ("⌂", "Overview"),
        ("◈", "Scan Center"),
        ("≡", "Findings"),
    ],
    "ANALYSIS": [
        ("◉", "Risk Analysis"),
        ("✓", "Compliance"),
        ("⌁", "Attack Paths"),
        ("◇", "Correlations"),
    ],
    "RESPONSE": [
        ("↗", "Remediation"),
        ("△", "Simulator"),
    ],
    "INTELLIGENCE": [
        ("◷", "History"),
        ("✦", "ML Analysis"),
        ("▣", "Reports"),
    ],
}


# -------------------------------------------------------------------
# SIDEBAR
# -------------------------------------------------------------------

with st.sidebar:

    st.markdown(
        """
        <div class="sidebar-brand">
            <div class="sidebar-logo">🛡</div>
            <div class="sidebar-title">DockerShield</div>
            <div class="sidebar-subtitle">SECURITY OPERATIONS CENTER</div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    selected_page = None

    for group, items in pages.items():

        st.markdown(
            f'<div class="nav-label">{group}</div>',
            unsafe_allow_html=True,
        )

        for icon, label in items:

            if st.button(
                f"{icon}   {label}",
                key=f"nav_{label}",
                use_container_width=True,
            ):
                st.session_state.current_page = label

    if "current_page" not in st.session_state:
        st.session_state.current_page = "Overview"

    try:
        health = api.health()
        docker_online = health.get("docker", False)
    except Exception:
        docker_online = False

    st.markdown(
        f"""
        <div class="engine-status">
            <div class="engine-text">
                <span class="engine-dot">●</span>
                DOCKER ENGINE
                <strong>{"ONLINE" if docker_online else "OFFLINE"}</strong>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )


# -------------------------------------------------------------------
# TOP BAR
# -------------------------------------------------------------------

current_page = st.session_state.current_page

st.markdown(
    f"""
    <div class="topbar">
        <div class="topbar-left">
            DOCKERSHIELD / {current_page.upper()}
        </div>
        <div class="topbar-right">
            SECURITY ANALYSIS PLATFORM
        </div>
    </div>
    """,
    unsafe_allow_html=True,
)


# -------------------------------------------------------------------
# PAGE ROUTING
# -------------------------------------------------------------------

if current_page == "Overview":
    from dockershield.dashboard.pages.overview import render
    render(api)

elif current_page == "Scan Center":
    from dockershield.dashboard.pages.scan import render
    render(api)

elif current_page == "Findings":
    from dockershield.dashboard.pages.findings import render
    render(api)

elif current_page == "Risk Analysis":
    from dockershield.dashboard.pages.risk import render
    render(api)

elif current_page == "Compliance":
    from dockershield.dashboard.pages.compliance import render
    render(api)

elif current_page == "Attack Paths":
    from dockershield.dashboard.pages.attack_paths import render
    render(api)

elif current_page == "Correlations":
    from dockershield.dashboard.pages.correlations import render
    render(api)

elif current_page == "Remediation":
    from dockershield.dashboard.pages.remediation import render
    render(api)

elif current_page == "Simulator":
    from dockershield.dashboard.pages.simulator import render
    render(api)

elif current_page == "History":
    from dockershield.dashboard.pages.history import render
    render(api)

elif current_page == "ML Analysis":
    from dockershield.dashboard.pages.ml import render
    render(api)

elif current_page == "Reports":
    from dockershield.dashboard.pages.reports import render
    render(api)