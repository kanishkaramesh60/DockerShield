from __future__ import annotations

import time

import streamlit as st


def _metric(label: str, value: str, subtitle: str = ""):
    st.markdown(
        f"""
        <div class="result-metric">
            <div class="result-label">{label}</div>
            <div class="result-value">{value}</div>
            <div class="result-sub">{subtitle}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def _pipeline():
    steps = [
        "DISCOVERY",
        "INSPECTION",
        "RULE ENGINE",
        "RISK",
        "ATTACK PATH",
    ]

    html = '<div class="pipeline">'

    for index, step in enumerate(steps):

        html += f"""
        <div class="pipeline-step">
            <div class="pipeline-number">{index + 1}</div>
            <div class="pipeline-label">{step}</div>
        </div>
        """

        if index < len(steps) - 1:
            html += '<div class="pipeline-arrow">→</div>'

    html += "</div>"

    st.markdown(html, unsafe_allow_html=True)


def _finding_card(finding: dict):

    severity = finding.get("severity", "UNKNOWN").upper()

    severity_class = {
        "CRITICAL": "red",
        "HIGH": "orange",
        "MEDIUM": "yellow",
        "LOW": "blue",
    }.get(severity, "blue")

    st.markdown(
        f"""
        <div class="finding-row">
            <div class="finding-rule">
                {finding.get("rule_id", "UNKNOWN")}
                &nbsp; / &nbsp;
                <span style="color:{{
                    "red":"#ef4444",
                    "orange":"#fb923c",
                    "yellow":"#facc15",
                    "blue":"#38bdf8"
                }}['{severity_class}']">
                    {severity}
                </span>
            </div>

            <div class="finding-title">
                {finding.get("title", "Security finding")}
            </div>

            <div class="finding-meta">
                {finding.get("container", "N/A")}
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def _render_results(result: dict):

    st.markdown(
        """
        <div class="workspace">
            <div class="workspace-header">
                <div>
                    <div class="workspace-title">SCAN RESULTS</div>
                    <div class="workspace-subtitle">
                        DockerShield security analysis output
                    </div>
                </div>
            </div>
            <div class="workspace-body">
        """,
        unsafe_allow_html=True,
    )

    risk = result.get("risk", {})
    compliance = result.get("compliance", {})
    findings = result.get("findings", [])
    paths = result.get("attack_paths", [])
    correlations = result.get("correlations", [])
    remediations = result.get("remediations", [])

    a, b, c, d, e = st.columns(5)

    with a:
        _metric(
            "RISK SCORE",
            f"{risk.get('score', 0)}/100",
            risk.get("level", "SECURE"),
        )

    with b:
        _metric(
            "COMPLIANCE",
            f"{compliance.get('compliance_percentage', 100)}%",
            f"{compliance.get('passed', 0)} controls passing",
        )

    with c:
        _metric(
            "FINDINGS",
            str(len(findings)),
            "security findings",
        )

    with d:
        _metric(
            "ATTACK PATHS",
            str(len(paths)),
            "potential paths",
        )

    with e:
        _metric(
            "REMEDIATION",
            str(len(remediations)),
            "recommended actions",
        )

    st.markdown("<br>", unsafe_allow_html=True)

    tabs = st.tabs(
        [
            "FINDINGS",
            "ATTACK PATHS",
            "CORRELATIONS",
            "REMEDIATION",
        ]
    )

    with tabs[0]:

        if not findings:
            st.success("No security findings detected.")

        else:

            severity_filter = st.multiselect(
                "Severity",
                ["CRITICAL", "HIGH", "MEDIUM", "LOW"],
                default=[
                    "CRITICAL",
                    "HIGH",
                    "MEDIUM",
                    "LOW",
                ],
            )

            search = st.text_input(
                "Search",
                placeholder="Search rule, title, container or evidence...",
            )

            search = search.lower().strip()

            for finding in findings:

                severity = finding.get(
                    "severity",
                    "",
                ).upper()

                if severity not in severity_filter:
                    continue

                searchable = " ".join(
                    [
                        str(finding.get("rule_id", "")),
                        str(finding.get("title", "")),
                        str(finding.get("container", "")),
                        str(finding.get("description", "")),
                        str(finding.get("evidence", "")),
                    ]
                ).lower()

                if search and search not in searchable:
                    continue

                _finding_card(finding)

                with st.expander(
                    f"View {finding.get('rule_id', 'finding')} details"
                ):

                    st.markdown("**Description**")
                    st.write(
                        finding.get(
                            "description",
                            "No description.",
                        )
                    )

                    st.markdown("**Evidence**")
                    st.code(
                        finding.get(
                            "evidence",
                            "No evidence.",
                        )
                    )

                    st.markdown("**Impact**")
                    st.write(
                        finding.get(
                            "impact",
                            "No impact information.",
                        )
                    )

                    st.markdown("**Remediation**")
                    st.write(
                        finding.get(
                            "remediation",
                            "No remediation information.",
                        )
                    )

    with tabs[1]:

        if not paths:
            st.success("No attack paths identified.")

        for path in paths:

            with st.container(border=True):

                st.markdown(
                    f"### {path.get('path_id', 'PATH-???')}"
                )

                st.write(
                    path.get(
                        "title",
                        "Potential attack path",
                    )
                )

                st.caption(
                    f"Severity: "
                    f"{path.get('severity', 'UNKNOWN')}"
                )

                if path.get("description"):
                    st.write(path["description"])

                if path.get("rule_ids"):
                    st.caption(
                        "Rules: "
                        + ", ".join(path["rule_ids"])
                    )

    with tabs[2]:

        if not correlations:
            st.success("No correlations identified.")

        for correlation in correlations:

            with st.container(border=True):

                st.markdown(
                    f"### "
                    f"{correlation.get('correlation_id', 'CORR-???')}"
                )

                st.write(
                    correlation.get(
                        "title",
                        "Security correlation",
                    )
                )

                st.caption(
                    f"Severity: "
                    f"{correlation.get('severity', 'UNKNOWN')}"
                )

                if correlation.get("description"):
                    st.write(
                        correlation["description"]
                    )

    with tabs[3]:

        if not remediations:
            st.success("No remediation actions required.")

        for remediation in remediations:

            with st.container(border=True):

                st.markdown(
                    f"### "
                    f"{remediation.get('remediation_id', 'REM-???')}"
                )

                st.write(
                    remediation.get(
                        "title",
                        "Remediation",
                    )
                )

                st.caption(
                    f"Priority: "
                    f"{remediation.get('priority', 'UNKNOWN')}"
                )

                if remediation.get("description"):
                    st.write(
                        remediation["description"]
                    )

                if remediation.get("reason"):
                    st.info(
                        remediation["reason"]
                    )

    st.markdown(
        """
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def _runtime(api):

    st.markdown(
        """
        <div class="workspace">
            <div class="workspace-header">
                <div>
                    <div class="workspace-title">
                        RUNTIME CONTAINER
                    </div>
                    <div class="workspace-subtitle">
                        Analyze a live Docker container
                    </div>
                </div>
            </div>
            <div class="workspace-body">
        """,
        unsafe_allow_html=True,
    )

    containers = api.containers()

    if not containers:
        st.warning(
            "No Docker containers are currently available."
        )

        st.markdown("</div></div>", unsafe_allow_html=True)
        return

    names = []

    for container in containers:

        name = (
            container.get("name")
            or container.get("Names")
        )

        if name:
            names.append(name)

    if not names:
        st.warning("Docker returned no usable containers.")
        return

    container_name = st.selectbox(
        "TARGET CONTAINER",
        names,
    )

    selected = next(
        (
            container
            for container in containers
            if (
                container.get("name")
                or container.get("Names")
            ) == container_name
        ),
        {},
    )

    st.caption(
        f"ID: `{selected.get('id', selected.get('Id', 'unknown'))}` "
        f" · STATUS: `{selected.get('status', 'unknown')}`"
    )

    _pipeline()

    if st.button(
        "▶  START SECURITY SCAN",
        type="primary",
        use_container_width=True,
    ):

        progress = st.progress(0)
        status = st.empty()

        status.write("Initializing Docker inspection...")
        progress.progress(15)

        time.sleep(.2)

        status.write("Collecting container configuration...")
        progress.progress(35)

        time.sleep(.2)

        status.write("Running DockerShield security rules...")
        progress.progress(55)

        try:

            result = api.runtime_scan(
                container_name
            )

            status.write(
                "Calculating risk and attack paths..."
            )
            progress.progress(80)

            time.sleep(.2)

            progress.progress(100)

            st.session_state.scan_data = result
            st.session_state.scan_type = "runtime"
            st.session_state.scan_target = container_name

            status.success(
                "Security analysis completed."
            )

        except Exception as exc:

            progress.empty()

            st.error(
                f"Runtime scan failed: {exc}"
            )

    st.markdown(
        """
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def _file_scan(
    api,
    scan_type: str,
    title: str,
    subtitle: str,
    default_path: str,
    scan_function,
):

    st.markdown(
        f"""
        <div class="workspace">
            <div class="workspace-header">
                <div>
                    <div class="workspace-title">
                        {title}
                    </div>
                    <div class="workspace-subtitle">
                        {subtitle}
                    </div>
                </div>
            </div>
            <div class="workspace-body">
        """,
        unsafe_allow_html=True,
    )

    path = st.text_input(
        "TARGET FILE",
        value=default_path,
    )

    _pipeline()

    if st.button(
        "▶  START SECURITY SCAN",
        type="primary",
        use_container_width=True,
    ):

        if not path.strip():

            st.error(
                "A target path is required."
            )

            return

        progress = st.progress(0)
        status = st.empty()

        try:

            status.write(
                "Opening target configuration..."
            )
            progress.progress(20)

            time.sleep(.2)

            status.write(
                "Executing DockerShield rules..."
            )
            progress.progress(45)

            result = scan_function(
                path.strip()
            )

            status.write(
                "Building security analysis..."
            )
            progress.progress(80)

            time.sleep(.2)

            progress.progress(100)

            st.session_state.scan_data = result
            st.session_state.scan_type = scan_type
            st.session_state.scan_target = path.strip()

            status.success(
                "Security analysis completed."
            )

        except Exception as exc:

            progress.empty()

            st.error(
                f"Scan failed: {exc}"
            )

    st.markdown(
        """
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def render(api):

    st.markdown(
        """
        <div class="page-hero">
            <div class="hero-eyebrow">
                SECURITY OPERATIONS / ANALYSIS WORKBENCH
            </div>

            <h1>Scan Center</h1>

            <p>
                Inspect Docker runtime environments, image build definitions
                and Compose deployments through the unified DockerShield
                security analysis pipeline.
            </p>
        </div>
        """,
        unsafe_allow_html=True,
    )

    # ---------------------------------------------------------------
    # TARGET TYPE
    # ---------------------------------------------------------------

    st.markdown(
        """
        <div style="
            color:#68778b;
            font-family:'JetBrains Mono';
            font-size:10px;
            letter-spacing:1.5px;
            margin-bottom:10px;">
            SELECT ANALYSIS TARGET
        </div>
        """,
        unsafe_allow_html=True,
    )

    target = st.radio(
        "Target",
        [
            "Runtime Container",
            "Dockerfile",
            "Docker Compose",
        ],
        horizontal=True,
        label_visibility="collapsed",
    )

    st.markdown("<br>", unsafe_allow_html=True)

    # ---------------------------------------------------------------
    # SCAN TARGET
    # ---------------------------------------------------------------

    if target == "Runtime Container":

        _runtime(api)

    elif target == "Dockerfile":

        _file_scan(
            api,
            "dockerfile",
            "DOCKERFILE",
            "Inspect Dockerfile build instructions and image configuration.",
            "Dockerfile",
            api.dockerfile_scan,
        )

    else:

        _file_scan(
            api,
            "compose",
            "DOCKER COMPOSE",
            "Inspect service privileges, namespaces, capabilities, mounts and resource limits.",
            "test-data/compose.yml",
            api.compose_scan,
        )

    # ---------------------------------------------------------------
    # LATEST RESULT
    # ---------------------------------------------------------------

    if "scan_data" in st.session_state:

        st.markdown("<br><br>", unsafe_allow_html=True)

        result = st.session_state.scan_data

        st.markdown(
            f"""
            <div style="
                color:#38bdf8;
                font-family:'JetBrains Mono';
                font-size:10px;
                letter-spacing:1.5px;
                margin-bottom:10px;">
                LATEST ANALYSIS / {
                    st.session_state.get(
                        "scan_type",
                        "UNKNOWN"
                    ).upper()
                }
            </div>
            """,
            unsafe_allow_html=True,
        )

        _render_results(result)