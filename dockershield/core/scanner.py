from __future__ import annotations

from pathlib import Path
from typing import Any, Iterable

from dockershield.models import Finding

from dockershield.runtime import scan_container
from dockershield.dockerfile import (
    scan_dockerfile as scan_dockerfile_file,
)
from dockershield.compose import (
    scan_compose as scan_compose_file,
)

from dockershield.engine.risk import calculate_risk
from dockershield.engine.compliance import calculate_compliance

from dockershield.engine.correlation import (
    correlate_findings,
    summarize_correlations,
)

from dockershield.engine.attack_path import (
    analyze_attack_paths,
    summarize_attack_paths,
)

from dockershield.engine.remediation import (
    generate_remediations,
)

from dockershield.ml.predict import predict_risk


def _findings_to_dict(
    findings: Iterable[Finding],
) -> list[dict[str, Any]]:
    """
    Convert DockerShield Finding objects into dictionaries
    for API, dashboard and JSON-compatible output.
    """

    return [
        finding.to_dict()
        for finding in findings
    ]


# ============================================================
# CENTRAL ANALYSIS PIPELINE
# ============================================================

def analyze_findings(
    findings: Iterable[Finding],
    scan_type: str,
    target: str,
) -> dict[str, Any]:
    """
    Central DockerShield security-analysis pipeline.

    Shared by:
        - CLI
        - FastAPI
        - Streamlit dashboard

    The actual security logic remains inside the existing
    scanner and engine modules.
    """

    findings = list(findings)

    # --------------------------------------------------------
    # Risk
    # --------------------------------------------------------

    risk = calculate_risk(findings)

    # --------------------------------------------------------
    # ML
    # --------------------------------------------------------

    # ML intentionally runs immediately after deterministic
    # risk scoring.
    try:
        ml_prediction = predict_risk(findings)

    except Exception as exc:
        ml_prediction = {
            "available": False,
            "error": str(exc),
        }

    # --------------------------------------------------------
    # Compliance
    # --------------------------------------------------------

    compliance = calculate_compliance(findings)

    # --------------------------------------------------------
    # Correlation
    # --------------------------------------------------------

    correlations = correlate_findings(findings)

    correlation_summary = summarize_correlations(
        findings
    )

    # --------------------------------------------------------
    # Attack Paths
    # --------------------------------------------------------

    attack_paths = analyze_attack_paths(findings)

    attack_path_summary = summarize_attack_paths(
        findings
    )

    # --------------------------------------------------------
    # Remediation
    # --------------------------------------------------------

    remediations = generate_remediations(
        findings,
        attack_paths=attack_paths,
    )

    # --------------------------------------------------------
    # Unified result
    # --------------------------------------------------------

    return {
        "scan_metadata": {
            "scan_type": scan_type,
            "target": target,
        },

        "findings": _findings_to_dict(
            findings
        ),

        "risk": risk,

        "ml_prediction": ml_prediction,

        "compliance": compliance,

        "correlations": correlations,
        "correlation_summary": correlation_summary,

        "attack_paths": attack_paths,
        "attack_path_summary": attack_path_summary,

        "remediations": remediations,
    }


# ============================================================
# RUNTIME SCAN
# ============================================================

def scan_runtime_target(
    container_name: str,
) -> dict[str, Any]:
    """
    Scan a running Docker container and execute the
    complete DockerShield analysis pipeline.
    """

    from dockershield.docker_client import try_get_client

    client = try_get_client()

    if client is None:
        raise RuntimeError(
            "Docker Engine is unavailable. "
            "Make sure Docker Desktop is running."
        )

    try:
        container = client.containers.get(
            container_name
        )

    except Exception as exc:
        raise RuntimeError(
            f"Could not find Docker container "
            f"'{container_name}': {exc}"
        ) from exc

    findings = scan_container(container)

    return analyze_findings(
        findings=findings,
        scan_type="runtime",
        target=container_name,
    )


# ============================================================
# DOCKERFILE SCAN
# ============================================================

def scan_dockerfile_target(
    file_path: str,
) -> dict[str, Any]:
    """
    Scan a Dockerfile and execute the complete
    DockerShield analysis pipeline.
    """

    path = Path(file_path)

    if not path.exists():
        raise FileNotFoundError(
            f"Dockerfile not found: {path}"
        )

    if not path.is_file():
        raise ValueError(
            f"Dockerfile path is not a file: {path}"
        )

    findings = scan_dockerfile_file(
        str(path)
    )

    return analyze_findings(
        findings=findings,
        scan_type="dockerfile",
        target=str(path),
    )


# ============================================================
# DOCKER COMPOSE SCAN
# ============================================================

def scan_compose_target(
    file_path: str,
) -> dict[str, Any]:
    """
    Scan a Docker Compose file and execute the complete
    DockerShield analysis pipeline.
    """

    path = Path(file_path)

    if not path.exists():
        raise FileNotFoundError(
            f"Compose file not found: {path}"
        )

    if not path.is_file():
        raise ValueError(
            f"Compose path is not a file: {path}"
        )

    findings = scan_compose_file(
        str(path)
    )

    return analyze_findings(
        findings=findings,
        scan_type="compose",
        target=str(path),
    )


# ============================================================
# RUNTIME FINDING COLLECTION
# ============================================================

def collect_runtime_findings() -> list[Finding]:
    """
    Collect findings from all currently running Docker
    containers.

    This uses the same runtime scanner used by the
    normal DockerShield runtime scan.
    """

    from dockershield.docker_client import try_get_client

    client = try_get_client()

    if client is None:
        raise RuntimeError(
            "Docker Engine is unavailable. "
            "Make sure Docker Desktop is running."
        )

    findings: list[Finding] = []

    containers = client.containers.list()

    for container in containers:
        findings.extend(
            scan_container(container)
        )

    return findings


# ============================================================
# DOCKER ENVIRONMENT INFORMATION
# ============================================================

def get_docker_environment() -> dict[str, Any]:
    """
    Collect Docker Engine environment information.

    This is intentionally non-printing so it can be used by:
        - CLI
        - FastAPI
        - Streamlit
    """

    from dockershield.docker_client import try_get_client

    client = try_get_client()

    if client is None:
        raise RuntimeError(
            "Docker Engine is unavailable. "
            "Make sure Docker Desktop is running."
        )

    version = client.version()
    info = client.info()

    return {
        "docker_version": version.get(
            "Version",
            "Unknown",
        ),
        "api_version": version.get(
            "ApiVersion",
            "Unknown",
        ),
        "os": version.get(
            "Os",
            "Unknown",
        ),
        "architecture": version.get(
            "Arch",
            "Unknown",
        ),
        "containers": info.get(
            "Containers",
            0,
        ),
        "running": info.get(
            "ContainersRunning",
            0,
        ),
        "paused": info.get(
            "ContainersPaused",
            0,
        ),
        "stopped": info.get(
            "ContainersStopped",
            0,
        ),
        "images": info.get(
            "Images",
            0,
        ),
        "driver": info.get(
            "Driver",
            "Unknown",
        ),
        "cpus": info.get(
            "NCPU",
            0,
        ),
        "memory": info.get(
            "MemTotal",
            0,
        ),
    }


# ============================================================
# FULL DOCKERSHIELD SCAN
# ============================================================

def run_full_scan(
    compose_path: str = (
        "test-data\\vulnerable\\compose.yml"
    ),
    dockerfile_path: str = (
        "test-data\\Dockerfile"
    ),
) -> dict[str, Any]:
    """
    Run the complete DockerShield security pipeline.

    Pipeline:

        1. Docker environment
        2. Runtime scanner
        3. Dockerfile scanner
        4. Compose scanner
        5. Unified risk scoring
        6. ML risk classification
        7. Compliance analysis
        8. Correlation analysis
        9. Attack-path analysis
        10. Remediation analysis

    IMPORTANT:
        The three scanners here are the existing
        DockerShield scanners. No duplicate scanning
        implementation is created for the dashboard.
    """

    # --------------------------------------------------------
    # 1. Docker environment
    # --------------------------------------------------------

    environment = get_docker_environment()

    # --------------------------------------------------------
    # 2. Runtime scan
    # --------------------------------------------------------

    runtime_findings = collect_runtime_findings()

    # --------------------------------------------------------
    # 3. Dockerfile scan
    # --------------------------------------------------------

    dockerfile_path_obj = Path(
        dockerfile_path
    )

    if not dockerfile_path_obj.exists():
        raise FileNotFoundError(
            f"Dockerfile not found: "
            f"{dockerfile_path_obj}"
        )

    if not dockerfile_path_obj.is_file():
        raise ValueError(
            f"Dockerfile path is not a file: "
            f"{dockerfile_path_obj}"
        )

    dockerfile_findings = scan_dockerfile_file(
        str(dockerfile_path_obj)
    )

    # --------------------------------------------------------
    # 4. Compose scan
    # --------------------------------------------------------

    compose_path_obj = Path(
        compose_path
    )

    if not compose_path_obj.exists():
        raise FileNotFoundError(
            f"Compose file not found: "
            f"{compose_path_obj}"
        )

    if not compose_path_obj.is_file():
        raise ValueError(
            f"Compose path is not a file: "
            f"{compose_path_obj}"
        )

    compose_findings = scan_compose_file(
        str(compose_path_obj)
    )

    # --------------------------------------------------------
    # Combine all scanner results
    # --------------------------------------------------------

    all_findings = (
        runtime_findings
        + dockerfile_findings
        + compose_findings
    )

    # --------------------------------------------------------
    # Run the SAME central analysis pipeline
    # --------------------------------------------------------

    analysis = analyze_findings(
        findings=all_findings,
        scan_type="full",
        target="DockerShield full environment",
    )

    # --------------------------------------------------------
    # Add full-scan metadata
    # --------------------------------------------------------

    analysis["environment"] = environment

    analysis["scan_summary"] = {
        "runtime_findings": len(
            runtime_findings
        ),
        "dockerfile_findings": len(
            dockerfile_findings
        ),
        "compose_findings": len(
            compose_findings
        ),
        "total_findings": len(
            all_findings
        ),
    }

    analysis["scan_targets"] = {
        "compose": str(
            compose_path_obj
        ),
        "dockerfile": str(
            dockerfile_path_obj
        ),
        "runtime": "running containers",
    }

    return analysis