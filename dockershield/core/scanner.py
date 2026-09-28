from __future__ import annotations

from pathlib import Path
from typing import Iterable

from dockershield.models import Finding

from dockershield.runtime import scan_container
from dockershield.dockerfile import scan_dockerfile as scan_dockerfile_file
from dockershield.compose import scan_compose as scan_compose_file

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
from dockershield.engine.remediation import generate_remediations

from dockershield.ml.predict import predict_risk


def _findings_to_dict(findings: Iterable[Finding]) -> list[dict]:
    """
    Convert DockerShield Finding objects into dictionaries
    for the API, dashboard and JSON-compatible output.
    """
    return [finding.to_dict() for finding in findings]


def analyze_findings(
    findings: Iterable[Finding],
    scan_type: str,
    target: str,
) -> dict:
    """
    Central DockerShield security-analysis pipeline.

    This function is the shared analysis layer used by:
        - CLI
        - FastAPI
        - Streamlit dashboard

    Security logic must remain here or inside the existing
    scanner/engine modules rather than being duplicated in
    individual interfaces.
    """

    findings = list(findings)

    # --------------------------------------------------------
    # Risk
    # --------------------------------------------------------

    risk = calculate_risk(findings)

    # --------------------------------------------------------
    # Compliance
    # --------------------------------------------------------

    compliance = calculate_compliance(findings)

    # --------------------------------------------------------
    # Correlation
    # --------------------------------------------------------

    correlations = correlate_findings(findings)

    # IMPORTANT:
    # summarize_correlations() expects the original findings,
    # not the already-generated correlation objects.
    correlation_summary = summarize_correlations(findings)

    # --------------------------------------------------------
    # Attack paths
    # --------------------------------------------------------

    attack_paths = analyze_attack_paths(findings)
    attack_path_summary = summarize_attack_paths(findings)

    # --------------------------------------------------------
    # Remediation
    # --------------------------------------------------------

    remediations = generate_remediations(
        findings,
        attack_paths=attack_paths,
    )

    # --------------------------------------------------------
    # ML prediction
    # --------------------------------------------------------

    try:
        ml_prediction = predict_risk(findings)

    except Exception as exc:
        ml_prediction = {
            "available": False,
            "error": str(exc),
        }

    # --------------------------------------------------------
    # Unified result
    # --------------------------------------------------------

    return {
        "scan_metadata": {
            "scan_type": scan_type,
            "target": target,
        },

        "findings": _findings_to_dict(findings),

        "risk": risk,

        "compliance": compliance,

        "correlations": correlations,
        "correlation_summary": correlation_summary,

        "attack_paths": attack_paths,
        "attack_path_summary": attack_path_summary,

        "remediations": remediations,

        "ml_prediction": ml_prediction,
    }


def scan_runtime_target(container_name: str) -> dict:
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
        container = client.containers.get(container_name)

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


def scan_dockerfile_target(file_path: str) -> dict:
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

    findings = scan_dockerfile_file(str(path))

    return analyze_findings(
        findings=findings,
        scan_type="dockerfile",
        target=str(path),
    )


def scan_compose_target(file_path: str) -> dict:
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

    findings = scan_compose_file(str(path))

    return analyze_findings(
        findings=findings,
        scan_type="compose",
        target=str(path),
    )