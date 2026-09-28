from __future__ import annotations

from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from dockershield.docker_client import try_get_client

from dockershield.runtime import scan_container
from dockershield.dockerfile import scan_dockerfile
from dockershield.compose import scan_compose

from dockershield.engine.risk import calculate_risk
from dockershield.engine.compliance import calculate_compliance
from dockershield.engine.correlation import summarize_correlations
from dockershield.engine.attack_path import summarize_attack_paths
from dockershield.engine.remediation import summarize_remediations
from dockershield.engine.simulator import simulate_remediations

from dockershield.ml.predict import predict_risk


# =========================================================
# APPLICATION
# =========================================================

app = FastAPI(
    title="DockerShield API",
    description=(
        "Docker security, compliance, attack-path analysis, "
        "remediation, simulation and ML risk analysis API."
    ),
    version="1.0.0",
)


# =========================================================
# REQUEST MODELS
# =========================================================

class ComposeScanRequest(BaseModel):
    path: str


class DockerfileScanRequest(BaseModel):
    path: str


class RuntimeScanRequest(BaseModel):
    container: str


class SimulationRequest(BaseModel):
    path: str
    remediation_ids: list[str]


# =========================================================
# HELPERS
# =========================================================

def findings_to_dict(findings) -> list[dict[str, Any]]:
    """
    Convert Finding dataclasses into JSON-compatible dictionaries.
    """

    return [
        finding.to_dict()
        for finding in findings
    ]


def analyze_findings(findings) -> dict[str, Any]:
    """
    Run all DockerShield analysis engines against a finding set.

    This is the central API analysis pipeline.

    Pipeline:

        Findings
           |
           +--> Risk
           |
           +--> Compliance
           |
           +--> Correlations
           |
           +--> Attack Paths
           |
           +--> Remediation
           |
           +--> XGBoost
    """

    risk = calculate_risk(findings)

    compliance = calculate_compliance(findings)

    correlations = summarize_correlations(findings)

    attack_paths = summarize_attack_paths(findings)

    remediations = summarize_remediations(
        findings,
        attack_paths["paths"],
    )

    try:
        ml_prediction = predict_risk(findings)

    except FileNotFoundError:
        ml_prediction = None

    return {
        "findings": findings_to_dict(findings),

        "risk": risk,

        "compliance": compliance,

        "correlations": correlations,

        "attack_paths": attack_paths,

        "remediations": remediations,

        "ml_prediction": ml_prediction,
    }


def validate_file(path_string: str, description: str) -> Path:
    """
    Validate a user-provided local file path.
    """

    path = Path(path_string)

    if not path.exists():
        raise HTTPException(
            status_code=404,
            detail=f"{description} not found: {path}",
        )

    if not path.is_file():
        raise HTTPException(
            status_code=400,
            detail=f"{description} is not a file: {path}",
        )

    return path


# =========================================================
# ROOT
# =========================================================

@app.get("/")
def root():
    return {
        "name": "DockerShield",
        "status": "running",
        "version": "1.0.0",
    }


# =========================================================
# HEALTH
# =========================================================

@app.get("/health")
def health():
    """
    API health endpoint.

    Docker being unavailable does NOT make the API itself unhealthy.
    """

    client = try_get_client()

    if client is None:
        return {
            "status": "healthy",
            "docker": "disconnected",
        }

    return {
        "status": "healthy",
        "docker": "connected",
    }


# =========================================================
# CONTAINERS
# =========================================================

@app.get("/containers")
def containers():
    """
    Return all Docker containers.

    This endpoint never terminates the FastAPI process if Docker
    is unavailable.
    """

    client = try_get_client()

    if client is None:
        raise HTTPException(
            status_code=503,
            detail=(
                "Docker Engine is unavailable. "
                "Start Docker Desktop and try again."
            ),
        )

    try:
        results = []

        for container in client.containers.list(all=True):

            image_name = (
                container.image.tags[0]
                if container.image.tags
                else container.image.short_id
            )

            results.append(
                {
                    "id": container.id[:12],
                    "name": container.name,
                    "status": container.status,
                    "image": image_name,
                }
            )

        return {
            "containers": results,
            "count": len(results),
        }

    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=str(exc),
        )


# =========================================================
# RUNTIME SCAN
# =========================================================

@app.post("/scan/runtime")
def runtime_scan(request: RuntimeScanRequest):
    """
    Scan a running or stopped Docker container.
    """

    client = try_get_client()

    if client is None:
        raise HTTPException(
            status_code=503,
            detail=(
                "Docker Engine is unavailable. "
                "Start Docker Desktop and try again."
            ),
        )

    try:
        container = client.containers.get(
            request.container
        )

        findings = scan_container(container)

        result = analyze_findings(findings)

        result["scan_metadata"] = {
            "scan_type": "runtime",
            "target": request.container,
        }

        return result

    except Exception as exc:
        raise HTTPException(
            status_code=400,
            detail=str(exc),
        )


# =========================================================
# DOCKERFILE SCAN
# =========================================================

@app.post("/scan/dockerfile")
def dockerfile_scan(
    request: DockerfileScanRequest,
):
    """
    Scan a Dockerfile.
    """

    path = validate_file(
        request.path,
        "Dockerfile",
    )

    try:
        findings = scan_dockerfile(
            str(path)
        )

        result = analyze_findings(findings)

        result["scan_metadata"] = {
            "scan_type": "dockerfile",
            "target": str(path),
        }

        return result

    except Exception as exc:
        raise HTTPException(
            status_code=400,
            detail=str(exc),
        )


# =========================================================
# COMPOSE SCAN
# =========================================================

@app.post("/scan/compose")
def compose_scan(
    request: ComposeScanRequest,
):
    """
    Scan a Docker Compose file.
    """

    path = validate_file(
        request.path,
        "Compose file",
    )

    try:
        findings = scan_compose(
            str(path)
        )

        result = analyze_findings(findings)

        result["scan_metadata"] = {
            "scan_type": "compose",
            "target": str(path),
        }

        return result

    except Exception as exc:
        raise HTTPException(
            status_code=400,
            detail=str(exc),
        )


# =========================================================
# SIMULATION
# =========================================================

@app.post("/simulate")
def simulate(
    request: SimulationRequest,
):
    """
    Simulate remediation actions against a Compose scan.

    This is completely in-memory.
    It does NOT modify Docker or the Compose file.
    """

    path = validate_file(
        request.path,
        "Compose file",
    )

    try:
        findings = scan_compose(
            str(path)
        )

        result = simulate_remediations(
            findings,
            request.remediation_ids,
        )

        result["scan_metadata"] = {
            "scan_type": "compose",
            "target": str(path),
        }

        return result

    except Exception as exc:
        raise HTTPException(
            status_code=400,
            detail=str(exc),
        )


# =========================================================
# API INFORMATION
# =========================================================

@app.get("/api/info")
def api_info():
    """
    Basic API capability information for the dashboard.
    """

    return {
        "name": "DockerShield",
        "version": "1.0.0",
        "features": [
            "runtime scanning",
            "Dockerfile scanning",
            "Compose scanning",
            "risk analysis",
            "compliance analysis",
            "finding correlation",
            "attack-path analysis",
            "attack-path-aware remediation",
            "what-if remediation simulation",
            "XGBoost risk prediction",
        ],
    }