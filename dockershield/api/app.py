from __future__ import annotations

from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from dockershield.docker_client import try_get_client

from dockershield.runtime import scan_container
from dockershield.dockerfile import scan_dockerfile
from dockershield.compose import scan_compose

from dockershield.engine.simulator import simulate_remediations

from dockershield.core.scanner import (
    analyze_findings as core_analyze_findings,
    run_full_scan,
)


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


class FullScanRequest(BaseModel):
    compose_path: str = (
        "test-data\\vulnerable\\compose.yml"
    )

    dockerfile_path: str = (
        "test-data\\Dockerfile"
    )


# =========================================================
# HELPERS
# =========================================================

def validate_file(
    path_string: str,
    description: str,
) -> Path:
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


def analyze_findings(
    findings,
    scan_type: str,
    target: str,
) -> dict[str, Any]:
    """
    Use the shared DockerShield analysis engine.

    The API does NOT maintain a second copy of the
    risk/compliance/correlation/attack-path/ML logic.
    """

    return core_analyze_findings(
        findings=findings,
        scan_type=scan_type,
        target=target,
    )


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

    Docker being unavailable does NOT make the API itself
    unhealthy.
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

        for container in client.containers.list(
            all=True
        ):

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
def runtime_scan(
    request: RuntimeScanRequest,
):
    """
    Scan a running or stopped Docker container.

    Uses the same central analysis engine as the CLI.
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

        findings = scan_container(
            container
        )

        return analyze_findings(
            findings=findings,
            scan_type="runtime",
            target=request.container,
        )

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

    Uses the same central analysis engine as the CLI.
    """

    path = validate_file(
        request.path,
        "Dockerfile",
    )

    try:
        findings = scan_dockerfile(
            str(path)
        )

        return analyze_findings(
            findings=findings,
            scan_type="dockerfile",
            target=str(path),
        )

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

    Uses the same central analysis engine as the CLI.
    """

    path = validate_file(
        request.path,
        "Compose file",
    )

    try:
        findings = scan_compose(
            str(path)
        )

        return analyze_findings(
            findings=findings,
            scan_type="compose",
            target=str(path),
        )

    except Exception as exc:
        raise HTTPException(
            status_code=400,
            detail=str(exc),
        )


# =========================================================
# FULL DOCKERSHIELD SCAN
# =========================================================

@app.post("/scan/full")
def full_scan(
    request: FullScanRequest,
):
    """
    Run the complete DockerShield security pipeline.

    One API request performs:

        1. Docker environment discovery
        2. Runtime scanning
        3. Dockerfile scanning
        4. Compose scanning
        5. Risk scoring
        6. ML risk classification
        7. Compliance analysis
        8. Correlation analysis
        9. Attack-path analysis
        10. Remediation analysis

    The dashboard uses this endpoint for its single
    RUN FULL SCAN button.

    No duplicate scanner implementation is used here.
    """

    try:
        result = run_full_scan(
            compose_path=request.compose_path,
            dockerfile_path=request.dockerfile_path,
        )

        return result

    except FileNotFoundError as exc:
        raise HTTPException(
            status_code=404,
            detail=str(exc),
        )

    except RuntimeError as exc:
        raise HTTPException(
            status_code=503,
            detail=str(exc),
        )

    except ValueError as exc:
        raise HTTPException(
            status_code=400,
            detail=str(exc),
        )

    except Exception as exc:
        raise HTTPException(
            status_code=500,
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
            "full environment scanning",
            "risk analysis",
            "ML risk prediction",
            "compliance analysis",
            "finding correlation",
            "attack-path analysis",
            "attack-path-aware remediation",
            "what-if remediation simulation",
        ],

        "endpoints": {
            "health": "/health",
            "containers": "/containers",
            "runtime_scan": "/scan/runtime",
            "dockerfile_scan": "/scan/dockerfile",
            "compose_scan": "/scan/compose",
            "full_scan": "/scan/full",
            "simulation": "/simulate",
        },
    }