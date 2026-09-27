from __future__ import annotations

from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from dockershield.docker_client import get_client
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


app = FastAPI(
    title="DockerShield API",
    description=(
        "Docker security, compliance, attack-path analysis, "
        "remediation, simulation and ML risk API."
    ),
    version="1.0.0",
)


class ComposeScanRequest(BaseModel):
    path: str


class DockerfileScanRequest(BaseModel):
    path: str


class RuntimeScanRequest(BaseModel):
    container: str


class SimulationRequest(BaseModel):
    path: str
    remediation_ids: list[str]


def findings_to_dict(findings) -> list[dict[str, Any]]:
    return [
        finding.to_dict()
        for finding in findings
    ]


def analyze_findings(findings) -> dict[str, Any]:
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


@app.get("/")
def root():
    return {
        "name": "DockerShield",
        "status": "running",
        "version": "1.0.0",
    }


@app.get("/health")
def health():
    docker_status = "disconnected"

    try:
        client = get_client()
        client.ping()
        docker_status = "connected"
    except SystemExit:
        pass
    except Exception:
        pass

    return {
        "status": "healthy",
        "docker": docker_status,
    }


@app.get("/containers")
def containers():
    try:
        client = get_client()

        results = []

        for container in client.containers.list(all=True):
            results.append(
                {
                    "id": container.id[:12],
                    "name": container.name,
                    "status": container.status,
                    "image": (
                        container.image.tags[0]
                        if container.image.tags
                        else container.image.short_id
                    ),
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


@app.post("/scan/runtime")
def runtime_scan(request: RuntimeScanRequest):
    try:
        client = get_client()

        container = client.containers.get(
            request.container
        )

        findings = scan_container(container)

        return analyze_findings(findings)

    except Exception as exc:
        raise HTTPException(
            status_code=400,
            detail=str(exc),
        )


@app.post("/scan/dockerfile")
def dockerfile_scan(request: DockerfileScanRequest):
    path = Path(request.path)

    if not path.exists():
        raise HTTPException(
            status_code=404,
            detail=f"Dockerfile not found: {path}",
        )

    try:
        findings = scan_dockerfile(str(path))
        return analyze_findings(findings)

    except Exception as exc:
        raise HTTPException(
            status_code=400,
            detail=str(exc),
        )


@app.post("/scan/compose")
def compose_scan(request: ComposeScanRequest):
    path = Path(request.path)

    if not path.exists():
        raise HTTPException(
            status_code=404,
            detail=f"Compose file not found: {path}",
        )

    try:
        findings = scan_compose(str(path))
        return analyze_findings(findings)

    except Exception as exc:
        raise HTTPException(
            status_code=400,
            detail=str(exc),
        )


@app.post("/simulate")
def simulate(request: SimulationRequest):
    path = Path(request.path)

    if not path.exists():
        raise HTTPException(
            status_code=404,
            detail=f"Compose file not found: {path}",
        )

    try:
        findings = scan_compose(str(path))

        result = simulate_remediations(
            findings,
            request.remediation_ids,
        )

        return result

    except Exception as exc:
        raise HTTPException(
            status_code=400,
            detail=str(exc),
        )