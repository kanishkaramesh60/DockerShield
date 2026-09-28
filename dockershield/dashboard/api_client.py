from __future__ import annotations

import requests

from dockershield.models import Finding


class DockerShieldAPI:
    """
    Client for the DockerShield FastAPI backend.

    Scans, simulation, health and container listing go through the API.
    Features that exist in the CLI but have no API endpoint (baseline,
    compare, HTML report, environment discovery) call the very same
    engine functions the CLI uses, so behaviour stays identical.
    """

    def __init__(
        self,
        base_url: str = "http://127.0.0.1:8001",
    ):
        self.base_url = base_url.rstrip("/")

    # ------------------------------------------------------------
    # HTTP helpers
    # ------------------------------------------------------------

    @staticmethod
    def _raise(response: requests.Response) -> None:
        """Raise an error that includes the API's `detail` message."""

        if response.ok:
            return

        try:
            detail = response.json().get("detail", response.text)
        except Exception:
            detail = response.text

        raise RuntimeError(f"API error {response.status_code}: {detail}")

    def _get(self, endpoint: str):
        response = requests.get(
            f"{self.base_url}{endpoint}",
            timeout=30,
        )
        self._raise(response)
        return response.json()

    def _post(self, endpoint: str, payload: dict):
        response = requests.post(
            f"{self.base_url}{endpoint}",
            json=payload,
            timeout=120,
        )
        self._raise(response)
        return response.json()

    # ------------------------------------------------------------
    # System
    # ------------------------------------------------------------

    def health(self) -> dict:
        return self._get("/health")

    def info(self) -> dict:
        return self._get("/api/info")

    # ------------------------------------------------------------
    # Docker
    # ------------------------------------------------------------

    def containers(self) -> list:
        result = self._get("/containers")

        if isinstance(result, list):
            return result

        if isinstance(result, dict):
            return result.get("containers", [])

        return []

    # ------------------------------------------------------------
    # Scans (API)
    # ------------------------------------------------------------

    def runtime_scan(self, container_name: str) -> dict:
        # The API model field is `container`.
        return self._post(
            "/scan/runtime",
            {"container": container_name},
        )

    def dockerfile_scan(self, path: str) -> dict:
        return self._post("/scan/dockerfile", {"path": path})

    def compose_scan(self, path: str) -> dict:
        return self._post("/scan/compose", {"path": path})

    def simulate(self, path: str, remediation_ids: list[str]) -> dict:
        return self._post(
            "/simulate",
            {
                "path": path,
                "remediation_ids": remediation_ids,
            },
        )

    # ------------------------------------------------------------
    # Scan all running containers (same as `dockershield.py scan`)
    # ------------------------------------------------------------

    def runtime_scan_all(self) -> dict:
        """
        Scan every running container through the API and merge the
        findings, then run the shared engines on the merged set.
        """

        from dockershield.dashboard.analysis import analyze_findings

        running = [
            item
            for item in self.containers()
            if item.get("status") == "running"
        ]

        if not running:
            raise RuntimeError("No running containers found.")

        merged: list[Finding] = []

        for item in running:
            result = self.runtime_scan(item["name"])
            merged.extend(
                Finding(**finding)
                for finding in result.get("findings", [])
            )

        result = analyze_findings(merged)
        result["scan_metadata"] = {
            "scan_type": "runtime",
            "target": f"all running containers ({len(running)})",
        }
        return result

    # ------------------------------------------------------------
    # Baseline / compare / report (same engine code as the CLI)
    # ------------------------------------------------------------

    def save_baseline(self, findings: list[Finding]) -> dict:
        from dockershield.engine.baseline import save_baseline

        return save_baseline(findings)

    def load_baseline(self) -> dict:
        from dockershield.engine.baseline import load_baseline

        return load_baseline()

    def compare_baseline(self, findings: list[Finding]) -> dict:
        from dockershield.engine.baseline import (
            compare_with_baseline,
            load_baseline,
        )

        return compare_with_baseline(findings, load_baseline())

    def generate_report(
        self,
        findings: list[Finding],
        output: str = "data/report.html",
    ) -> str:
        from dockershield.report import generate_html_report

        return str(generate_html_report(findings, output))
