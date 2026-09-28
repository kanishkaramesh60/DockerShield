from __future__ import annotations

import requests


class DockerShieldAPI:
    """
    Client for the DockerShield FastAPI backend.

    The dashboard communicates with the API rather than
    implementing security scanning logic itself.
    """

    def __init__(
        self,
        base_url: str = "http://127.0.0.1:8000",
    ):
        self.base_url = base_url.rstrip("/")

    def _get(self, endpoint: str):
        response = requests.get(
            f"{self.base_url}{endpoint}",
            timeout=30,
        )

        response.raise_for_status()

        return response.json()

    def _post(self, endpoint: str, payload: dict):
        response = requests.post(
            f"{self.base_url}{endpoint}",
            json=payload,
            timeout=120,
        )

        response.raise_for_status()

        return response.json()

    # ========================================================
    # System
    # ========================================================

    def health(self) -> dict:
        return self._get("/health")

    def info(self) -> dict:
        return self._get("/api/info")

    # ========================================================
    # Docker
    # ========================================================

    def containers(self) -> list:
        result = self._get("/containers")

        if isinstance(result, list):
            return result

        if isinstance(result, dict):
            return result.get(
                "containers",
                [],
            )

        return []

    # ========================================================
    # Runtime scan
    # ========================================================

    def runtime_scan(
        self,
        container_name: str,
    ) -> dict:

        return self._post(
            "/scan/runtime",
            {
                "container_name": container_name,
            },
        )

    # ========================================================
    # Dockerfile scan
    # ========================================================

    def dockerfile_scan(
        self,
        path: str,
    ) -> dict:

        return self._post(
            "/scan/dockerfile",
            {
                "path": path,
            },
        )

    # ========================================================
    # Compose scan
    # ========================================================

    def compose_scan(
        self,
        path: str,
    ) -> dict:

        return self._post(
            "/scan/compose",
            {
                "path": path,
            },
        )

    # ========================================================
    # Simulation
    # ========================================================

    def simulate(
        self,
        path: str,
        remediation_ids: list[str],
    ) -> dict:

        return self._post(
            "/simulate",
            {
                "path": path,
                "remediation_ids": remediation_ids,
            },
        )