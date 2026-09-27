from __future__ import annotations

import sys

import docker
from docker.errors import DockerException


def get_client():
    try:
        client = docker.from_env()
        client.ping()
        return client

    except DockerException as exc:
        print("\n[ERROR] Could not connect to Docker Engine.")
        print("Make sure Docker Desktop is running.")
        print(f"Details: {exc}")
        sys.exit(1)