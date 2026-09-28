from __future__ import annotations

import sys

import docker
from docker.errors import DockerException


def get_client():
    """
    Create and validate a Docker client.

    This function is intended for the CLI.
    If Docker is unavailable, it prints an error and exits.
    """

    try:
        client = docker.from_env()
        client.ping()
        return client

    except DockerException as exc:
        print("\n[ERROR] Could not connect to Docker Engine.")
        print("Make sure Docker Desktop is running.")
        print(f"Details: {exc}")
        sys.exit(1)


def try_get_client():
    """
    Create and validate a Docker client without terminating the process.

    This function is intended for FastAPI, Streamlit and other
    long-running application components.

    Returns:
        Docker client when Docker is available.
        None when Docker is unavailable.
    """

    try:
        client = docker.from_env()
        client.ping()
        return client

    except DockerException:
        return None