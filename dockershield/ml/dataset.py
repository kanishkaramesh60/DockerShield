from __future__ import annotations

import csv
import random
from pathlib import Path


DEFAULT_DATASET_PATH = Path("data") / "ml_dataset.csv"


FEATURE_NAMES = [
    "total_findings",
    "critical_count",
    "high_count",
    "medium_count",
    "low_count",
    "privileged",
    "root_user",
    "dangerous_capabilities",
    "docker_socket",
    "host_network",
    "host_pid",
    "host_ipc",
    "sensitive_mount",
    "missing_memory_limit",
    "missing_cpu_limit",
    "unsafe_add",
    "possible_secret",
    "remote_shell_download",
]


def _calculate_label(
    critical_count: int,
    high_count: int,
    medium_count: int,
    low_count: int,
) -> str:
    """
    Calculate the synthetic training label using
    DockerShield's current documented risk thresholds.
    """

    score = (
        critical_count * 25
        + high_count * 15
        + medium_count * 7
        + low_count * 2
    )

    if score >= 80:
        return "CRITICAL"

    if score >= 60:
        return "HIGH"

    if score >= 30:
        return "MEDIUM"

    if score > 0:
        return "LOW"

    return "SECURE"


def generate_sample() -> dict[str, int | str]:
    """
    Generate one synthetic Docker security configuration.

    The label is derived from the generated security features
    using the current DockerShield risk thresholds.
    """

    privileged = random.randint(0, 1)
    root_user = random.randint(0, 1)
    dangerous_capabilities = random.randint(0, 1)
    docker_socket = random.randint(0, 1)
    host_network = random.randint(0, 1)
    host_pid = random.randint(0, 1)
    host_ipc = random.randint(0, 1)
    sensitive_mount = random.randint(0, 1)
    missing_memory_limit = random.randint(0, 1)
    missing_cpu_limit = random.randint(0, 1)
    unsafe_add = random.randint(0, 1)
    possible_secret = random.randint(0, 1)
    remote_shell_download = random.randint(0, 1)

    critical_count = (
        privileged
        + docker_socket
    )

    high_count = (
        dangerous_capabilities
        + host_network
        + host_pid
        + host_ipc
        + sensitive_mount
    )

    medium_count = (
        missing_memory_limit
        + missing_cpu_limit
        + unsafe_add
        + possible_secret
        + remote_shell_download
    )

    low_count = root_user

    total_findings = (
        critical_count
        + high_count
        + medium_count
        + low_count
    )

    label = _calculate_label(
        critical_count,
        high_count,
        medium_count,
        low_count,
    )

    return {
        "total_findings": total_findings,
        "critical_count": critical_count,
        "high_count": high_count,
        "medium_count": medium_count,
        "low_count": low_count,
        "privileged": privileged,
        "root_user": root_user,
        "dangerous_capabilities": dangerous_capabilities,
        "docker_socket": docker_socket,
        "host_network": host_network,
        "host_pid": host_pid,
        "host_ipc": host_ipc,
        "sensitive_mount": sensitive_mount,
        "missing_memory_limit": missing_memory_limit,
        "missing_cpu_limit": missing_cpu_limit,
        "unsafe_add": unsafe_add,
        "possible_secret": possible_secret,
        "remote_shell_download": remote_shell_download,
        "label": label,
    }


def _secure_sample() -> dict[str, int | str]:
    return {
        "total_findings": 0,
        "critical_count": 0,
        "high_count": 0,
        "medium_count": 0,
        "low_count": 0,
        "privileged": 0,
        "root_user": 0,
        "dangerous_capabilities": 0,
        "docker_socket": 0,
        "host_network": 0,
        "host_pid": 0,
        "host_ipc": 0,
        "sensitive_mount": 0,
        "missing_memory_limit": 0,
        "missing_cpu_limit": 0,
        "unsafe_add": 0,
        "possible_secret": 0,
        "remote_shell_download": 0,
        "label": "SECURE",
    }


def _low_sample() -> dict[str, int | str]:
    return {
        "total_findings": 1,
        "critical_count": 0,
        "high_count": 0,
        "medium_count": 0,
        "low_count": 1,
        "privileged": 0,
        "root_user": 1,
        "dangerous_capabilities": 0,
        "docker_socket": 0,
        "host_network": 0,
        "host_pid": 0,
        "host_ipc": 0,
        "sensitive_mount": 0,
        "missing_memory_limit": 0,
        "missing_cpu_limit": 0,
        "unsafe_add": 0,
        "possible_secret": 0,
        "remote_shell_download": 0,
        "label": "LOW",
    }


def _medium_sample() -> dict[str, int | str]:
    return {
        "total_findings": 5,
        "critical_count": 0,
        "high_count": 0,
        "medium_count": 5,
        "low_count": 0,
        "privileged": 0,
        "root_user": 0,
        "dangerous_capabilities": 0,
        "docker_socket": 0,
        "host_network": 0,
        "host_pid": 0,
        "host_ipc": 0,
        "sensitive_mount": 0,
        "missing_memory_limit": 1,
        "missing_cpu_limit": 1,
        "unsafe_add": 1,
        "possible_secret": 1,
        "remote_shell_download": 1,
        "label": "MEDIUM",
    }


def _high_sample() -> dict[str, int | str]:
    return {
        "total_findings": 4,
        "critical_count": 0,
        "high_count": 4,
        "medium_count": 0,
        "low_count": 0,
        "privileged": 0,
        "root_user": 0,
        "dangerous_capabilities": 1,
        "docker_socket": 0,
        "host_network": 1,
        "host_pid": 1,
        "host_ipc": 1,
        "sensitive_mount": 0,
        "missing_memory_limit": 0,
        "missing_cpu_limit": 0,
        "unsafe_add": 0,
        "possible_secret": 0,
        "remote_shell_download": 0,
        "label": "HIGH",
    }


def _critical_sample() -> dict[str, int | str]:
    return {
        "total_findings": 2,
        "critical_count": 2,
        "high_count": 0,
        "medium_count": 0,
        "low_count": 0,
        "privileged": 1,
        "root_user": 0,
        "dangerous_capabilities": 0,
        "docker_socket": 1,
        "host_network": 0,
        "host_pid": 0,
        "host_ipc": 0,
        "sensitive_mount": 0,
        "missing_memory_limit": 0,
        "missing_cpu_limit": 0,
        "unsafe_add": 0,
        "possible_secret": 0,
        "remote_shell_download": 0,
        "label": "CRITICAL",
    }


def generate_dataset(
    samples: int = 1000,
    output_path: Path = DEFAULT_DATASET_PATH,
) -> Path:
    """
    Generate and save a synthetic training dataset.

    At least 20 deterministic examples are included for
    every risk class. Remaining examples are generated randomly.
    """

    if samples < 100:
        raise ValueError(
            "samples must be at least 100"
        )

    output_path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    templates = [
        _secure_sample(),
        _low_sample(),
        _medium_sample(),
        _high_sample(),
        _critical_sample(),
    ]

    rows: list[dict[str, int | str]] = []

    # Guarantee sufficient examples for every class.
    for template in templates:
        for _ in range(20):
            rows.append(template.copy())

    # Generate the remaining examples.
    while len(rows) < samples:
        rows.append(generate_sample())

    random.shuffle(rows)

    fieldnames = FEATURE_NAMES + ["label"]

    with output_path.open(
        "w",
        newline="",
        encoding="utf-8",
    ) as file:
        writer = csv.DictWriter(
            file,
            fieldnames=fieldnames,
        )

        writer.writeheader()
        writer.writerows(rows)

    return output_path


if __name__ == "__main__":
    path = generate_dataset()

    print(
        f"[ML] Dataset generated: {path}"
    )