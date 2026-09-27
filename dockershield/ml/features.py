from __future__ import annotations

from collections import Counter
from typing import Iterable

from dockershield.models import Finding


def extract_features(
    findings: Iterable[Finding],
) -> dict[str, int]:
    """
    Convert DockerShield findings into numerical ML features.

    The rule engine remains responsible for detecting security issues.
    These features are used as input to the XGBoost risk model.
    """

    findings = list(findings)

    rule_ids = {
        finding.rule_id
        for finding in findings
    }

    severity_counts = Counter(
        finding.severity.upper()
        for finding in findings
    )

    features = {
        # Overall finding statistics
        "total_findings": len(findings),
        "critical_count": severity_counts.get(
            "CRITICAL", 0
        ),
        "high_count": severity_counts.get(
            "HIGH", 0
        ),
        "medium_count": severity_counts.get(
            "MEDIUM", 0
        ),
        "low_count": severity_counts.get(
            "LOW", 0
        ),

        # Privilege-related features
        "privileged": int(
            "DS001" in rule_ids
            or "DS015" in rule_ids
        ),
        "root_user": int(
            "DS002" in rule_ids
            or "DS011" in rule_ids
        ),
        "dangerous_capabilities": int(
            "DS008" in rule_ids
            or "DS020" in rule_ids
        ),

        # Host exposure
        "docker_socket": int(
            "DS003" in rule_ids
            or "DS016" in rule_ids
        ),
        "host_network": int(
            "DS005" in rule_ids
            or "DS017" in rule_ids
        ),
        "host_pid": int(
            "DS006" in rule_ids
            or "DS018" in rule_ids
        ),
        "host_ipc": int(
            "DS007" in rule_ids
            or "DS019" in rule_ids
        ),
        "sensitive_mount": int(
            "DS004" in rule_ids
        ),

        # Resource controls
        "missing_memory_limit": int(
            "DS009" in rule_ids
            or "DS021" in rule_ids
        ),
        "missing_cpu_limit": int(
            "DS010" in rule_ids
            or "DS022" in rule_ids
        ),

        # Dockerfile security
        "unsafe_add": int(
            "DS012" in rule_ids
        ),
        "possible_secret": int(
            "DS013" in rule_ids
        ),
        "remote_shell_download": int(
            "DS014" in rule_ids
        ),
    }

    return features


def feature_names() -> list[str]:
    """
    Return the feature names in stable order.
    """

    return list(
        extract_features([])
    .keys()
    )