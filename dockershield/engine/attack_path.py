from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

from dockershield.models import Finding


@dataclass(frozen=True)
class AttackPathRule:
    path_id: str
    title: str
    description: str
    required_rules: tuple[str, ...]
    severity: str


ATTACK_PATH_RULES = [
    AttackPathRule(
        path_id="PATH-001",
        title="Docker daemon access path",
        description=(
            "Container configuration exposes the Docker daemon socket, "
            "creating a potential path to Docker resource control."
        ),
        required_rules=("DS016",),
        severity="CRITICAL",
    ),
    AttackPathRule(
        path_id="PATH-002",
        title="Privileged container path",
        description=(
            "Privileged execution combined with additional capabilities "
            "creates a potential elevated-privilege path."
        ),
        required_rules=("DS015", "DS020"),
        severity="CRITICAL",
    ),
    AttackPathRule(
        path_id="PATH-003",
        title="Host namespace exposure path",
        description=(
            "Sharing host namespaces reduces container isolation and "
            "creates a potential path toward host-level visibility."
        ),
        required_rules=("DS017", "DS018", "DS019"),
        severity="HIGH",
    ),
    AttackPathRule(
        path_id="PATH-004",
        title="Combined host-impact path",
        description=(
            "Privileged execution combined with host namespace exposure "
            "creates a stronger potential host-impact path."
        ),
        required_rules=("DS015", "DS017", "DS018"),
        severity="CRITICAL",
    ),
]


def analyze_attack_paths(
    findings: Iterable[Finding],
) -> list[dict]:
    findings = list(findings)

    rule_ids = {
        finding.rule_id
        for finding in findings
    }

    paths = []

    for rule in ATTACK_PATH_RULES:
        matched_rules = [
            rule_id
            for rule_id in rule.required_rules
            if rule_id in rule_ids
        ]

        if all(
            rule_id in rule_ids
            for rule_id in rule.required_rules
        ):
            paths.append(
                {
                    "path_id": rule.path_id,
                    "title": rule.title,
                    "description": rule.description,
                    "severity": rule.severity,
                    "matched_rules": matched_rules,
                    "steps": [
                        "Container configuration",
                        *matched_rules,
                        "Potential security impact",
                    ],
                }
            )

    return paths


def summarize_attack_paths(
    findings: Iterable[Finding],
) -> dict:
    paths = analyze_attack_paths(findings)

    critical = sum(
        1
        for path in paths
        if path["severity"] == "CRITICAL"
    )

    high = sum(
        1
        for path in paths
        if path["severity"] == "HIGH"
    )

    return {
        "total": len(paths),
        "critical": critical,
        "high": high,
        "paths": paths,
    }