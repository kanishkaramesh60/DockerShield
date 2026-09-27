from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

from dockershield.models import Finding


@dataclass(frozen=True)
class Correlation:
    correlation_id: str
    title: str
    description: str
    rule_ids: tuple[str, ...]
    severity: str


CORRELATION_RULES = [
    Correlation(
        correlation_id="CORR-001",
        title="Elevated container privilege",
        description=(
            "Privileged mode is combined with additional "
            "privilege-related configuration."
        ),
        rule_ids=("DS015", "DS020"),
        severity="CRITICAL",
    ),
    Correlation(
        correlation_id="CORR-002",
        title="Docker host control exposure",
        description=(
            "The container has Docker daemon socket access, "
            "which can significantly increase host impact."
        ),
        rule_ids=("DS016",),
        severity="CRITICAL",
    ),
    Correlation(
        correlation_id="CORR-003",
        title="Reduced namespace isolation",
        description=(
            "Multiple host namespace settings reduce isolation "
            "between the container and Docker host."
        ),
        rule_ids=("DS017", "DS018", "DS019"),
        severity="HIGH",
    ),
    Correlation(
        correlation_id="CORR-004",
        title="Multiple privilege boundaries weakened",
        description=(
            "The service combines elevated privileges with "
            "reduced namespace isolation."
        ),
        rule_ids=("DS015", "DS017", "DS018", "DS019"),
        severity="CRITICAL",
    ),
]


def correlate_findings(
    findings: Iterable[Finding],
) -> list[dict]:
    findings = list(findings)

    rule_ids = {
        finding.rule_id
        for finding in findings
    }

    correlations = []

    for correlation in CORRELATION_RULES:
        matched_rules = [
            rule_id
            for rule_id in correlation.rule_ids
            if rule_id in rule_ids
        ]

        # A single-rule correlation only needs that rule.
        if len(correlation.rule_ids) == 1:
            triggered = len(matched_rules) == 1
        else:
            triggered = len(matched_rules) >= 2

        if triggered:
            correlations.append(
                {
                    "correlation_id": correlation.correlation_id,
                    "title": correlation.title,
                    "description": correlation.description,
                    "severity": correlation.severity,
                    "matched_rules": matched_rules,
                }
            )

    return correlations


def summarize_correlations(
    findings: Iterable[Finding],
) -> dict:
    correlations = correlate_findings(findings)

    critical = sum(
        1
        for item in correlations
        if item["severity"] == "CRITICAL"
    )

    high = sum(
        1
        for item in correlations
        if item["severity"] == "HIGH"
    )

    return {
        "total": len(correlations),
        "critical": critical,
        "high": high,
        "correlations": correlations,
    }