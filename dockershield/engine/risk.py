from __future__ import annotations

from collections import Counter
from typing import Iterable

from dockershield.models import Finding


SEVERITY_WEIGHTS = {
    "CRITICAL": 25,
    "HIGH": 15,
    "MEDIUM": 7,
    "LOW": 2,
}


def calculate_risk_score(findings: Iterable[Finding]) -> int:
    """
    Calculate an overall Docker security risk score.

    The score is based on the severity of detected findings.
    The maximum score is capped at 100.
    """

    raw_score = sum(
        SEVERITY_WEIGHTS.get(finding.severity.upper(), 0)
        for finding in findings
    )

    return min(raw_score, 100)


def get_risk_level(score: int) -> str:
    """
    Convert a numerical risk score into a risk level.
    """

    if score >= 80:
        return "CRITICAL"

    if score >= 60:
        return "HIGH"

    if score >= 30:
        return "MEDIUM"

    if score > 0:
        return "LOW"

    return "SECURE"


def get_severity_counts(findings: Iterable[Finding]) -> dict[str, int]:
    """
    Return the number of findings for each severity.
    """

    counts = Counter(
        finding.severity.upper()
        for finding in findings
    )

    return {
        "CRITICAL": counts.get("CRITICAL", 0),
        "HIGH": counts.get("HIGH", 0),
        "MEDIUM": counts.get("MEDIUM", 0),
        "LOW": counts.get("LOW", 0),
    }


def calculate_risk(findings: Iterable[Finding]) -> dict:
    """
    Generate a complete risk assessment.
    """

    findings = list(findings)

    score = calculate_risk_score(findings)
    level = get_risk_level(score)
    severity_counts = get_severity_counts(findings)

    return {
        "score": score,
        "level": level,
        "severity_counts": severity_counts,
        "total_findings": len(findings),
    }