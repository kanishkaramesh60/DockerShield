from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

from dockershield.models import Finding


@dataclass(frozen=True)
class ComplianceControl:
    control_id: str
    title: str
    description: str
    rule_ids: tuple[str, ...]


COMPLIANCE_CONTROLS = [
    ComplianceControl(
        control_id="CIS-5.3",
        title="Restrict privileged containers",
        description="Containers should not run with unnecessary privileged access.",
        rule_ids=("DS001", "DS015"),
    ),
    ComplianceControl(
        control_id="CIS-5.4",
        title="Restrict host namespace usage",
        description="Containers should not unnecessarily share host namespaces.",
        rule_ids=("DS005", "DS006", "DS007", "DS017", "DS018", "DS019"),
    ),
    ComplianceControl(
        control_id="CIS-5.5",
        title="Restrict sensitive host mounts",
        description="Containers should not unnecessarily expose sensitive host paths.",
        rule_ids=("DS003", "DS004", "DS016"),
    ),
    ComplianceControl(
        control_id="CIS-5.6",
        title="Restrict Linux capabilities",
        description="Containers should use only required Linux capabilities.",
        rule_ids=("DS008", "DS020"),
    ),
    ComplianceControl(
        control_id="CIS-5.7",
        title="Use resource limits",
        description="Containers should have appropriate resource constraints.",
        rule_ids=("DS009", "DS010", "DS021", "DS022"),
    ),
    ComplianceControl(
        control_id="CIS-4.1",
        title="Specify a non-root user",
        description="Docker images should avoid running applications as root when unnecessary.",
        rule_ids=("DS002", "DS011"),
    ),
    ComplianceControl(
        control_id="CIS-4.2",
        title="Use safer Dockerfile instructions",
        description="Dockerfiles should avoid unnecessarily risky build instructions.",
        rule_ids=("DS012", "DS014"),
    ),
    ComplianceControl(
        control_id="CIS-4.3",
        title="Avoid secrets in image configuration",
        description="Sensitive information should not be embedded in Docker image configuration.",
        rule_ids=("DS013",),
    ),
]


def evaluate_compliance(
    findings: Iterable[Finding],
) -> list[dict]:
    findings = list(findings)

    findings_by_rule: dict[str, list[Finding]] = {}

    for finding in findings:
        findings_by_rule.setdefault(finding.rule_id, []).append(finding)

    results = []

    for control in COMPLIANCE_CONTROLS:
        matched_findings = []

        for rule_id in control.rule_ids:
            matched_findings.extend(
                findings_by_rule.get(rule_id, [])
            )

        results.append(
            {
                "control_id": control.control_id,
                "title": control.title,
                "status": "FAIL" if matched_findings else "PASS",
                "finding_count": len(matched_findings),
                "rule_ids": list(control.rule_ids),
            }
        )

    return results


def calculate_compliance(findings: Iterable[Finding]) -> dict:
    results = evaluate_compliance(findings)

    total = len(results)
    passed = sum(
        1 for result in results
        if result["status"] == "PASS"
    )
    failed = total - passed

    percentage = (
        round((passed / total) * 100, 1)
        if total
        else 100.0
    )

    return {
        "total_controls": total,
        "passed": passed,
        "failed": failed,
        "compliance_percentage": percentage,
        "controls": results,
    }