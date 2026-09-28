from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from dockershield.models import Finding


@dataclass(frozen=True)
class ComplianceControl:
    control_id: str
    title: str
    description: str
    rule_ids: tuple[str, ...]


# CIS-aligned Docker hardening controls.
#
# These are DockerShield's mapped controls. They should not be interpreted
# as claiming that every individual DockerShield rule is a verbatim CIS
# Docker Benchmark check.
COMPLIANCE_CONTROLS = [
    ComplianceControl(
        control_id="CIS-5.3",
        title="Restrict privileged containers",
        description=(
            "Containers should not run with unrestricted privileged access."
        ),
        rule_ids=("DS001", "DS015"),
    ),
    ComplianceControl(
        control_id="CIS-5.4",
        title="Restrict host namespace usage",
        description=(
            "Containers should not unnecessarily share host namespaces."
        ),
        rule_ids=(
            "DS005",
            "DS006",
            "DS007",
            "DS017",
            "DS018",
            "DS019",
            "DS027",
        ),
    ),
    ComplianceControl(
        control_id="CIS-5.5",
        title="Restrict sensitive host mounts",
        description=(
            "Sensitive host resources should not be exposed to containers "
            "without a documented requirement."
        ),
        rule_ids=(
            "DS003",
            "DS004",
            "DS016",
            "DS025",
            "DS036",
        ),
    ),
    ComplianceControl(
        control_id="CIS-5.6",
        title="Restrict Linux capabilities",
        description=(
            "Containers should run with only the Linux capabilities "
            "required by the workload."
        ),
        rule_ids=(
            "DS008",
            "DS020",
            "DS026",
        ),
    ),
    ComplianceControl(
        control_id="CIS-5.7",
        title="Use resource limits",
        description=(
            "Container workloads should define appropriate CPU and "
            "memory limits."
        ),
        rule_ids=(
            "DS009",
            "DS010",
            "DS021",
            "DS022",
        ),
    ),
    ComplianceControl(
        control_id="CIS-4.1",
        title="Specify a non-root user",
        description=(
            "Container processes should avoid unnecessary root privileges."
        ),
        rule_ids=(
            "DS002",
            "DS011",
            "DS033",
        ),
    ),
    ComplianceControl(
        control_id="CIS-4.2",
        title="Use safer Dockerfile instructions",
        description=(
            "Dockerfiles should avoid unsafe instructions and patterns "
            "that can increase supply-chain or runtime risk."
        ),
        rule_ids=(
            "DS012",
            "DS014",
            "DS028",
            "DS029",
            "DS030",
            "DS031",
            "DS032",
        ),
    ),
    ComplianceControl(
        control_id="CIS-4.3",
        title="Avoid secrets in image configuration",
        description=(
            "Secrets should not be embedded in Docker image configuration."
        ),
        rule_ids=("DS013",),
    ),
    ComplianceControl(
        control_id="DS-HARD-01",
        title="Use a read-only root filesystem",
        description=(
            "Where application requirements permit, containers should "
            "use a read-only root filesystem."
        ),
        rule_ids=(
            "DS023",
            "DS034",
        ),
    ),
    ComplianceControl(
        control_id="DS-HARD-02",
        title="Prevent privilege escalation",
        description=(
            "Containers should prevent processes from gaining additional "
            "privileges when privilege transitions are not required."
        ),
        rule_ids=(
            "DS024",
            "DS035",
        ),
    ),
    ComplianceControl(
        control_id="DS-HARD-03",
        title="Restrict security profile weakening",
        description=(
            "Default kernel security profiles should remain enabled "
            "unless an explicit workload requirement exists."
        ),
        rule_ids=("DS037",),
    ),
]


def evaluate_compliance(
    findings: list[Finding],
) -> list[dict[str, Any]]:
    """
    Evaluate DockerShield findings against configured compliance controls.

    A control fails when one or more of its associated rule IDs are
    present in the findings.
    """

    finding_rule_ids = {
        finding.rule_id
        for finding in findings
    }

    results: list[dict[str, Any]] = []

    for control in COMPLIANCE_CONTROLS:
        matched_rules = [
            rule_id
            for rule_id in control.rule_ids
            if rule_id in finding_rule_ids
        ]

        status = "FAIL" if matched_rules else "PASS"

        results.append(
            {
                "control_id": control.control_id,
                "title": control.title,
                "description": control.description,
                "status": status,
                "matched_rules": matched_rules,
                "passed": status == "PASS",
            }
        )

    return results


def calculate_compliance(
    findings: list[Finding],
) -> dict[str, Any]:
    """
    Calculate DockerShield compliance results.

    Both the current 'percentage' field and the legacy
    'compliance_percentage' field are returned so existing
    dashboard, simulator, report, and test consumers remain compatible.
    """

    controls = evaluate_compliance(findings)

    total_controls = len(controls)

    passed_controls = sum(
        1
        for control in controls
        if control["status"] == "PASS"
    )

    failed_controls = total_controls - passed_controls

    compliance_percentage = (
        round(
            (passed_controls / total_controls) * 100,
            2,
        )
        if total_controls
        else 100.0
    )

    return {
        "total_controls": total_controls,
        "passed": passed_controls,
        "failed": failed_controls,

        # Current field
        "percentage": compliance_percentage,

        # Backward-compatible field used by existing code/tests
        "compliance_percentage": compliance_percentage,

        "controls": controls,
    }