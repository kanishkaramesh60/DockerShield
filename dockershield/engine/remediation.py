from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

from dockershield.models import Finding


@dataclass(frozen=True)
class RemediationRule:
    remediation_id: str
    rule_id: str
    title: str
    action: str
    rationale: str
    verification: str
    priority: str


REMEDIATION_RULES = [
    RemediationRule(
        remediation_id="REM-001",
        rule_id="DS015",
        title="Remove privileged container mode",
        action=(
            "Set privileged mode to false or remove the privileged "
            "configuration from the service."
        ),
        rationale=(
            "Privileged containers receive substantially broader access "
            "than normally isolated containers."
        ),
        verification=(
            "Verify that privileged mode is absent or explicitly set to false."
        ),
        priority="CRITICAL",
    ),
    RemediationRule(
        remediation_id="REM-002",
        rule_id="DS016",
        title="Remove Docker socket exposure",
        action=(
            "Remove the Docker socket from the service volume mounts unless "
            "Docker daemon access is explicitly required."
        ),
        rationale=(
            "Docker socket access can provide a container with significant "
            "control over Docker resources."
        ),
        verification=(
            "Verify that no service volume contains docker.sock."
        ),
        priority="CRITICAL",
    ),
    RemediationRule(
        remediation_id="REM-003",
        rule_id="DS017",
        title="Disable host networking",
        action=(
            "Remove host network mode and use an isolated Docker network "
            "unless host networking is required."
        ),
        rationale=(
            "Host networking reduces network namespace isolation."
        ),
        verification=(
            "Verify that network_mode is not set to host."
        ),
        priority="HIGH",
    ),
    RemediationRule(
        remediation_id="REM-004",
        rule_id="DS018",
        title="Disable host PID namespace",
        action=(
            "Remove host PID configuration unless sharing the host PID "
            "namespace is explicitly required."
        ),
        rationale=(
            "Host PID sharing reduces process namespace isolation."
        ),
        verification=(
            "Verify that pid is not set to host."
        ),
        priority="HIGH",
    ),
    RemediationRule(
        remediation_id="REM-005",
        rule_id="DS019",
        title="Disable host IPC namespace",
        action=(
            "Remove host IPC configuration unless it is explicitly required."
        ),
        rationale=(
            "Host IPC sharing reduces inter-process isolation."
        ),
        verification=(
            "Verify that ipc is not set to host."
        ),
        priority="HIGH",
    ),
    RemediationRule(
        remediation_id="REM-006",
        rule_id="DS020",
        title="Remove unnecessary Linux capabilities",
        action=(
            "Remove dangerous capabilities that are not required by the "
            "application and keep only the minimum required capabilities."
        ),
        rationale=(
            "Excess Linux capabilities can increase the privileges available "
            "to a container."
        ),
        verification=(
            "Verify that dangerous capabilities identified by DS020 are absent."
        ),
        priority="HIGH",
    ),
    RemediationRule(
        remediation_id="REM-007",
        rule_id="DS021",
        title="Add a memory limit",
        action=(
            "Define an appropriate memory limit for the service."
        ),
        rationale=(
            "Resource limits help constrain excessive memory consumption."
        ),
        verification=(
            "Verify that the service has a non-zero memory limit."
        ),
        priority="MEDIUM",
    ),
    RemediationRule(
        remediation_id="REM-008",
        rule_id="DS022",
        title="Add a CPU limit",
        action=(
            "Define an appropriate CPU limit for the service."
        ),
        rationale=(
            "Resource limits help constrain excessive CPU consumption."
        ),
        verification=(
            "Verify that the service has a CPU limit."
        ),
        priority="MEDIUM",
    ),
]


def _build_rule_map() -> dict[str, RemediationRule]:
    return {
        rule.rule_id: rule
        for rule in REMEDIATION_RULES
    }


def _get_attack_path_rule_ids(
    attack_paths: Iterable[dict] | None,
) -> set[str]:
    rule_ids: set[str] = set()

    if attack_paths is None:
        return rule_ids

    for path in attack_paths:
        for rule_id in path.get("matched_rules", []):
            rule_ids.add(rule_id)

    return rule_ids


def generate_remediations(
    findings: Iterable[Finding],
    attack_paths: Iterable[dict] | None = None,
) -> list[dict]:
    """
    Generate deterministic remediation recommendations.

    A remediation is generated only when a finding has a corresponding
    remediation rule.

    Findings that participate in a detected attack path receive an
    attack-path impact flag and are prioritized before other findings.
    """
    findings = list(findings)
    rule_map = _build_rule_map()
    attack_path_rule_ids = _get_attack_path_rule_ids(attack_paths)

    remediations = []

    for finding in findings:
        rule = rule_map.get(finding.rule_id)

        if rule is None:
            continue

        affects_attack_path = finding.rule_id in attack_path_rule_ids

        remediations.append({
            "remediation_id": rule.remediation_id,
            "rule_id": rule.rule_id,
            "title": rule.title,
            "severity": finding.severity.upper(),
            "priority": rule.priority,
            "action": rule.action,
            "rationale": rule.rationale,
            "verification": rule.verification,
            "affects_attack_path": affects_attack_path,
        })

    remediations.sort(
        key=lambda item: (
            not item["affects_attack_path"],
            {
                "CRITICAL": 0,
                "HIGH": 1,
                "MEDIUM": 2,
                "LOW": 3,
            }.get(item["severity"], 4),
            item["rule_id"],
        )
    )

    return remediations


def summarize_remediations(
    findings: Iterable[Finding],
    attack_paths: Iterable[dict] | None = None,
) -> dict:
    remediations = generate_remediations(
        findings,
        attack_paths,
    )

    attack_path_fixes = sum(
        1
        for item in remediations
        if item["affects_attack_path"]
    )

    return {
        "total": len(remediations),
        "attack_path_fixes": attack_path_fixes,
        "remediations": remediations,
    }