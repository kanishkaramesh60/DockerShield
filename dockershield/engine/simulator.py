from __future__ import annotations

from typing import Iterable

from dockershield.models import Finding
from dockershield.engine.risk import calculate_risk
from dockershield.engine.compliance import calculate_compliance
from dockershield.engine.correlation import summarize_correlations
from dockershield.engine.attack_path import summarize_attack_paths
from dockershield.engine.remediation import REMEDIATION_RULES


def _remediation_rule_ids(remediation_ids: Iterable[str]) -> set[str]:
    requested = {item.upper() for item in remediation_ids}

    return {
        rule.rule_id
        for rule in REMEDIATION_RULES
        if rule.remediation_id.upper() in requested
        or rule.rule_id.upper() in requested
    }


def simulate_remediations(
    findings: Iterable[Finding],
    remediation_ids: Iterable[str],
) -> dict:
    """
    Simulate remediation in memory.

    This does not modify Docker, Compose files,
    Dockerfiles, or the host system.
    """

    findings = list(findings)
    remediation_ids = list(remediation_ids)

    selected_rule_ids = _remediation_rule_ids(
        remediation_ids
    )

    before_attack_paths = summarize_attack_paths(
        findings
    )

    remaining_findings = [
        finding
        for finding in findings
        if finding.rule_id not in selected_rule_ids
    ]

    after_attack_paths = summarize_attack_paths(
        remaining_findings
    )

    before = {
        "findings": len(findings),
        "risk": calculate_risk(findings),
        "compliance": calculate_compliance(findings),
        "correlations": summarize_correlations(findings),
        "attack_paths": before_attack_paths,
    }

    after = {
        "findings": len(remaining_findings),
        "risk": calculate_risk(remaining_findings),
        "compliance": calculate_compliance(
            remaining_findings
        ),
        "correlations": summarize_correlations(
            remaining_findings
        ),
        "attack_paths": after_attack_paths,
    }

    before_path_ids = {
        path["path_id"]
        for path in before_attack_paths["paths"]
    }

    after_path_ids = {
        path["path_id"]
        for path in after_attack_paths["paths"]
    }

    return {
        "requested_remediations": remediation_ids,
        "selected_rule_ids": sorted(
            selected_rule_ids
        ),
        "before": before,
        "after": after,
        "resolved_attack_paths": sorted(
            before_path_ids - after_path_ids
        ),
        "remaining_attack_paths": sorted(
            after_path_ids
        ),
    }