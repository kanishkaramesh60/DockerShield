from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

from dockershield.models import Finding
from dockershield.engine.risk import calculate_risk
from dockershield.engine.compliance import calculate_compliance
from dockershield.engine.correlation import summarize_correlations
from dockershield.engine.attack_path import summarize_attack_paths


DEFAULT_BASELINE_PATH = Path("data") / "baseline.json"


def _finding_key(finding: Finding) -> str:
    return f"{finding.rule_id}:{finding.container}"


def create_snapshot(findings: Iterable[Finding]) -> dict:
    """
    Create a security snapshot from the current findings.
    """

    findings = list(findings)

    risk = calculate_risk(findings)
    compliance = calculate_compliance(findings)
    correlations = summarize_correlations(findings)
    attack_paths = summarize_attack_paths(findings)

    return {
        "created_at": datetime.now(timezone.utc).isoformat(),
        "findings": [
            {
                "rule_id": finding.rule_id,
                "severity": finding.severity,
                "title": finding.title,
                "container": finding.container,
            }
            for finding in findings
        ],
        "risk": risk,
        "compliance": compliance,
        "correlations": correlations,
        "attack_paths": attack_paths,
    }


def save_baseline(
    findings: Iterable[Finding],
    path: Path = DEFAULT_BASELINE_PATH,
) -> dict:
    """
    Save the current security state as a baseline.
    """

    snapshot = create_snapshot(findings)

    path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    path.write_text(
        json.dumps(
            snapshot,
            indent=2,
        ),
        encoding="utf-8",
    )

    return snapshot


def load_baseline(
    path: Path = DEFAULT_BASELINE_PATH,
) -> dict:
    """
    Load a previously saved baseline.
    """

    if not path.exists():
        raise FileNotFoundError(
            f"Baseline not found: {path}"
        )

    return json.loads(
        path.read_text(
            encoding="utf-8"
        )
    )


def compare_with_baseline(
    findings: Iterable[Finding],
    baseline: dict,
) -> dict:
    """
    Compare the current scan with a saved baseline.
    """

    findings = list(findings)

    baseline_findings = {
        f"{item['rule_id']}:{item['container']}"
        for item in baseline.get("findings", [])
    }

    current_findings = {
        _finding_key(finding)
        for finding in findings
    }

    resolved = sorted(
        baseline_findings - current_findings
    )

    new_findings = sorted(
        current_findings - baseline_findings
    )

    unchanged = sorted(
        baseline_findings & current_findings
    )

    baseline_risk = baseline.get(
        "risk",
        {},
    ).get(
        "score",
        0,
    )

    current_risk = calculate_risk(
        findings
    )["score"]

    baseline_compliance = baseline.get(
        "compliance",
        {},
    ).get(
        "compliance_percentage",
        0.0,
    )

    current_compliance = calculate_compliance(
        findings
    )["compliance_percentage"]

    return {
        "baseline_findings": len(baseline_findings),
        "current_findings": len(current_findings),
        "resolved": resolved,
        "new": new_findings,
        "unchanged": unchanged,
        "risk_change": current_risk - baseline_risk,
        "compliance_change": round(
            current_compliance - baseline_compliance,
            1,
        ),
        "regression": bool(new_findings),
    }