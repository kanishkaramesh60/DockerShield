from dockershield.engine.simulator import simulate_remediations
from dockershield.models import Finding


def make_finding(
    rule_id: str,
    severity: str = "HIGH",
) -> Finding:
    return Finding(
        rule_id=rule_id,
        severity=severity,
        title=f"Test finding {rule_id}",
        container="test-container",
        description="Test finding",
        evidence="Test evidence",
        impact="Test impact",
        remediation="Test remediation",
    )


def test_simulation_changes_runtime_findings():
    findings = [
        make_finding("DS015", "CRITICAL"),
        make_finding("DS016", "CRITICAL"),
        make_finding("DS017"),
        make_finding("DS018"),
        make_finding("DS019"),
        make_finding("DS020"),
        make_finding("DS021", "MEDIUM"),
        make_finding("DS022", "MEDIUM"),
    ]

    result = simulate_remediations(
        findings,
        ["REM-001"],
    )

    assert result["before"]["risk"]["score"] == 100

    assert result["after"]["risk"]["score"] == 99

    # The compliance model now contains 11 controls.
    # After REM-001 removes DS015:
    # 7 controls pass and 4 controls fail.
    assert (
        result["after"]["compliance"]["compliance_percentage"]
        == 63.64
    )

    assert (
        result["after"]["compliance"]["percentage"]
        == 63.64
    )