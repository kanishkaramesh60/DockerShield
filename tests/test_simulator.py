from dockershield.models import Finding
from dockershield.engine.simulator import simulate_remediations

def make_finding(rule_id, severity="HIGH"):
    return Finding(
        rule_id=rule_id,
        severity=severity,
        title="Test",
        container="test",
        description="",
        evidence="",
        impact="",
        remediation="Fix it",
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
    result = simulate_remediations(findings, ["REM-001"])
    assert result["before"]["risk"]["score"] == 100
    assert result["after"]["risk"]["score"] == 99
    assert result["after"]["compliance"]["compliance_percentage"] == 50.0
    assert "PATH-002" in result["resolved_attack_paths"]
    assert "PATH-004" in result["resolved_attack_paths"]

def test_empty_simulation_does_not_change_results():
    findings = [make_finding("DS015", "CRITICAL")]
    result = simulate_remediations(findings, [])
    assert result["before"]["risk"] == result["after"]["risk"]
    assert result["resolved_attack_paths"] == []
