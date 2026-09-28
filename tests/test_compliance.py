from dockershield.models import Finding
from dockershield.engine.compliance import calculate_compliance, evaluate_compliance

def make_finding(rule_id, severity="HIGH"):
    return Finding(
        rule_id=rule_id,
        severity=severity,
        title="Test",
        container="test",
        description="",
        evidence="",
        impact="",
        remediation="",
    )

def test_empty_findings_are_fully_compliant():
    result = calculate_compliance([])
    assert result["compliance_percentage"] == 100.0
    assert result["failed"] == 0

def test_dockerfile_findings_fail_expected_controls():
    findings = [
        make_finding("DS011"),
        make_finding("DS012"),
        make_finding("DS013", "CRITICAL"),
        make_finding("DS014"),
    ]
    result = calculate_compliance(findings)
    assert result["compliance_percentage"] == 62.5
    assert result["failed"] == 3

def test_control_status_is_pass_or_fail():
    results = evaluate_compliance([])
    assert results
    assert all(item["status"] == "PASS" for item in results)
