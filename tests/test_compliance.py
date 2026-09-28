from dockershield.engine.compliance import calculate_compliance
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


def test_empty_findings_are_fully_compliant():
    result = calculate_compliance([])

    assert result["compliance_percentage"] == 100.0
    assert result["percentage"] == 100.0
    assert result["failed"] == 0
    assert result["passed"] == result["total_controls"]


def test_dockerfile_findings_fail_expected_controls():
    findings = [
        make_finding("DS011"),
        make_finding("DS012"),
        make_finding("DS013", "CRITICAL"),
        make_finding("DS014"),
    ]

    result = calculate_compliance(findings)

    # With the expanded 11-control compliance model:
    # 8 controls pass and 3 controls fail.
    assert result["compliance_percentage"] == 72.73
    assert result["percentage"] == 72.73
    assert result["failed"] == 3
    assert result["passed"] == 8
    assert result["total_controls"] == 11


def test_privileged_compose_fails_privileged_control():
    findings = [
        make_finding("DS015", "CRITICAL"),
    ]

    result = calculate_compliance(findings)

    assert result["compliance_percentage"] < 100.0

    privileged_control = next(
        control
        for control in result["controls"]
        if control["control_id"] == "CIS-5.3"
    )

    assert privileged_control["status"] == "FAIL"
    assert "DS015" in privileged_control["matched_rules"]


def test_read_only_and_no_new_privileges_controls():
    findings = [
        make_finding("DS034", "MEDIUM"),
        make_finding("DS035", "MEDIUM"),
    ]

    result = calculate_compliance(findings)

    read_only_control = next(
        control
        for control in result["controls"]
        if control["control_id"] == "DS-HARD-01"
    )

    no_new_privileges_control = next(
        control
        for control in result["controls"]
        if control["control_id"] == "DS-HARD-02"
    )

    assert read_only_control["status"] == "FAIL"
    assert "DS034" in read_only_control["matched_rules"]

    assert no_new_privileges_control["status"] == "FAIL"
    assert "DS035" in no_new_privileges_control["matched_rules"]