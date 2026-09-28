from dockershield.models import Finding
from dockershield.engine.remediation import generate_remediations

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

def test_dockerfile_findings_have_no_runtime_remediation_entries():
    findings = [
        make_finding("DS011"),
        make_finding("DS012"),
        make_finding("DS013", "CRITICAL"),
        make_finding("DS014"),
    ]
    assert generate_remediations(findings) == []

def test_compose_runtime_findings_generate_remediations():
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
    remediations = generate_remediations(findings)
    ids = {item["remediation_id"] for item in remediations}
    assert len(remediations) == 8
    assert {"REM-001", "REM-002", "REM-003", "REM-004",
            "REM-005", "REM-006", "REM-007", "REM-008"} <= ids
