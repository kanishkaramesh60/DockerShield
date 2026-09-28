from dockershield.models import Finding
from dockershield.engine.risk import (
    calculate_risk_score,
    get_risk_level,
    get_severity_counts,
    calculate_risk,
)

def make_finding(severity, rule_id="TEST"):
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

def test_empty_findings_are_secure():
    assert calculate_risk([])["score"] == 0
    assert calculate_risk([])["level"] == "SECURE"

def test_severity_weights():
    findings = [
        make_finding("CRITICAL", "C1"),
        make_finding("HIGH", "H1"),
        make_finding("MEDIUM", "M1"),
        make_finding("LOW", "L1"),
    ]
    assert calculate_risk_score(findings) == 49

def test_risk_score_is_capped_at_100():
    findings = [make_finding("CRITICAL", f"C{i}") for i in range(10)]
    assert calculate_risk_score(findings) == 100

def test_risk_levels():
    assert get_risk_level(0) == "SECURE"
    assert get_risk_level(10) == "LOW"
    assert get_risk_level(30) == "MEDIUM"
    assert get_risk_level(60) == "HIGH"
    assert get_risk_level(80) == "CRITICAL"

def test_severity_counts():
    findings = [
        make_finding("CRITICAL", "C1"),
        make_finding("HIGH", "H1"),
        make_finding("HIGH", "H2"),
        make_finding("LOW", "L1"),
    ]
    assert get_severity_counts(findings) == {
        "CRITICAL": 1,
        "HIGH": 2,
        "MEDIUM": 0,
        "LOW": 1,
    }
