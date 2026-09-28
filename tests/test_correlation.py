from dockershield.models import Finding
from dockershield.engine.correlation import correlate_findings, summarize_correlations

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

def test_no_correlation_for_unrelated_dockerfile_findings():
    findings = [
        make_finding("DS011"),
        make_finding("DS012"),
        make_finding("DS013", "CRITICAL"),
        make_finding("DS014"),
    ]
    assert correlate_findings(findings) == []

def test_privilege_correlation():
    findings = [
        make_finding("DS015", "CRITICAL"),
        make_finding("DS020", "HIGH"),
    ]
    correlations = correlate_findings(findings)
    ids = {item["correlation_id"] for item in correlations}
    assert "CORR-001" in ids

def test_correlation_summary_accepts_findings():
    findings = [
        make_finding("DS015", "CRITICAL"),
        make_finding("DS020", "HIGH"),
    ]
    summary = summarize_correlations(findings)
    assert summary["total"] >= 1
