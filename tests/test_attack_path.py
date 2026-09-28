from dockershield.models import Finding
from dockershield.engine.attack_path import analyze_attack_paths, summarize_attack_paths

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

def test_dockerfile_findings_have_no_runtime_attack_paths():
    findings = [
        make_finding("DS011"),
        make_finding("DS012"),
        make_finding("DS013", "CRITICAL"),
        make_finding("DS014"),
    ]
    assert analyze_attack_paths(findings) == []

def test_docker_socket_attack_path():
    paths = analyze_attack_paths([make_finding("DS016", "CRITICAL")])
    ids = {item["path_id"] for item in paths}
    assert "PATH-001" in ids

def test_combined_runtime_attack_path():
    findings = [
        make_finding("DS015", "CRITICAL"),
        make_finding("DS017", "HIGH"),
        make_finding("DS018", "HIGH"),
    ]
    paths = analyze_attack_paths(findings)
    ids = {item["path_id"] for item in paths}
    assert "PATH-004" in ids
    assert summarize_attack_paths(findings)["total"] >= 1
