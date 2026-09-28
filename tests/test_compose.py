from pathlib import Path
from dockershield.compose import scan_compose

def test_vulnerable_compose_detects_expected_rules(tmp_path: Path):
    compose = tmp_path / "compose.yml"
    compose.write_text(
        "services:\n"
        "  app:\n"
        "    image: nginx:latest\n"
        "    privileged: true\n"
        "    network_mode: host\n"
        "    pid: host\n"
        "    ipc: host\n"
        "    cap_add:\n"
        "      - SYS_ADMIN\n"
        "    volumes:\n"
        "      - /var/run/docker.sock:/var/run/docker.sock\n",
        encoding="utf-8",
    )
    findings = scan_compose(str(compose))
    rule_ids = {finding.rule_id for finding in findings}
    assert {"DS015", "DS016", "DS017", "DS018", "DS019", "DS020"} <= rule_ids

def test_clean_compose_has_no_security_findings(tmp_path: Path):
    compose = tmp_path / "compose.yml"
    compose.write_text(
        "services:\n"
        "  app:\n"
        "    image: nginx:1.27\n"
        "    read_only: true\n"
        "    mem_limit: 256m\n"
        "    cpus: \"0.50\"\n",
        encoding="utf-8",
    )
    findings = scan_compose(str(compose))
    assert findings == []
