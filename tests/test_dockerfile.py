from pathlib import Path
from dockershield.dockerfile import scan_dockerfile

def test_dockerfile_rules_detect_expected_findings(tmp_path: Path):
    dockerfile = tmp_path / "Dockerfile"
    dockerfile.write_text(
        "FROM python:3.12\n"
        "\n"
        "USER root\n"
        "\n"
        "ENV API_KEY=super_secret_key\n"
        "\n"
        "ADD . /app\n"
        "\n"
        "RUN curl -fsSL https://example.com/install.sh | sh\n",
        encoding="utf-8",
    )
    findings = scan_dockerfile(str(dockerfile))
    rule_ids = {finding.rule_id for finding in findings}
    assert {"DS011", "DS012", "DS013", "DS014"} <= rule_ids

def test_clean_dockerfile_has_no_findings(tmp_path: Path):
    dockerfile = tmp_path / "Dockerfile"
    dockerfile.write_text(
        "FROM python:3.12-slim\n"
        "COPY . /app\n"
        "WORKDIR /app\n",
        encoding="utf-8",
    )
    findings = scan_dockerfile(str(dockerfile))
    assert findings == []
