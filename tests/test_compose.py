from pathlib import Path

from dockershield.compose import scan_compose


def test_clean_compose_has_no_security_findings(tmp_path: Path):
    compose = tmp_path / "compose.yml"

    compose.write_text(
        "services:\n"
        "  app:\n"
        "    image: nginx:1.27\n"
        "    read_only: true\n"
        "    mem_limit: 256m\n"
        "    cpus: \"0.50\"\n"
        "    security_opt:\n"
        "      - no-new-privileges:true\n",
        encoding="utf-8",
    )

    findings = scan_compose(str(compose))

    assert findings == []


def test_privileged_compose_service(tmp_path: Path):
    compose = tmp_path / "compose.yml"

    compose.write_text(
        "services:\n"
        "  app:\n"
        "    image: nginx:1.27\n"
        "    privileged: true\n",
        encoding="utf-8",
    )

    findings = scan_compose(str(compose))

    rule_ids = {finding.rule_id for finding in findings}

    assert "DS015" in rule_ids


def test_docker_socket_mount(tmp_path: Path):
    compose = tmp_path / "compose.yml"

    compose.write_text(
        "services:\n"
        "  app:\n"
        "    image: nginx:1.27\n"
        "    volumes:\n"
        "      - /var/run/docker.sock:/var/run/docker.sock\n",
        encoding="utf-8",
    )

    findings = scan_compose(str(compose))

    rule_ids = {finding.rule_id for finding in findings}

    assert "DS016" in rule_ids


def test_host_network(tmp_path: Path):
    compose = tmp_path / "compose.yml"

    compose.write_text(
        "services:\n"
        "  app:\n"
        "    image: nginx:1.27\n"
        "    network_mode: host\n"
        "    read_only: true\n"
        "    mem_limit: 256m\n"
        "    cpus: \"0.50\"\n"
        "    security_opt:\n"
        "      - no-new-privileges:true\n",
        encoding="utf-8",
    )

    findings = scan_compose(str(compose))

    rule_ids = {finding.rule_id for finding in findings}

    assert rule_ids == {"DS017"}


def test_host_pid(tmp_path: Path):
    compose = tmp_path / "compose.yml"

    compose.write_text(
        "services:\n"
        "  app:\n"
        "    image: nginx:1.27\n"
        "    pid: host\n",
        encoding="utf-8",
    )

    findings = scan_compose(str(compose))

    rule_ids = {finding.rule_id for finding in findings}

    assert "DS018" in rule_ids


def test_host_ipc(tmp_path: Path):
    compose = tmp_path / "compose.yml"

    compose.write_text(
        "services:\n"
        "  app:\n"
        "    image: nginx:1.27\n"
        "    ipc: host\n",
        encoding="utf-8",
    )

    findings = scan_compose(str(compose))

    rule_ids = {finding.rule_id for finding in findings}

    assert "DS019" in rule_ids


def test_dangerous_capability(tmp_path: Path):
    compose = tmp_path / "compose.yml"

    compose.write_text(
        "services:\n"
        "  app:\n"
        "    image: nginx:1.27\n"
        "    cap_add:\n"
        "      - SYS_ADMIN\n",
        encoding="utf-8",
    )

    findings = scan_compose(str(compose))

    rule_ids = {finding.rule_id for finding in findings}

    assert "DS020" in rule_ids


def test_missing_memory_limit(tmp_path: Path):
    compose = tmp_path / "compose.yml"

    compose.write_text(
        "services:\n"
        "  app:\n"
        "    image: nginx:1.27\n",
        encoding="utf-8",
    )

    findings = scan_compose(str(compose))

    rule_ids = {finding.rule_id for finding in findings}

    assert "DS021" in rule_ids


def test_missing_cpu_limit(tmp_path: Path):
    compose = tmp_path / "compose.yml"

    compose.write_text(
        "services:\n"
        "  app:\n"
        "    image: nginx:1.27\n",
        encoding="utf-8",
    )

    findings = scan_compose(str(compose))

    rule_ids = {finding.rule_id for finding in findings}

    assert "DS022" in rule_ids


def test_writable_root_filesystem(tmp_path: Path):
    compose = tmp_path / "compose.yml"

    compose.write_text(
        "services:\n"
        "  app:\n"
        "    image: nginx:1.27\n"
        "    read_only: false\n"
        "    mem_limit: 256m\n"
        "    cpus: \"0.50\"\n"
        "    security_opt:\n"
        "      - no-new-privileges:true\n",
        encoding="utf-8",
    )

    findings = scan_compose(str(compose))

    rule_ids = {finding.rule_id for finding in findings}

    assert rule_ids == {"DS034"}


def test_no_new_privileges_missing(tmp_path: Path):
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

    rule_ids = {finding.rule_id for finding in findings}

    assert rule_ids == {"DS035"}


def test_no_new_privileges_enabled(tmp_path: Path):
    compose = tmp_path / "compose.yml"

    compose.write_text(
        "services:\n"
        "  app:\n"
        "    image: nginx:1.27\n"
        "    read_only: true\n"
        "    mem_limit: 256m\n"
        "    cpus: \"0.50\"\n"
        "    security_opt:\n"
        "      - no-new-privileges:true\n",
        encoding="utf-8",
    )

    findings = scan_compose(str(compose))

    assert findings == []