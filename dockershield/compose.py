from __future__ import annotations

from pathlib import Path

import yaml

from dockershield.models import Finding


def scan_compose(path: str) -> list[Finding]:
    """
    Scan a Docker Compose file for common security issues.
    """

    compose_path = Path(path)

    if not compose_path.exists():
        raise FileNotFoundError(path)

    with compose_path.open("r", encoding="utf-8") as file:
        data = yaml.safe_load(file) or {}

    services = data.get("services", {})

    if not isinstance(services, dict):
        return []

    findings: list[Finding] = []

    for service_name, service in services.items():

        if not isinstance(service, dict):
            continue

        # ====================================================
        # DS015 - Privileged mode
        # ====================================================

        if service.get("privileged") is True:
            findings.append(
                Finding(
                    rule_id="DS015",
                    severity="CRITICAL",
                    title="Compose service uses privileged mode",
                    container=service_name,
                    description=(
                        "The Compose service is configured with "
                        "privileged mode."
                    ),
                    evidence=(
                        f"Service '{service_name}': "
                        "privileged: true"
                    ),
                    impact=(
                        "Privileged containers receive significantly "
                        "expanded access to the Docker host."
                    ),
                    remediation=(
                        "Remove privileged: true and grant only the "
                        "specific capabilities required by the application."
                    ),
                )
            )

        # ====================================================
        # DS016 - Docker socket
        # ====================================================

        volumes = service.get("volumes", [])

        if not isinstance(volumes, list):
            volumes = []

        docker_socket_found = False

        for volume in volumes:

            if isinstance(volume, str):

                if "docker.sock" in volume:
                    docker_socket_found = True

            elif isinstance(volume, dict):

                source = str(volume.get("source", ""))

                if "docker.sock" in source:
                    docker_socket_found = True

        if docker_socket_found:
            findings.append(
                Finding(
                    rule_id="DS016",
                    severity="CRITICAL",
                    title="Docker socket exposed to Compose service",
                    container=service_name,
                    description=(
                        "The service has access to the Docker daemon "
                        "socket."
                    ),
                    evidence=(
                        f"Service '{service_name}' has a volume "
                        "containing docker.sock."
                    ),
                    impact=(
                        "Access to the Docker daemon socket can provide "
                        "control over Docker resources and may allow "
                        "significant host impact."
                    ),
                    remediation=(
                        "Avoid mounting /var/run/docker.sock into "
                        "application containers unless absolutely "
                        "necessary."
                    ),
                )
            )

        # ====================================================
        # DS017 - Host network
        # ====================================================

        if service.get("network_mode") == "host":
            findings.append(
                Finding(
                    rule_id="DS017",
                    severity="HIGH",
                    title="Compose service uses host networking",
                    container=service_name,
                    description=(
                        "The service uses the host network namespace."
                    ),
                    evidence=(
                        f"Service '{service_name}': "
                        "network_mode: host"
                    ),
                    impact=(
                        "Host networking reduces network isolation between "
                        "the container and Docker host."
                    ),
                    remediation=(
                        "Use a dedicated Docker network instead of "
                        "host networking where possible."
                    ),
                )
            )

        # ====================================================
        # DS018 - Host PID
        # ====================================================

        if service.get("pid") == "host":
            findings.append(
                Finding(
                    rule_id="DS018",
                    severity="HIGH",
                    title="Compose service uses host PID namespace",
                    container=service_name,
                    description=(
                        "The service shares the host PID namespace."
                    ),
                    evidence=(
                        f"Service '{service_name}': pid: host"
                    ),
                    impact=(
                        "Processes from the host may become visible to "
                        "the container, reducing process isolation."
                    ),
                    remediation=(
                        "Avoid pid: host unless the application has a "
                        "documented requirement for it."
                    ),
                )
            )

        # ====================================================
        # DS019 - Host IPC
        # ====================================================

        if service.get("ipc") == "host":
            findings.append(
                Finding(
                    rule_id="DS019",
                    severity="HIGH",
                    title="Compose service uses host IPC namespace",
                    container=service_name,
                    description=(
                        "The service shares the host IPC namespace."
                    ),
                    evidence=(
                        f"Service '{service_name}': ipc: host"
                    ),
                    impact=(
                        "Sharing the host IPC namespace reduces "
                        "container isolation."
                    ),
                    remediation=(
                        "Avoid ipc: host unless explicitly required."
                    ),
                )
            )

        # ====================================================
        # DS020 - Dangerous capabilities
        # ====================================================

        cap_add = service.get("cap_add", [])

        dangerous_capabilities = {
            "SYS_ADMIN",
            "NET_ADMIN",
            "SYS_PTRACE",
            "SYS_MODULE",
            "DAC_READ_SEARCH",
            "DAC_OVERRIDE",
            "NET_RAW",
        }

        detected_capabilities: list[str] = []

        if isinstance(cap_add, list):

            for capability in cap_add:

                capability_name = str(capability).upper()

                if capability_name in dangerous_capabilities:
                    detected_capabilities.append(capability_name)

        if detected_capabilities:
            findings.append(
                Finding(
                    rule_id="DS020",
                    severity="HIGH",
                    title="Dangerous Linux capabilities detected",
                    container=service_name,
                    description=(
                        "The Compose service requests Linux capabilities "
                        "that can increase its privileges."
                    ),
                    evidence=(
                        f"Service '{service_name}': "
                        f"cap_add={detected_capabilities}"
                    ),
                    impact=(
                        "Excessive Linux capabilities can weaken container "
                        "isolation and increase the impact of compromise."
                    ),
                    remediation=(
                        "Remove unnecessary capabilities and follow the "
                        "principle of least privilege."
                    ),
                )
            )

        # ====================================================
        # DS021 - Memory limit
        # ====================================================

        memory_limit = service.get("mem_limit")

        if not memory_limit:
            findings.append(
                Finding(
                    rule_id="DS021",
                    severity="MEDIUM",
                    title="Memory limit not configured",
                    container=service_name,
                    description=(
                        "The Compose service does not define a memory "
                        "limit."
                    ),
                    evidence=(
                        f"Service '{service_name}' has no mem_limit."
                    ),
                    impact=(
                        "An application consuming excessive memory could "
                        "affect other containers or the Docker host."
                    ),
                    remediation=(
                        "Define an appropriate memory limit for the "
                        "service."
                    ),
                )
            )

        # ====================================================
        # DS022 - CPU limit
        # ====================================================

        cpu_limit = (
            service.get("cpus")
            or service.get("cpu_quota")
            or service.get("cpu_period")
        )

        if not cpu_limit:
            findings.append(
                Finding(
                    rule_id="DS022",
                    severity="MEDIUM",
                    title="CPU limit not configured",
                    container=service_name,
                    description=(
                        "The Compose service does not define a CPU "
                        "resource limit."
                    ),
                    evidence=(
                        f"Service '{service_name}' has no CPU limit."
                    ),
                    impact=(
                        "A container consuming excessive CPU could "
                        "affect other workloads."
                    ),
                    remediation=(
                        "Define an appropriate CPU limit for the service."
                    ),
                )
            )

        # ====================================================
        # DS034 - Writable root filesystem
        # ====================================================

        read_only = service.get("read_only", False)

        if read_only is not True:
            findings.append(
                Finding(
                    rule_id="DS034",
                    severity="MEDIUM",
                    title="Compose service root filesystem is writable",
                    container=service_name,
                    description=(
                        "The Compose service does not enable a "
                        "read-only root filesystem."
                    ),
                    evidence=(
                        f"Service '{service_name}': "
                        f"read_only={read_only!r}"
                    ),
                    impact=(
                        "A writable root filesystem can allow a compromised "
                        "application to modify files inside the container."
                    ),
                    remediation=(
                        "Set read_only: true where the application does "
                        "not require writes to its root filesystem."
                    ),
                )
            )

        # ====================================================
        # DS035 - No-new-privileges
        # ====================================================

        security_opt = service.get("security_opt", [])

        if not isinstance(security_opt, list):
            security_opt = []

        normalized_security_options = {
            str(option).strip().lower()
            for option in security_opt
        }

        no_new_privileges_enabled = any(
            option in {
                "no-new-privileges",
                "no-new-privileges:true",
                "no-new-privileges=true",
            }
            for option in normalized_security_options
        )

        if not no_new_privileges_enabled:
            findings.append(
                Finding(
                    rule_id="DS035",
                    severity="MEDIUM",
                    title=(
                        "Compose service does not enable "
                        "no-new-privileges"
                    ),
                    container=service_name,
                    description=(
                        "The Compose service does not explicitly enable "
                        "the no-new-privileges security option."
                    ),
                    evidence=(
                        f"Service '{service_name}': "
                        f"security_opt={security_opt}"
                    ),
                    impact=(
                        "Processes may potentially gain additional "
                        "privileges through setuid, setgid, or similar "
                        "mechanisms."
                    ),
                    remediation=(
                        "Add no-new-privileges:true unless the application "
                        "requires privilege transitions."
                    ),
                )
            )

    return findings