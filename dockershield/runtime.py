from __future__ import annotations

from dockershield.models import Finding


# ============================================================
# Runtime Security Rules
# ============================================================

def check_privileged(container) -> Finding | None:
    attrs = container.attrs
    host_config = attrs.get("HostConfig", {})

    if host_config.get("Privileged", False):
        return Finding(
            rule_id="DS001",
            severity="CRITICAL",
            title="Privileged container",
            container=container.name,
            description=(
                "The container is running with privileged mode enabled."
            ),
            evidence="HostConfig.Privileged=true",
            impact=(
                "Privileged containers have significantly reduced "
                "isolation from the Docker host."
            ),
            remediation=(
                "Remove privileged mode and grant only the specific "
                "capabilities required by the application."
            ),
        )

    return None


def check_root_user(container) -> Finding | None:
    attrs = container.attrs
    config = attrs.get("Config", {})

    user = config.get("User", "")

    if user in ("0", "root"):
        return Finding(
            rule_id="DS002",
            severity="HIGH",
            title="Container configured to run as root",
            container=container.name,
            description=(
                "The container configuration explicitly specifies "
                "the root user."
            ),
            evidence=f"Config.User={user}",
            impact=(
                "A process compromise can provide root privileges "
                "inside the container and increase the impact of "
                "other container weaknesses."
            ),
            remediation=(
                "Create and use a dedicated non-root user for the "
                "application."
            ),
        )

    return None


def check_docker_socket(container) -> Finding | None:
    attrs = container.attrs
    mounts = attrs.get("Mounts", [])

    for mount in mounts:
        source = mount.get("Source", "")
        destination = mount.get("Destination", "")

        if (
            source.endswith("docker.sock")
            or destination == "/var/run/docker.sock"
        ):
            return Finding(
                rule_id="DS003",
                severity="CRITICAL",
                title="Docker socket exposed to container",
                container=container.name,
                description=(
                    "The Docker Engine socket is mounted into the "
                    "container."
                ),
                evidence=(
                    f"Source={source}, Destination={destination}"
                ),
                impact=(
                    "Access to the Docker socket can allow a container "
                    "to interact with the Docker Engine."
                ),
                remediation=(
                    "Remove the Docker socket mount unless it is "
                    "strictly required. Prefer a restricted API proxy "
                    "when Docker API access is necessary."
                ),
            )

    return None


def check_host_mount(container) -> Finding | None:
    attrs = container.attrs
    mounts = attrs.get("Mounts", [])

    dangerous_sources = {
        "/",
        "/etc",
        "/var",
        "/home",
        "/root",
        "/proc",
        "/sys",
        "/dev",
    }

    for mount in mounts:
        source = mount.get("Source", "")
        destination = mount.get("Destination", "")

        if source in dangerous_sources:
            return Finding(
                rule_id="DS004",
                severity="HIGH",
                title="Sensitive host filesystem mount",
                container=container.name,
                description=(
                    "The container has a mount from a sensitive "
                    "host filesystem location."
                ),
                evidence=(
                    f"Source={source}, Destination={destination}"
                ),
                impact=(
                    "Sensitive host filesystem access can weaken "
                    "container isolation and expose host resources."
                ),
                remediation=(
                    "Remove the host filesystem mount or replace it "
                    "with the smallest required application-specific "
                    "directory."
                ),
            )

    return None


def check_host_network(container) -> Finding | None:
    attrs = container.attrs
    host_config = attrs.get("HostConfig", {})

    network_mode = host_config.get("NetworkMode", "")

    if network_mode == "host":
        return Finding(
            rule_id="DS005",
            severity="HIGH",
            title="Host network mode enabled",
            container=container.name,
            description=(
                "The container uses the host network namespace."
            ),
            evidence="HostConfig.NetworkMode=host",
            impact=(
                "Host networking reduces network isolation and can "
                "expose host network services to the container."
            ),
            remediation=(
                "Use an isolated Docker network unless host networking "
                "is explicitly required."
            ),
        )

    return None


def check_host_pid(container) -> Finding | None:
    attrs = container.attrs
    host_config = attrs.get("HostConfig", {})

    pid_mode = host_config.get("PidMode", "")

    if pid_mode == "host":
        return Finding(
            rule_id="DS006",
            severity="HIGH",
            title="Host PID namespace enabled",
            container=container.name,
            description=(
                "The container shares the host PID namespace."
            ),
            evidence="HostConfig.PidMode=host",
            impact=(
                "Processes running on the host may become visible "
                "from the container."
            ),
            remediation=(
                "Remove host PID mode unless it is explicitly required."
            ),
        )

    return None


def check_host_ipc(container) -> Finding | None:
    attrs = container.attrs
    host_config = attrs.get("HostConfig", {})

    ipc_mode = host_config.get("IpcMode", "")

    if ipc_mode == "host":
        return Finding(
            rule_id="DS007",
            severity="HIGH",
            title="Host IPC namespace enabled",
            container=container.name,
            description=(
                "The container shares the host IPC namespace."
            ),
            evidence="HostConfig.IpcMode=host",
            impact=(
                "Sharing the host IPC namespace reduces process "
                "isolation."
            ),
            remediation=(
                "Remove host IPC mode unless explicitly required."
            ),
        )

    return None


def check_dangerous_capabilities(container) -> Finding | None:
    attrs = container.attrs
    host_config = attrs.get("HostConfig", {})

    cap_add = host_config.get("CapAdd") or []

    dangerous = {
        "SYS_ADMIN",
        "SYS_PTRACE",
        "NET_ADMIN",
        "NET_RAW",
        "SYS_MODULE",
        "DAC_READ_SEARCH",
    }

    detected = sorted(
        capability
        for capability in cap_add
        if capability.upper() in dangerous
    )

    if detected:
        return Finding(
            rule_id="DS008",
            severity="HIGH",
            title="Dangerous Linux capability enabled",
            container=container.name,
            description=(
                "The container has one or more capabilities that "
                "can significantly increase its privileges."
            ),
            evidence=f"CapAdd={', '.join(detected)}",
            impact=(
                "Excessive Linux capabilities can weaken container "
                "isolation and increase the impact of exploitation."
            ),
            remediation=(
                "Remove unnecessary capabilities and follow the "
                "principle of least privilege."
            ),
        )

    return None


def check_memory_limit(container) -> Finding | None:
    attrs = container.attrs
    host_config = attrs.get("HostConfig", {})

    memory = host_config.get("Memory", 0)

    if not memory:
        return Finding(
            rule_id="DS009",
            severity="MEDIUM",
            title="Memory limit not configured",
            container=container.name,
            description=(
                "The container does not have a memory limit configured."
            ),
            evidence="HostConfig.Memory=0",
            impact=(
                "An uncontrolled container can consume excessive "
                "memory and affect other workloads."
            ),
            remediation=(
                "Configure an appropriate memory limit based on "
                "application requirements."
            ),
        )

    return None


def check_cpu_limit(container) -> Finding | None:
    attrs = container.attrs
    host_config = attrs.get("HostConfig", {})

    nano_cpus = host_config.get("NanoCpus", 0)
    cpu_quota = host_config.get("CpuQuota", 0)

    if not nano_cpus and not cpu_quota:
        return Finding(
            rule_id="DS010",
            severity="MEDIUM",
            title="CPU limit not configured",
            container=container.name,
            description=(
                "The container does not have a CPU limit configured."
            ),
            evidence=(
                "HostConfig.NanoCpus=0 and HostConfig.CpuQuota=0"
            ),
            impact=(
                "Uncontrolled CPU consumption can affect the "
                "availability of other workloads."
            ),
            remediation=(
                "Configure an appropriate CPU limit for the workload."
            ),
        )

    return None


# ============================================================
# Runtime Rule Registry
# ============================================================

SECURITY_RULES = [
    check_privileged,
    check_root_user,
    check_docker_socket,
    check_host_mount,
    check_host_network,
    check_host_pid,
    check_host_ipc,
    check_dangerous_capabilities,
    check_memory_limit,
    check_cpu_limit,
]


# ============================================================
# Runtime Container Scanner
# ============================================================

def scan_container(container) -> list[Finding]:
    findings: list[Finding] = []

    for rule in SECURITY_RULES:
        try:
            finding = rule(container)

            if finding:
                findings.append(finding)

        except Exception as exc:
            print(
                f"[WARNING] Rule {rule.__name__} failed for "
                f"{container.name}: {exc}"
            )

    return findings