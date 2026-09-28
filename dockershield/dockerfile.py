from __future__ import annotations

import re
from pathlib import Path

from dockershield.models import Finding


# ============================================================
# Dockerfile Security Rules
# ============================================================

def check_dockerfile_latest_tag(
    lines: list[str],
    dockerfile_path: Path,
) -> Finding | None:
    for line_number, line in enumerate(lines, start=1):
        stripped = line.strip()

        if stripped.upper().startswith("FROM "):
            image = (
                stripped
                .split(None, 1)[1]
                .split(" AS ", 1)[0]
                .strip()
            )

            # Ignore scratch because it is intentionally tagless.
            if image.lower() == "scratch":
                continue

            # Image is unpinned when neither a tag nor digest is present.
            if ":" not in image and "@" not in image:
                return Finding(
                    rule_id="DS028",
                    severity="MEDIUM",
                    title="Docker image uses implicit latest tag",
                    container=str(dockerfile_path),
                    description=(
                        "A FROM instruction does not specify an explicit "
                        "image tag or digest."
                    ),
                    evidence=f"Line {line_number}: {stripped}",
                    impact=(
                        "Using an implicit latest image can make builds "
                        "non-reproducible and may introduce unexpected "
                        "image changes."
                    ),
                    remediation=(
                        "Pin the base image to an explicit version tag "
                        "or, preferably, an immutable image digest."
                    ),
                )

    return None


def check_dockerfile_add_remote_url(
    lines: list[str],
    dockerfile_path: Path,
) -> Finding | None:
    for line_number, line in enumerate(lines, start=1):
        stripped = line.strip()

        if stripped.upper().startswith("ADD "):
            arguments = stripped[4:].strip()

            if (
                "http://" in arguments.lower()
                or "https://" in arguments.lower()
            ):
                return Finding(
                    rule_id="DS029",
                    severity="HIGH",
                    title="Dockerfile ADD downloads remote content",
                    container=str(dockerfile_path),
                    description=(
                        "The Dockerfile uses ADD with a remote URL."
                    ),
                    evidence=f"Line {line_number}: {stripped}",
                    impact=(
                        "Remote downloads during image builds can "
                        "introduce uncontrolled or unexpected "
                        "build-time content."
                    ),
                    remediation=(
                        "Download required artifacts explicitly, verify "
                        "their integrity, and prefer COPY for local files."
                    ),
                )

    return None


def check_dockerfile_package_upgrade(
    lines: list[str],
    dockerfile_path: Path,
) -> Finding | None:
    upgrade_patterns = (
        "apt-get upgrade",
        "apt upgrade",
        "yum upgrade",
        "dnf upgrade",
        "apk upgrade",
    )

    for line_number, line in enumerate(lines, start=1):
        stripped = line.strip()

        if not stripped.upper().startswith("RUN "):
            continue

        command = stripped[4:].lower()

        if any(pattern in command for pattern in upgrade_patterns):
            return Finding(
                rule_id="DS030",
                severity="MEDIUM",
                title="Dockerfile performs package upgrade during build",
                container=str(dockerfile_path),
                description=(
                    "The Dockerfile performs a broad operating-system "
                    "package upgrade."
                ),
                evidence=f"Line {line_number}: {stripped}",
                impact=(
                    "Uncontrolled package upgrades can reduce build "
                    "reproducibility and introduce unexpected dependency "
                    "changes."
                ),
                remediation=(
                    "Prefer a deliberately versioned base image and "
                    "install only the packages required by the application."
                ),
            )

    return None


def check_dockerfile_sudo(
    lines: list[str],
    dockerfile_path: Path,
) -> Finding | None:
    for line_number, line in enumerate(lines, start=1):
        stripped = line.strip()

        if not stripped.upper().startswith("RUN "):
            continue

        command = stripped[4:].lower()

        if re.search(r"(^|[;&|]\s*)sudo(?:\s|$)", command):
            return Finding(
                rule_id="DS031",
                severity="LOW",
                title="Dockerfile uses sudo",
                container=str(dockerfile_path),
                description=(
                    "The Dockerfile uses sudo during the image build."
                ),
                evidence=f"Line {line_number}: {stripped}",
                impact=(
                    "Using sudo during image construction can indicate "
                    "unnecessary privilege transitions and complicate "
                    "least-privilege image design."
                ),
                remediation=(
                    "Perform build-time administrative operations directly "
                    "where appropriate, then run the final application "
                    "as a non-root user."
                ),
            )

    return None


def check_dockerfile_shell_form(
    lines: list[str],
    dockerfile_path: Path,
) -> Finding | None:
    for line_number, line in enumerate(lines, start=1):
        stripped = line.strip()

        upper_line = stripped.upper()

        if (
            upper_line.startswith("ENTRYPOINT ")
            or upper_line.startswith("CMD ")
        ):
            parts = stripped.split(None, 1)

            if len(parts) != 2:
                continue

            value = parts[1].strip()

            # JSON-array/exec form starts with "[".
            if value and not value.startswith("["):
                return Finding(
                    rule_id="DS032",
                    severity="LOW",
                    title="Dockerfile uses shell-form CMD or ENTRYPOINT",
                    container=str(dockerfile_path),
                    description=(
                        "The Dockerfile uses shell-form execution for "
                        "CMD or ENTRYPOINT."
                    ),
                    evidence=f"Line {line_number}: {stripped}",
                    impact=(
                        "Shell-form execution introduces an additional "
                        "shell process and can complicate signal handling "
                        "and process isolation."
                    ),
                    remediation=(
                        "Prefer JSON-array exec form for CMD and ENTRYPOINT "
                        "when shell interpretation is not required."
                    ),
                )

    return None


# ============================================================
# Dockerfile Scanner
# ============================================================

def scan_dockerfile(path: str) -> list[Finding]:
    """
    Scan a Dockerfile for common security issues.
    """

    dockerfile_path = Path(path)

    if not dockerfile_path.exists():
        raise FileNotFoundError(path)

    if not dockerfile_path.is_file():
        raise ValueError(f"Dockerfile path is not a file: {path}")

    content = dockerfile_path.read_text(
        encoding="utf-8",
        errors="ignore",
    )

    lines = content.splitlines()

    findings: list[Finding] = []

    # ========================================================
    # DS011 - Dockerfile explicitly runs as root
    # ========================================================

    for line_number, raw_line in enumerate(lines, start=1):
        line = raw_line.strip()

        if not line:
            continue

        if re.match(
            r"^USER\s+root\s*$",
            line,
            re.IGNORECASE,
        ):
            findings.append(
                Finding(
                    rule_id="DS011",
                    severity="HIGH",
                    title="Dockerfile explicitly runs as root",
                    container=str(dockerfile_path),
                    description=(
                        "The Dockerfile explicitly switches to the root "
                        "user."
                    ),
                    evidence=f"Line {line_number}: {raw_line}",
                    impact=(
                        "A compromised application may have root-level "
                        "privileges inside the container."
                    ),
                    remediation=(
                        "Create and use a dedicated non-root application "
                        "user."
                    ),
                )
            )

        # ====================================================
        # DS012 - ADD instruction
        # ====================================================

        if re.match(
            r"^ADD\s+",
            line,
            re.IGNORECASE,
        ):
            findings.append(
                Finding(
                    rule_id="DS012",
                    severity="MEDIUM",
                    title="Dockerfile uses ADD instruction",
                    container=str(dockerfile_path),
                    description=(
                        "The Dockerfile uses ADD, which has additional "
                        "behavior beyond copying local files."
                    ),
                    evidence=f"Line {line_number}: {raw_line}",
                    impact=(
                        "Unexpected archive extraction or remote-resource "
                        "behavior can increase build complexity and risk."
                    ),
                    remediation=(
                        "Prefer COPY when only local file copying is "
                        "required."
                    ),
                )
            )

        # ====================================================
        # DS013 - Possible secret in ENV
        # ====================================================

        if re.match(
            r"^ENV\s+",
            line,
            re.IGNORECASE,
        ):
            secret_pattern = re.search(
                r"(PASSWORD|PASSWD|SECRET|TOKEN|API[_-]?KEY|PRIVATE[_-]?KEY)",
                line,
                re.IGNORECASE,
            )

            if secret_pattern:
                findings.append(
                    Finding(
                        rule_id="DS013",
                        severity="CRITICAL",
                        title="Possible secret stored in Dockerfile ENV",
                        container=str(dockerfile_path),
                        description=(
                            "An environment variable appears to contain "
                            "a credential, secret, token, or private key."
                        ),
                        evidence=f"Line {line_number}: {raw_line}",
                        impact=(
                            "Secrets embedded in image build instructions "
                            "may become exposed through image layers, "
                            "build history, or source control."
                        ),
                        remediation=(
                            "Do not hard-code secrets in the Dockerfile. "
                            "Use Docker secrets, runtime environment "
                            "configuration, or another secure secret "
                            "management mechanism."
                        ),
                    )
                )

        # ====================================================
        # DS014 - Remote download piped to shell
        # ====================================================

        remote_shell_pattern = re.search(
            r"(curl|wget).*(\|\s*(sh|bash)|\|\s*/bin/(sh|bash))",
            line,
            re.IGNORECASE,
        )

        if remote_shell_pattern:
            findings.append(
                Finding(
                    rule_id="DS014",
                    severity="HIGH",
                    title="Remote content is piped directly to a shell",
                    container=str(dockerfile_path),
                    description=(
                        "The Dockerfile downloads remote content and "
                        "directly executes it through a shell."
                    ),
                    evidence=f"Line {line_number}: {raw_line}",
                    impact=(
                        "A compromised or modified remote resource could "
                        "execute arbitrary commands during the image build."
                    ),
                    remediation=(
                        "Download and verify artifacts separately, "
                        "prefer trusted package repositories, and avoid "
                        "piping remote content directly into a shell."
                    ),
                )
            )

    # ========================================================
    # DS028 - Implicit latest image tag
    # ========================================================

    finding = check_dockerfile_latest_tag(
        lines,
        dockerfile_path,
    )

    if finding:
        findings.append(finding)

    # ========================================================
    # DS029 - Remote URL in ADD
    # ========================================================

    finding = check_dockerfile_add_remote_url(
        lines,
        dockerfile_path,
    )

    if finding:
        findings.append(finding)

    # ========================================================
    # DS030 - Package upgrade
    # ========================================================

    finding = check_dockerfile_package_upgrade(
        lines,
        dockerfile_path,
    )

    if finding:
        findings.append(finding)

    # ========================================================
    # DS031 - sudo
    # ========================================================

    finding = check_dockerfile_sudo(
        lines,
        dockerfile_path,
    )

    if finding:
        findings.append(finding)

    # ========================================================
    # DS032 - Shell-form CMD/ENTRYPOINT
    # ========================================================

    finding = check_dockerfile_shell_form(
        lines,
        dockerfile_path,
    )

    if finding:
        findings.append(finding)

    return findings