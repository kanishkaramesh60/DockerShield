from __future__ import annotations

import re
from pathlib import Path

from dockershield.models import Finding


def scan_dockerfile(path: str) -> list[Finding]:
    """
    Scan a Dockerfile for common security issues.
    """

    dockerfile_path = Path(path)

    if not dockerfile_path.exists():
        raise FileNotFoundError(path)

    content = dockerfile_path.read_text(
        encoding="utf-8",
        errors="ignore",
    )

    lines = content.splitlines()

    findings: list[Finding] = []

    for line_number, raw_line in enumerate(lines, start=1):
        line = raw_line.strip()

        if not line:
            continue

        # ----------------------------------------------------
        # DS011 - Dockerfile explicitly runs as root
        # ----------------------------------------------------

        if re.match(r"^USER\s+root\s*$", line, re.IGNORECASE):

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

        # ----------------------------------------------------
        # DS012 - ADD instruction
        # ----------------------------------------------------

        if re.match(r"^ADD\s+", line, re.IGNORECASE):

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

        # ----------------------------------------------------
        # DS013 - Possible secret in ENV
        # ----------------------------------------------------

        if re.match(r"^ENV\s+", line, re.IGNORECASE):

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

        # ----------------------------------------------------
        # DS014 - Remote download piped to shell
        # ----------------------------------------------------

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

    return findings