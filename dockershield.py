#!/usr/bin/env python3

from __future__ import annotations

import argparse
import sys

from dockershield.docker_client import get_client
from dockershield.models import Finding
from dockershield.runtime import scan_container
from dockershield.dockerfile import scan_dockerfile
from dockershield.compose import scan_compose
from dockershield.engine.risk import calculate_risk
from dockershield.engine.compliance import calculate_compliance
from dockershield.engine.correlation import summarize_correlations
from dockershield.engine.attack_path import summarize_attack_paths


VERSION = "0.4.0"


# ============================================================
# OUTPUT / DISPLAY FUNCTIONS
# ============================================================

def print_finding(finding: Finding) -> None:
    """Print one security finding in a readable format."""

    print("\n" + "-" * 70)
    print(f"[{finding.severity}] {finding.rule_id} - {finding.title}")

    if finding.container:
        print(f"Container   : {finding.container}")

    print(f"Description : {finding.description}")
    print(f"Evidence    : {finding.evidence}")
    print(f"Impact      : {finding.impact}")
    print(f"Remediation : {finding.remediation}")


def print_findings(findings: list[Finding]) -> None:
    """Print all findings."""

    if not findings:
        print("\n[OK] No security findings detected.")
        return

    print(f"\n[!] {len(findings)} security finding(s) detected.")

    for finding in findings:
        print_finding(finding)


def print_summary(findings: list[Finding]) -> None:
    """Print severity summary."""

    counts = {
        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0,
    }

    for finding in findings:
        if finding.severity in counts:
            counts[finding.severity] += 1

    print("\n" + "=" * 70)
    print("SECURITY SUMMARY")
    print("=" * 70)

    print(f"CRITICAL : {counts['CRITICAL']}")
    print(f"HIGH     : {counts['HIGH']}")
    print(f"MEDIUM   : {counts['MEDIUM']}")
    print(f"LOW      : {counts['LOW']}")
    print(f"TOTAL    : {len(findings)}")

    print("=" * 70)


def print_risk_assessment(findings: list[Finding]) -> None:
    """Print overall risk assessment."""

    assessment = calculate_risk(findings)

    print()
    print("=" * 70)
    print("RISK ASSESSMENT")
    print("=" * 70)

    print(f"Risk Score  : {assessment['score']}/100")
    print(f"Risk Level  : {assessment['level']}")
    print(f"Total       : {assessment['total_findings']}")

    counts = assessment["severity_counts"]

    print()
    print("Severity Breakdown")
    print("-" * 70)

    print(f"CRITICAL    : {counts['CRITICAL']}")
    print(f"HIGH        : {counts['HIGH']}")
    print(f"MEDIUM      : {counts['MEDIUM']}")
    print(f"LOW         : {counts['LOW']}")

    print("=" * 70)

def print_compliance_assessment(findings):
    compliance = calculate_compliance(findings)

    print("\nCompliance Assessment")
    print("---------------------")
    print(f"Controls Checked : {compliance['total_controls']}")
    print(f"Passed           : {compliance['passed']}")
    print(f"Failed           : {compliance['failed']}")
    print(
        f"Compliance       : "
        f"{compliance['compliance_percentage']}%"
    )

    print("\nControl Status")

    for control in compliance["controls"]:
        print(
            f"{control['control_id']:<10} "
            f"{control['status']:<5} "
            f"{control['title']}"
        )

def print_correlation_assessment(findings):
    correlation_summary = summarize_correlations(findings)

    print("\nCorrelation Assessment")
    print("----------------------")
    print(f"Correlations Detected : {correlation_summary['total']}")
    print(f"Critical              : {correlation_summary['critical']}")
    print(f"High                  : {correlation_summary['high']}")

    if not correlation_summary["correlations"]:
        print("\nNo correlated security conditions detected.")
        return

    print("\nCorrelated Conditions")

    for correlation in correlation_summary["correlations"]:
        print("\n" + "-" * 70)
        print(
            f"[{correlation['severity']}] "
            f"{correlation['correlation_id']} - "
            f"{correlation['title']}"
        )
        print(f"Description : {correlation['description']}")
        print(
            "Matched Rules : "
            + ", ".join(correlation["matched_rules"])
        )

# ============================================================
# DOCKER ENGINE HEALTH CHECK
# ============================================================

def doctor() -> None:
    """Check whether Docker Engine is reachable."""

    print("=" * 70)
    print("DockerShield Doctor")
    print("=" * 70)

    try:
        client = get_client()

        version = client.version()

        print("\n[OK] Docker Engine is reachable.")
        print(f"Docker version : {version.get('Version', 'Unknown')}")
        print(f"API version    : {version.get('ApiVersion', 'Unknown')}")
        print(f"OS             : {version.get('Os', 'Unknown')}")
        print(f"Architecture   : {version.get('Arch', 'Unknown')}")

        print("\nDockerShield is ready.")

    except Exception as exc:
        print("\n[ERROR] Docker health check failed.")
        print(f"Details: {exc}")
        sys.exit(1)

def print_attack_path_assessment(findings):
    summary = summarize_attack_paths(findings)

    print("\nAttack-Path Assessment")
    print("----------------------")
    print(f"Attack Paths Detected : {summary['total']}")
    print(f"Critical              : {summary['critical']}")
    print(f"High                  : {summary['high']}")

    if not summary["paths"]:
        print("\nNo potential attack paths detected.")
        return

    print("\nPotential Attack Paths")

    for path in summary["paths"]:
        print("\n" + "-" * 70)
        print(
            f"[{path['severity']}] "
            f"{path['path_id']} - "
            f"{path['title']}"
        )
        print(f"Description : {path['description']}")
        print(
            "Matched Rules : "
            + ", ".join(path["matched_rules"])
        )
        print(
            "Path : "
            + " -> ".join(path["steps"])
        )

# ============================================================
# RUNTIME SECURITY SCAN
# ============================================================

def security_scan() -> None:
    """Scan running Docker containers."""

    print("=" * 70)
    print("DockerShield Runtime Security Scanner")
    print("=" * 70)

    client = get_client()

    try:
        containers = client.containers.list()

        if not containers:
            print("\n[INFO] No running containers found.")
            return

        print(f"\nFound {len(containers)} running container(s).")

        all_findings: list[Finding] = []

        for container in containers:
            print("\n" + "=" * 70)
            print(f"Scanning container: {container.name}")
            print("=" * 70)

            findings = scan_container(container)

            print_findings(findings)

            all_findings.extend(findings)

        print_summary(all_findings)
        print_risk_assessment(all_findings)

    except Exception as exc:
        print("\n[ERROR] Runtime scan failed.")
        print(f"Details: {exc}")
        sys.exit(1)


# ============================================================
# DOCKERFILE SECURITY SCAN
# ============================================================

def dockerfile_scan(path: str) -> None:
    """Scan a Dockerfile."""

    print("=" * 70)
    print("DockerShield Dockerfile Security Scanner")
    print("=" * 70)

    print(f"\nTarget: {path}")

    try:
        findings = scan_dockerfile(path)

        print_findings(findings)
        print_summary(findings)
        print_risk_assessment(findings)

    except FileNotFoundError:
        print(f"\n[ERROR] Dockerfile not found: {path}")
        sys.exit(1)

    except Exception as exc:
        print("\n[ERROR] Dockerfile scan failed.")
        print(f"Details: {exc}")
        sys.exit(1)


# ============================================================
# DOCKER COMPOSE SECURITY SCAN
# ============================================================

def compose_scan(path: str) -> None:
    """Scan a Docker Compose file."""

    print("=" * 70)
    print("DockerShield Compose Security Scanner")
    print("=" * 70)

    print(f"\nTarget: {path}")

    try:
        findings = scan_compose(path)

        print_findings(findings)
        print_summary(findings)
        print_risk_assessment(findings)
        print_compliance_assessment(findings)
        print_correlation_assessment(findings)
        print_attack_path_assessment(findings)

    except FileNotFoundError:
        print(f"\n[ERROR] Compose file not found: {path}")
        sys.exit(1)

    except Exception as exc:
        print("\n[ERROR] Compose scan failed.")
        print(f"Details: {exc}")
        sys.exit(1)


# ============================================================
# DOCKER ENVIRONMENT DISCOVERY
# ============================================================

def discover() -> None:
    """Display Docker environment information."""

    print("=" * 70)
    print("DockerShield Environment Discovery")
    print("=" * 70)

    client = get_client()

    try:
        version = client.version()
        info = client.info()

        print("\nDOCKER ENGINE")
        print("-" * 70)

        print(f"Version        : {version.get('Version', 'Unknown')}")
        print(f"API Version    : {version.get('ApiVersion', 'Unknown')}")
        print(f"OS             : {version.get('Os', 'Unknown')}")
        print(f"Architecture   : {version.get('Arch', 'Unknown')}")

        print("\nDOCKER HOST")
        print("-" * 70)

        print(f"Containers     : {info.get('Containers', 'Unknown')}")
        print(f"Running        : {info.get('ContainersRunning', 'Unknown')}")
        print(f"Paused         : {info.get('ContainersPaused', 'Unknown')}")
        print(f"Stopped        : {info.get('ContainersStopped', 'Unknown')}")
        print(f"Images         : {info.get('Images', 'Unknown')}")

        print("\nSTORAGE")
        print("-" * 70)

        print(f"Driver         : {info.get('Driver', 'Unknown')}")

        print("\nSYSTEM")
        print("-" * 70)

        print(f"CPUs           : {info.get('NCPU', 'Unknown')}")
        print(f"Memory         : {info.get('MemTotal', 'Unknown')} bytes")

    except Exception as exc:
        print("\n[ERROR] Environment discovery failed.")
        print(f"Details: {exc}")
        sys.exit(1)


# ============================================================
# VERSION
# ============================================================

def show_version() -> None:
    """Display DockerShield version."""

    print(f"DockerShield {VERSION}")


# ============================================================
# CLI
# ============================================================

def main() -> None:
    """DockerShield command-line entry point."""

    parser = argparse.ArgumentParser(
        prog="dockershield",
        description=(
            "DockerShield - Docker Security, Compliance "
            "and Attack-Path Analysis Platform"
        ),
    )

    parser.add_argument(
        "--version",
        action="version",
        version=f"DockerShield {VERSION}",
    )

    subparsers = parser.add_subparsers(
        dest="command",
        metavar="COMMAND",
    )

    # --------------------------------------------------------
    # doctor
    # --------------------------------------------------------

    subparsers.add_parser(
        "doctor",
        help="Check Docker Engine connectivity and environment.",
    )

    # --------------------------------------------------------
    # discover
    # --------------------------------------------------------

    subparsers.add_parser(
        "discover",
        help="Display Docker environment information.",
    )

    # --------------------------------------------------------
    # scan
    # --------------------------------------------------------

    subparsers.add_parser(
        "scan",
        help="Scan running Docker containers.",
    )

    # --------------------------------------------------------
    # dockerfile
    # --------------------------------------------------------

    dockerfile_parser = subparsers.add_parser(
        "dockerfile",
        help="Scan a Dockerfile for security issues.",
    )

    dockerfile_parser.add_argument(
        "path",
        help="Path to the Dockerfile.",
    )

    # --------------------------------------------------------
    # compose
    # --------------------------------------------------------

    compose_parser = subparsers.add_parser(
        "compose",
        help="Scan a Docker Compose file for security issues.",
    )

    compose_parser.add_argument(
        "path",
        help="Path to the Docker Compose YAML file.",
    )

    # --------------------------------------------------------
    # Parse arguments
    # --------------------------------------------------------

    args = parser.parse_args()

    # --------------------------------------------------------
    # Execute command
    # --------------------------------------------------------

    if args.command == "doctor":
        doctor()

    elif args.command == "discover":
        discover()

    elif args.command == "scan":
        security_scan()

    elif args.command == "dockerfile":
        dockerfile_scan(args.path)

    elif args.command == "compose":
        compose_scan(args.path)

    else:
        parser.print_help()


# ============================================================
# PROGRAM ENTRY POINT
# ============================================================

if __name__ == "__main__":
    main()