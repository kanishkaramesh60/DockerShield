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
from dockershield.engine.remediation import summarize_remediations
from dockershield.engine.simulator import simulate_remediations
from dockershield.engine.baseline import (
    save_baseline,
    load_baseline,
    compare_with_baseline,
)
from dockershield.report import generate_html_report
from dockershield.ml.predict import predict_risk


VERSION = "0.5.0"


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

def print_ml_risk_assessment(
    findings,
) -> None:
    """
    Print the XGBoost risk prediction.
    """

    try:
        prediction = predict_risk(findings)
    except FileNotFoundError as exc:
        print("\n[ML] XGBoost model unavailable.")
        print(f"Details: {exc}")
        return

    print("\n" + "=" * 60)
    print("XGBOOST RISK PREDICTION")
    print("=" * 60)

    print(
        f"Model: {prediction['model']}"
    )

    print(
        f"Predicted Risk: "
        f"{prediction['predicted_class']}"
    )

    print(
        f"Confidence: "
        f"{prediction['confidence'] * 100:.2f}%"
    )

    print("\nClass probabilities:")

    for label, probability in (
        prediction["probabilities"].items()
    ):
        print(
            f"  {label:<10} "
            f"{probability * 100:>6.2f}%"
        )

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

def print_attack_path_assessment(summary):

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

def print_remediation_assessment(
    findings: list[Finding],
    attack_paths: list[dict],
) -> None:
    assessment = summarize_remediations(
        findings,
        attack_paths,
    )

    print("\nREMEDIATION ASSESSMENT")
    print("----------------------")
    print(f"Remediations Available : {assessment['total']}")
    print(f"Attack-Path Fixes      : {assessment['attack_path_fixes']}")

    if not assessment["remediations"]:
        print("No remediation recommendations.")
        return

    for item in assessment["remediations"]:
        print(f"\n{item['remediation_id']} {item['rule_id']} "
              f"{item['severity']}")
        print(f"Title  : {item['title']}")
        print(f"Action : {item['action']}")
        print(f"Why    : {item['rationale']}")
        print(f"Verify : {item['verification']}")
        print(
            "Attack Path Impact : "
            f"{'YES' if item['affects_attack_path'] else 'NO'}"
        )

def print_simulation_assessment(findings, remediation_ids):
    result = simulate_remediations(
        findings,
        remediation_ids,
    )

    before = result["before"]
    after = result["after"]

    print("\n" + "=" * 60)
    print("WHAT-IF REMEDIATION SIMULATION")
    print("=" * 60)

    print(f"Remediations: {', '.join(remediation_ids)}")

    print("\nBEFORE")
    print(f"  Findings: {before['findings']}")
    print(
        f"  Risk: {before['risk']['score']}/100 "
        f"({before['risk']['level']})"
    )
    print(
        f"  Compliance: "
        f"{before['compliance']['compliance_percentage']}%"
    )
    print(f"  Attack paths: {before['attack_paths']['total']}")

    print("\nAFTER")
    print(f"  Findings: {after['findings']}")
    print(
        f"  Risk: {after['risk']['score']}/100 "
        f"({after['risk']['level']})"
    )
    print(
        f"  Compliance: "
        f"{after['compliance']['compliance_percentage']}%"
    )
    print(f"  Attack paths: {after['attack_paths']['total']}")

    print("\nRESOLVED ATTACK PATHS")

    if result["resolved_attack_paths"]:
        for path_id in result["resolved_attack_paths"]:
            print(f"  - {path_id}")
    else:
        print("  None")

    print("=" * 60)

def print_baseline_assessment(comparison):
    print("\n" + "=" * 60)
    print("SECURITY BASELINE COMPARISON")
    print("=" * 60)

    print(
        f"Baseline findings : "
        f"{comparison['baseline_findings']}"
    )
    print(
        f"Current findings  : "
        f"{comparison['current_findings']}"
    )

    print(
        f"Resolved          : "
        f"{len(comparison['resolved'])}"
    )

    print(
        f"New findings      : "
        f"{len(comparison['new'])}"
    )

    print(
        f"Unchanged         : "
        f"{len(comparison['unchanged'])}"
    )

    print(
        f"Risk change       : "
        f"{comparison['risk_change']:+d}"
    )

    print(
        f"Compliance change : "
        f"{comparison['compliance_change']:+.1f}%"
    )

    print(
        f"Regression        : "
        f"{'YES' if comparison['regression'] else 'NO'}"
    )

    if comparison["resolved"]:
        print("\nResolved Findings")

        for item in comparison["resolved"]:
            print(f"  - {item}")

    if comparison["new"]:
        print("\nNew Findings")

        for item in comparison["new"]:
            print(f"  - {item}")

    print("=" * 60)

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

def collect_runtime_findings() -> list[Finding]:
    """Collect findings from all running Docker containers."""

    client = get_client()

    try:
        containers = client.containers.list()

        if not containers:
            print("\n[INFO] No running containers found.")
            return []

        all_findings: list[Finding] = []

        for container in containers:
            print("\n" + "=" * 70)
            print(f"Scanning container: {container.name}")
            print("=" * 70)

            findings = scan_container(container)
            all_findings.extend(findings)

        return all_findings

    except Exception as exc:
        print("\n[ERROR] Runtime scan failed.")
        print(f"Details: {exc}")
        sys.exit(1)

# ============================================================
# RUNTIME SECURITY SCAN
# ============================================================

def security_scan() -> None:
    """Scan running Docker containers."""

    print("=" * 70)
    print("DockerShield Runtime Security Scanner")
    print("=" * 70)

    all_findings = collect_runtime_findings()

    if not all_findings:
        return

    print_findings(all_findings)
    print_summary(all_findings)
    print_risk_assessment(all_findings)

# ============================================================
# DOCKERFILE SECURITY SCAN
# ============================================================

def dockerfile_scan(path: str) -> list[Finding]:
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
        return findings

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

def compose_scan(path: str) -> list[Finding]:
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

        attack_path_assessment = summarize_attack_paths(findings)
        print_attack_path_assessment(attack_path_assessment)

        print_remediation_assessment(
            findings,
            attack_path_assessment["paths"],
        )
        print_ml_risk_assessment(findings)
        return findings

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

def full_scan() -> None:
    """Run the complete DockerShield security analysis pipeline."""

    compose_path = "test-data\\vulnerable\\compose.yml"
    dockerfile_path = "test-data\\Dockerfile"

    print("\n" + "=" * 70)
    print("DOCKERSHIELD FULL SECURITY ANALYSIS")
    print("=" * 70)

    # --------------------------------------------------------
    # 1. Docker health check
    # --------------------------------------------------------
    print("\n[1/9] Docker Engine Health Check")
    doctor()

    # --------------------------------------------------------
    # 2. Environment discovery
    # --------------------------------------------------------
    print("\n[2/9] Docker Environment Discovery")
    discover()

    # --------------------------------------------------------
    # 3. Runtime container scan
    # --------------------------------------------------------
    print("\n[3/9] Runtime Container Scan")

    runtime_findings = collect_runtime_findings()

    print(f"Runtime Findings: {len(runtime_findings)}")

    # --------------------------------------------------------
    # 4. Dockerfile scan
    # --------------------------------------------------------
    print("\n[4/9] Dockerfile Security Scan")

    dockerfile_findings = scan_dockerfile(
        dockerfile_path
    )

    print(
        f"Dockerfile Findings: "
        f"{len(dockerfile_findings)}"
    )

    # --------------------------------------------------------
    # 5. Docker Compose scan
    # --------------------------------------------------------
    print("\n[5/9] Docker Compose Security Scan")

    compose_findings = scan_compose(
        compose_path
    )

    print(
        f"Compose Findings: "
        f"{len(compose_findings)}"
    )

    # --------------------------------------------------------
    # UNIFIED FINDINGS
    # --------------------------------------------------------
    all_findings = (
        runtime_findings
        + dockerfile_findings
        + compose_findings
    )

    print("\n" + "=" * 70)
    print("UNIFIED SECURITY ANALYSIS")
    print("=" * 70)

    print(
        f"\nRuntime Findings    : "
        f"{len(runtime_findings)}"
    )

    print(
        f"Dockerfile Findings : "
        f"{len(dockerfile_findings)}"
    )

    print(
        f"Compose Findings    : "
        f"{len(compose_findings)}"
    )

    print(
        f"Total Findings      : "
        f"{len(all_findings)}"
    )

    # --------------------------------------------------------
    # Risk scoring
    # --------------------------------------------------------
    print("\n" + "-" * 70)
    print("RISK ASSESSMENT")
    print("-" * 70)

    risk = calculate_risk(all_findings)

    print(
        f"Risk Score : "
        f"{risk['score']}/100"
    )

    print(
        f"Risk Level : "
        f"{risk['level']}"
    )

    print(
        f"Total Findings : "
        f"{risk['total_findings']}"
    )

    # --------------------------------------------------------
    # ML risk classification
    # ML runs immediately after deterministic risk scoring
    # --------------------------------------------------------
    print("\n" + "-" * 70)
    print("ML RISK ANALYSIS")
    print("-" * 70)

    print_ml_risk_assessment(
        all_findings
    )

    # --------------------------------------------------------
    # Compliance analysis
    # --------------------------------------------------------
    print("\n" + "-" * 70)
    print("COMPLIANCE ANALYSIS")
    print("-" * 70)

    compliance = calculate_compliance(
        all_findings
    )

    print(
        f"Compliance : "
        f"{compliance['compliance_percentage']}%"
    )

    # --------------------------------------------------------
    # Correlation analysis
    # --------------------------------------------------------
    print("\n" + "-" * 70)
    print("CORRELATION ANALYSIS")
    print("-" * 70)

    correlations = summarize_correlations(
        all_findings
    )

    print(
        f"Correlations : "
        f"{correlations['total']}"
    )

    # --------------------------------------------------------
    # Attack-path analysis
    # --------------------------------------------------------
    print("\n" + "-" * 70)
    print("ATTACK-PATH ANALYSIS")
    print("-" * 70)

    attack_paths = summarize_attack_paths(
        all_findings
    )

    print_attack_path_assessment(
        attack_paths
    )

    # --------------------------------------------------------
    # Remediation analysis
    # --------------------------------------------------------
    print("\n" + "-" * 70)
    print("REMEDIATION ANALYSIS")
    print("-" * 70)

    remediations = summarize_remediations(
        all_findings,
        attack_paths["paths"],
    )

    print_remediation_assessment(
        all_findings,
        attack_paths["paths"],
    )

    # --------------------------------------------------------
    # 6. What-if remediation simulation
    # --------------------------------------------------------
    print("\n[6/9] What-If Remediation Simulation")

    remediation_ids = [
        item["remediation_id"]
        for item in remediations["remediations"]
    ]

    if remediation_ids:
        print_simulation_assessment(
            all_findings,
            remediation_ids,
        )
    else:
        print(
            "No remediation actions "
            "available for simulation."
        )

    # --------------------------------------------------------
    # 7. Baseline / regression analysis
    # --------------------------------------------------------
    print("\n[7/9] Baseline / Regression Analysis")

    try:
        baseline = load_baseline()

        comparison = compare_with_baseline(
            all_findings,
            baseline,
        )

        print_baseline_assessment(
            comparison
        )

    except FileNotFoundError:
        print(
            "[INFO] No existing baseline found."
        )

        print(
            "[INFO] Creating baseline "
            "from current scan..."
        )

        save_baseline(
            all_findings
        )

        print("[OK] Baseline created.")
        print(
            "Location: data\\baseline.json"
        )

    # --------------------------------------------------------
    # 8. HTML security report
    # --------------------------------------------------------
    print("\n[8/9] HTML Security Report")

    report_path = generate_html_report(
        all_findings,
        "data\\report.html",
    )

    print(
        "[OK] HTML report generated."
    )

    print(
        f"Location: {report_path}"
    )

    # --------------------------------------------------------
    # 9. Final consolidated result
    # --------------------------------------------------------
    print("\n[9/9] FINAL SECURITY RESULT")

    print("\n" + "=" * 70)
    print("DOCKERSHIELD FINAL SECURITY SUMMARY")
    print("=" * 70)

    # --------------------------------------------------------
    # Final risk
    # --------------------------------------------------------
    print(
        f"\nRisk Score       : "
        f"{risk['score']}/100"
    )

    print(
        f"Risk Level       : "
        f"{risk['level']}"
    )

    print(
        f"Total Findings   : "
        f"{risk['total_findings']}"
    )


    # --------------------------------------------------------
    # Final ML result
    # --------------------------------------------------------
    try:
        prediction = predict_risk(
            all_findings
        )

        print(
            f"\nML Risk          : "
            f"{prediction['predicted_class']}"
        )

        print(
            f"ML Confidence    : "
            f"{prediction['confidence'] * 100:.2f}%"
        )

    except Exception as exc:
        print(
            f"\nML Risk          : "
            f"Unavailable ({exc})"
        )

    counts = risk["severity_counts"]

    print(
        f"CRITICAL         : "
        f"{counts['CRITICAL']}"
    )

    print(
        f"HIGH             : "
        f"{counts['HIGH']}"
    )

    print(
        f"MEDIUM           : "
        f"{counts['MEDIUM']}"
    )

    print(
        f"LOW              : "
        f"{counts['LOW']}"
    )

    # --------------------------------------------------------
    # Final compliance
    # --------------------------------------------------------
    print(
        f"\nCompliance       : "
        f"{compliance['compliance_percentage']}%"
    )

    # --------------------------------------------------------
    # Final correlations
    # --------------------------------------------------------
    print(
        f"Correlations     : "
        f"{correlations['total']}"
    )

    # --------------------------------------------------------
    # Final attack paths
    # --------------------------------------------------------
    print(
        f"Attack Paths     : "
        f"{attack_paths['total']}"
    )

    # --------------------------------------------------------
    # Final remediations
    # --------------------------------------------------------
    print(
        f"Remediations     : "
        f"{remediations['total']}"
    )

    print(
        f"Attack-Path Fixes: "
        f"{remediations['attack_path_fixes']}"
    )

    # --------------------------------------------------------
    # Output files
    # --------------------------------------------------------
    print(
        "\nReport            : "
        "data\\report.html"
    )

    print(
        "Baseline          : "
        "data\\baseline.json"
    )

    print("\n" + "=" * 70)
    print(
        "DOCKERSHIELD FULL ANALYSIS COMPLETE"
    )
    print("=" * 70)
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
    # full
    # --------------------------------------------------------

    subparsers.add_parser(
        "full",
        help="Run the complete DockerShield security analysis.",
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
    # simulate
    # --------------------------------------------------------

    simulate_parser = subparsers.add_parser(
        "simulate",
        help="Simulate remediation changes without modifying files.",
    )

    simulate_parser.add_argument(
        "path",
        help="Path to the Docker Compose YAML file.",
    )

    simulate_parser.add_argument(
        "remediations",
        nargs="+",
        help="Remediation IDs to simulate, e.g. REM-001 REM-006.",
    )

    # --------------------------------------------------------
    # baseline
    # --------------------------------------------------------

    baseline_parser = subparsers.add_parser(
        "baseline",
        help="Save the current Compose security state as a baseline.",
    )

    baseline_parser.add_argument(
        "path",
        help="Path to the Docker Compose YAML file.",
    )

    # --------------------------------------------------------
    # compare
    # --------------------------------------------------------

    compare_parser = subparsers.add_parser(
        "compare",
        help="Compare a Compose scan against the saved baseline.",
    )

    compare_parser.add_argument(
        "path",
        help="Path to the Docker Compose YAML file.",
    )

    # --------------------------------------------------------
    # report
    # --------------------------------------------------------

    report_parser = subparsers.add_parser(
        "report",
        help="Generate an HTML security report from a Compose scan.",
    )

    report_parser.add_argument(
        "path",
        help="Path to the Docker Compose YAML file.",
    )

    report_parser.add_argument(
        "--output",
        default="data\\report.html",
        help="Output HTML report path.",
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

    elif args.command == "full":
        full_scan()

    elif args.command == "discover":
        discover()

    elif args.command == "scan":
        security_scan()

    elif args.command == "dockerfile":
        dockerfile_scan(args.path)

    elif args.command == "compose":
        compose_scan(args.path)

    elif args.command == "simulate":
        findings = scan_compose(args.path)

        print_simulation_assessment(
            findings,
            args.remediations,
        )

    elif args.command == "baseline":
        findings = scan_compose(args.path)

        save_baseline(findings)

        print("\n[OK] Security baseline saved.")
        print("Location: data\\baseline.json")

    elif args.command == "compare":
        findings = scan_compose(args.path)

        try:
            baseline = load_baseline()
        except FileNotFoundError as exc:
            print(f"\n[ERROR] {exc}")
            sys.exit(1)

        comparison = compare_with_baseline(
            findings,
            baseline,
        )

        print_baseline_assessment(
            comparison
        )

    elif args.command == "report":
        findings = scan_compose(args.path)

        report_path = generate_html_report(
            findings,
            args.output,
        )

        print("\n[OK] HTML security report generated.")
        print(f"Location: {report_path}")

    else:
        parser.print_help()


# ============================================================
# PROGRAM ENTRY POINT
# ============================================================

if __name__ == "__main__":
    main()