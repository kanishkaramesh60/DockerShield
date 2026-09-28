from __future__ import annotations

import sys

from dockershield.compose import scan_compose
from dockershield.engine.risk import calculate_risk


DEFAULT_COMPOSE_FILE = "test-data/secure/compose.yml"
DEFAULT_MAX_RISK = 60


def main() -> int:
    compose_file = (
        sys.argv[1]
        if len(sys.argv) > 1
        else DEFAULT_COMPOSE_FILE
    )

    try:
        max_risk = (
            int(sys.argv[2])
            if len(sys.argv) > 2
            else DEFAULT_MAX_RISK
        )
    except ValueError:
        print("ERROR: Maximum risk threshold must be an integer.")
        return 2

    print(f"Scanning: {compose_file}")
    print(f"Maximum allowed risk: {max_risk}")

    try:
        findings = scan_compose(compose_file)
    except Exception as exc:
        print(f"ERROR: Could not scan Compose file: {exc}")
        return 2

    risk = calculate_risk(findings)

    print(f"DockerShield risk score: {risk['score']}/100")
    print(f"Risk level: {risk['level']}")
    print(f"Total findings: {risk['total_findings']}")

    if risk["score"] > max_risk:
        print()
        print("SECURITY GATE: FAILED")
        print(f"Risk score exceeds allowed threshold of {max_risk}.")
        return 1

    print()
    print("SECURITY GATE: PASSED")
    print(f"Risk score is within the allowed threshold of {max_risk}.")
    return 0


if __name__ == "__main__":
    sys.exit(main())