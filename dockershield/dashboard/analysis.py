from __future__ import annotations

from typing import Iterable

from dockershield.models import Finding
from dockershield.engine.risk import calculate_risk
from dockershield.engine.compliance import calculate_compliance
from dockershield.engine.correlation import summarize_correlations
from dockershield.engine.attack_path import summarize_attack_paths
from dockershield.engine.remediation import summarize_remediations
from dockershield.ml.predict import predict_risk


def analyze_findings(findings: Iterable[Finding]) -> dict:
    """
    Same pipeline as the API's `analyze_findings`, used only when the
    dashboard has to merge several container scans locally.
    """

    findings = list(findings)

    attack_paths = summarize_attack_paths(findings)

    try:
        ml_prediction = predict_risk(findings)
    except FileNotFoundError:
        ml_prediction = None

    return {
        "findings": [f.to_dict() for f in findings],
        "risk": calculate_risk(findings),
        "compliance": calculate_compliance(findings),
        "correlations": summarize_correlations(findings),
        "attack_paths": attack_paths,
        "remediations": summarize_remediations(
            findings,
            attack_paths["paths"],
        ),
        "ml_prediction": ml_prediction,
    }
