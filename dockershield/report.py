from __future__ import annotations

from datetime import datetime
from html import escape
from pathlib import Path

from dockershield.models import Finding
from dockershield.engine.risk import calculate_risk
from dockershield.engine.compliance import calculate_compliance
from dockershield.engine.correlation import summarize_correlations
from dockershield.engine.attack_path import summarize_attack_paths
from dockershield.engine.remediation import summarize_remediations
from dockershield.ml.predict import predict_risk


def generate_html_report(
    findings: list[Finding],
    output_path: str = "data\\report.html",
) -> Path:
    """Generate a standalone HTML security report."""

    risk = calculate_risk(findings)
    compliance = calculate_compliance(findings)
    correlations = summarize_correlations(findings)
    attack_paths = summarize_attack_paths(findings)

    remediations = summarize_remediations(
        findings,
        attack_paths["paths"],
    )

    # ---------------------------------------------------------
    # XGBoost prediction
    # ---------------------------------------------------------

    try:
        ml_prediction = predict_risk(findings)
    except FileNotFoundError:
        ml_prediction = None

    # ---------------------------------------------------------
    # Security findings
    # ---------------------------------------------------------

    finding_rows = ""

    for finding in findings:
        finding_rows += f"""
        <tr>
            <td>{escape(finding.rule_id)}</td>
            <td>{escape(finding.severity)}</td>
            <td>{escape(finding.title)}</td>
            <td>{escape(finding.container)}</td>
            <td>{escape(finding.description)}</td>
        </tr>
        """

    # ---------------------------------------------------------
    # Correlations
    # ---------------------------------------------------------

    correlation_rows = ""

    for item in correlations["correlations"]:
        correlation_rows += f"""
        <tr>
            <td>{escape(item["correlation_id"])}</td>
            <td>{escape(item["severity"])}</td>
            <td>{escape(item["title"])}</td>
            <td>{escape(", ".join(item["matched_rules"]))}</td>
        </tr>
        """

    # ---------------------------------------------------------
    # Attack paths
    # ---------------------------------------------------------

    attack_path_rows = ""

    for path in attack_paths["paths"]:
        attack_path_rows += f"""
        <tr>
            <td>{escape(path["path_id"])}</td>
            <td>{escape(path["severity"])}</td>
            <td>{escape(path["title"])}</td>
            <td>{escape(", ".join(path["matched_rules"]))}</td>
        </tr>
        """

    # ---------------------------------------------------------
    # Remediation
    # ---------------------------------------------------------

    remediation_rows = ""

    for item in remediations["remediations"]:
        remediation_rows += f"""
        <tr>
            <td>{escape(item["remediation_id"])}</td>
            <td>{escape(item["rule_id"])}</td>
            <td>{escape(item["priority"])}</td>
            <td>{escape(item["title"])}</td>
            <td>
                {"YES" if item["affects_attack_path"] else "NO"}
            </td>
        </tr>
        """

    # ---------------------------------------------------------
    # XGBoost HTML section
    # ---------------------------------------------------------

    ml_section = ""

    if ml_prediction is not None:

        probability_rows = ""

        for label, probability in (
            ml_prediction["probabilities"].items()
        ):
            probability_rows += f"""
            <tr>
                <td>{escape(label)}</td>
                <td>{probability * 100:.2f}%</td>
            </tr>
            """

        ml_section = f"""
        <section>
            <h2>XGBoost Risk Prediction</h2>

            <div class="cards">

                <div class="card">
                    <h3>Predicted Risk</h3>
                    <p>
                        <span class="badge">
                            {escape(ml_prediction["predicted_class"])}
                        </span>
                    </p>
                </div>

                <div class="card">
                    <h3>Model Confidence</h3>
                    <p>
                        {ml_prediction["confidence"] * 100:.2f}%
                    </p>
                </div>

            </div>

            <h3>Risk Class Probabilities</h3>

            <table>
                <thead>
                    <tr>
                        <th>Risk Class</th>
                        <th>Probability</th>
                    </tr>
                </thead>

                <tbody>
                    {probability_rows}
                </tbody>
            </table>

            <p class="note">
                The XGBoost prediction is an additional machine-learning
                risk assessment. Deterministic DockerShield security rules
                remain the primary source of individual security findings.
            </p>
        </section>
        """

    else:

        ml_section = """
        <section>
            <h2>XGBoost Risk Prediction</h2>

            <p class="note">
                XGBoost prediction is unavailable because the trained
                model was not found. Train the model before generating
                an ML-enabled report.
            </p>
        </section>
        """

    # ---------------------------------------------------------
    # HTML document
    # ---------------------------------------------------------

    html = f"""<!DOCTYPE html>
<html lang="en">

<head>

<meta charset="UTF-8">

<meta
    name="viewport"
    content="width=device-width, initial-scale=1.0"
>

<title>DockerShield Security Report</title>

<style>

body {{
    font-family: Arial, sans-serif;
    margin: 0;
    background: #f4f6f8;
    color: #222;
}}

header {{
    background: #1f2937;
    color: white;
    padding: 24px;
}}

main {{
    padding: 24px;
}}

.cards {{
    display: grid;
    grid-template-columns:
        repeat(auto-fit, minmax(180px, 1fr));
    gap: 16px;
}}

.card {{
    background: white;
    padding: 18px;
    border-radius: 8px;
    box-shadow: 0 2px 6px rgba(0,0,0,0.08);
}}

.card h3 {{
    margin-top: 0;
}}

table {{
    width: 100%;
    border-collapse: collapse;
    background: white;
    margin-bottom: 30px;
}}

th,
td {{
    border: 1px solid #ddd;
    padding: 10px;
    text-align: left;
}}

th {{
    background: #e5e7eb;
}}

section {{
    margin-top: 30px;
}}

.badge {{
    font-weight: bold;
}}

.note {{
    background: #f9fafb;
    border-left: 4px solid #6b7280;
    padding: 12px;
    margin-top: 15px;
}}

footer {{
    padding: 20px;
    color: #666;
}}

</style>

</head>

<body>

<header>

    <h1>DockerShield Security Report</h1>

    <p>
        Generated:
        {escape(datetime.now().strftime("%Y-%m-%d %H:%M:%S"))}
    </p>

</header>

<main>

<!-- ===================================================== -->
<!-- Summary Cards                                         -->
<!-- ===================================================== -->

<div class="cards">

    <div class="card">

        <h3>Risk Score</h3>

        <p>
            <span class="badge">
                {risk["score"]}/100
            </span>
        </p>

        <p>
            {escape(risk["level"])}
        </p>

    </div>


    <div class="card">

        <h3>Compliance</h3>

        <p>
            <span class="badge">
                {compliance["compliance_percentage"]}%
            </span>
        </p>

    </div>


    <div class="card">

        <h3>Findings</h3>

        <p>
            {len(findings)}
        </p>

    </div>


    <div class="card">

        <h3>Attack Paths</h3>

        <p>
            {attack_paths["total"]}
        </p>

    </div>


    <div class="card">

        <h3>Correlations</h3>

        <p>
            {correlations["total"]}
        </p>

    </div>


    <div class="card">

        <h3>Remediations</h3>

        <p>
            {remediations["total"]}
        </p>

    </div>

</div>


<!-- ===================================================== -->
<!-- XGBoost                                               -->
<!-- ===================================================== -->

{ml_section}


<!-- ===================================================== -->
<!-- Security Findings                                     -->
<!-- ===================================================== -->

<section>

<h2>Security Findings</h2>

<table>

<thead>

<tr>
    <th>Rule</th>
    <th>Severity</th>
    <th>Title</th>
    <th>Container</th>
    <th>Description</th>
</tr>

</thead>

<tbody>

{finding_rows}

</tbody>

</table>

</section>


<!-- ===================================================== -->
<!-- Correlations                                          -->
<!-- ===================================================== -->

<section>

<h2>Correlated Conditions</h2>

<table>

<thead>

<tr>
    <th>ID</th>
    <th>Severity</th>
    <th>Title</th>
    <th>Matched Rules</th>
</tr>

</thead>

<tbody>

{correlation_rows}

</tbody>

</table>

</section>


<!-- ===================================================== -->
<!-- Attack Paths                                          -->
<!-- ===================================================== -->

<section>

<h2>Potential Attack Paths</h2>

<table>

<thead>

<tr>
    <th>ID</th>
    <th>Severity</th>
    <th>Title</th>
    <th>Matched Rules</th>
</tr>

</thead>

<tbody>

{attack_path_rows}

</tbody>

</table>

</section>


<!-- ===================================================== -->
<!-- Remediation                                           -->
<!-- ===================================================== -->

<section>

<h2>Remediation Recommendations</h2>

<table>

<thead>

<tr>
    <th>ID</th>
    <th>Rule</th>
    <th>Priority</th>
    <th>Title</th>
    <th>Attack Path Impact</th>
</tr>

</thead>

<tbody>

{remediation_rows}

</tbody>

</table>

</section>

</main>


<footer>

    DockerShield —
    Docker Security, Compliance & Attack-Path Analysis

</footer>

</body>

</html>
"""

    # ---------------------------------------------------------
    # Write report
    # ---------------------------------------------------------

    path = Path(output_path)

    path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    path.write_text(
        html,
        encoding="utf-8",
    )

    return path