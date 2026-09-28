from pathlib import Path

from dockershield.compose import scan_compose


TEST_DATA = Path("test-data")


def test_secure_demo_environment():
    compose = TEST_DATA / "secure" / "compose.yml"

    findings = scan_compose(str(compose))

    assert findings == []


def test_moderate_demo_environment():
    compose = TEST_DATA / "moderate" / "compose.yml"

    findings = scan_compose(str(compose))

    rule_ids = {finding.rule_id for finding in findings}

    assert rule_ids == {"DS017"}


def test_vulnerable_demo_environment():
    compose = TEST_DATA / "vulnerable" / "compose.yml"

    findings = scan_compose(str(compose))

    rule_ids = {finding.rule_id for finding in findings}

    assert rule_ids == {
        "DS015",
        "DS016",
        "DS017",
        "DS018",
        "DS019",
        "DS020",
        "DS021",
        "DS022",
        "DS034",
        "DS035",
    }