import pytest
from dockershield.models import Finding

@pytest.fixture
def finding():
    return Finding(
        rule_id="TEST-001",
        severity="HIGH",
        title="Test finding",
        container="test",
        description="Test description",
        evidence="Test evidence",
        impact="Test impact",
        remediation="Test remediation",
    )
