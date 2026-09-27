from __future__ import annotations

from dataclasses import dataclass, asdict
from typing import Any


@dataclass
class Finding:
    rule_id: str
    severity: str
    title: str
    container: str
    description: str
    evidence: str
    impact: str
    remediation: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)