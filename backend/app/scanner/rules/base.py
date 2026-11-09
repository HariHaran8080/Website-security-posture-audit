from abc import ABC, abstractmethod
from typing import Any, Optional
from pydantic import BaseModel, Field
from app.scanner.constants import Severity, FindingStatus, OWASP

class Finding(BaseModel):
    id: str
    category: str
    title: str
    status: FindingStatus
    severity: Severity
    details: str
    attacker_abuse: str = Field(..., description="Explanation of theoretical security risk and how an attacker abuses it.")
    fix: str = Field(..., description="Actionable copy-paste defensive fix.")
    owasp_category: str = Field(default=OWASP.A05_SECURITY_MISCONFIGURATION.value)
    score_impact: int = 0

class BaseRule(ABC):
    """Abstract base class for all scanner modules."""

    category: str = "General"
    rule_id: str = "RULE_BASE"

    @abstractmethod
    async def evaluate(self, target_url: str, context: dict[str, Any]) -> list[Finding]:
        """Runs the rule checks and returns structured findings."""
        pass
