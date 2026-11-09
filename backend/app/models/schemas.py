from datetime import datetime
from typing import Any, Optional
from pydantic import BaseModel, Field, ConfigDict

class ScanRequest(BaseModel):
    """Payload for POST /scan"""
    url: str = Field(..., description="Target website URL or domain (e.g. https://example.com)")
    consent: bool = Field(..., description="Mandatory confirmation of ownership or authorization to scan.")

class FindingSchema(BaseModel):
    id: str
    category: str
    title: str
    status: str
    severity: str
    details: str
    attacker_abuse: str
    fix: str
    owasp_category: str
    score_impact: int = 0

class TopFixSchema(BaseModel):
    id: str
    title: str
    severity: str
    owasp_category: str
    fix: str
    impact: str

class ReportResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    target_url: str
    grade: str
    numerical_score: int
    total_issues: int
    severity_summary: dict[str, int]
    owasp_summary: dict[str, int]
    top_fixes: list[TopFixSchema]
    findings: list[FindingSchema]
    consent_acknowledged: bool
    scanned_at: datetime

class ReportSummary(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    target_url: str
    grade: str
    numerical_score: int
    total_issues: int
    scanned_at: datetime
