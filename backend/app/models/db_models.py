from datetime import datetime
from sqlalchemy import Column, Integer, String, Boolean, DateTime, JSON
from app.database import Base

class AuditReport(Base):
    __tablename__ = "audit_reports"

    id = Column(Integer, primary_key=True, index=True)
    target_url = Column(String, nullable=False, index=True)
    grade = Column(String, nullable=False)
    numerical_score = Column(Integer, nullable=False)
    total_issues = Column(Integer, nullable=False, default=0)
    severity_summary = Column(JSON, nullable=False, default=dict)
    owasp_summary = Column(JSON, nullable=False, default=dict)
    top_fixes = Column(JSON, nullable=False, default=list)
    findings = Column(JSON, nullable=False, default=list)
    consent_acknowledged = Column(Boolean, nullable=False, default=False)
    scanned_at = Column(DateTime, default=datetime.utcnow, nullable=False)
