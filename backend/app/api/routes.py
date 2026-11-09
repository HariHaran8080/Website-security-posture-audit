from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc

from app.database import get_db
from app.models.schemas import ScanRequest, ReportResponse, ReportSummary
from app.models.db_models import AuditReport
from app.scanner.engine import SecurityScannerEngine
from app.scanner.exceptions import UnauthorizedScanError
from app.scanner.security import SSRFSecurityError, InvalidTargetURLError
from app.api.dependencies import get_scanner
from app.api.rate_limiter import check_scan_rate_limit

router = APIRouter()

@router.post(
    "/scan",
    response_model=ReportResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Trigger Website Security Posture Scan",
    dependencies=[Depends(check_scan_rate_limit)]
)
async def scan_endpoint(
    payload: ScanRequest,
    scanner: SecurityScannerEngine = Depends(get_scanner),
    db: AsyncSession = Depends(get_db)
):
    """
    Executes a comprehensive website security posture audit.

    **Security & Consent Guards**:
    - Refuses scanning if `consent` is false with HTTP 403 Forbidden.
    - Validates target domain and blocks SSRF / internal IP targeting.
    - Rate-limited to prevent abuse.
    """
    if not payload.consent:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Scan refused: You must confirm that you own or have explicit written authorization to scan this target."
        )

    try:
        result = await scanner.scan(
            target_url=payload.url,
            has_permission=payload.consent
        )
    except UnauthorizedScanError as exc:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=str(exc)
        )
    except (SSRFSecurityError, InvalidTargetURLError) as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc)
        )
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Scanner execution failed: {str(exc)}"
        )

    # Persist report in SQLite
    report = AuditReport(
        target_url=result["target_url"],
        grade=result["grade"],
        numerical_score=result["numerical_score"],
        total_issues=result["total_issues"],
        severity_summary=result["severity_summary"],
        owasp_summary=result["owasp_summary"],
        top_fixes=result["top_fixes"],
        findings=result["findings"],
        consent_acknowledged=result["consent_acknowledged"]
    )
    db.add(report)
    await db.commit()
    await db.refresh(report)

    return report

@router.get(
    "/reports",
    response_model=list[ReportSummary],
    summary="List Past Security Audit Reports"
)
async def list_reports(
    limit: int = 50,
    db: AsyncSession = Depends(get_db)
):
    """Retrieve historical scan reports from SQLite."""
    stmt = select(AuditReport).order_by(desc(AuditReport.scanned_at)).limit(limit)
    res = await db.execute(stmt)
    return res.scalars().all()

@router.get(
    "/reports/{report_id}",
    response_model=ReportResponse,
    summary="Get Detailed Audit Report by ID"
)
async def get_report_by_id(
    report_id: int,
    db: AsyncSession = Depends(get_db)
):
    """Retrieve full audit report with all findings and remediation fixes."""
    stmt = select(AuditReport).where(AuditReport.id == report_id)
    res = await db.execute(stmt)
    report = res.scalar_one_or_none()

    if not report:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Audit report with ID {report_id} not found."
        )
    return report
