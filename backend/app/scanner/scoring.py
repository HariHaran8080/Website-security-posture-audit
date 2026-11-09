from typing import Any
from app.scanner.rules.base import Finding
from app.scanner.constants import Severity, FindingStatus, OWASP

SEVERITY_WEIGHTS = {
    Severity.CRITICAL: 25,
    Severity.HIGH: 15,
    Severity.MEDIUM: 8,
    Severity.LOW: 3,
    Severity.INFO: 0
}

def calculate_letter_grade(score: int) -> str:
    if score >= 95:
        return "A+"
    elif score >= 85:
        return "A"
    elif score >= 75:
        return "B"
    elif score >= 65:
        return "C"
    elif score >= 50:
        return "D"
    else:
        return "F"

def calculate_posture_score(findings: list[Finding]) -> dict[str, Any]:
    """
    Computes posture score (0-100), A-F grade, severity distribution,
    OWASP Top 10 breakdown, and top 3 prioritized fixes.
    """
    base_score = 100
    total_deduction = 0

    severity_counts = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "info": 0
    }

    owasp_counts: dict[str, int] = {}
    failing_findings: list[Finding] = []

    for f in findings:
        # Check if finding represents an issue / defect
        is_issue = f.status in [FindingStatus.FAIL, FindingStatus.WEAK, FindingStatus.MISSING]

        if is_issue:
            sev_key = f.severity.value if hasattr(f.severity, "value") else str(f.severity).lower()
            severity_counts[sev_key] = severity_counts.get(sev_key, 0) + 1

            # Penalty calculation
            sev_enum = Severity(sev_key) if sev_key in [s.value for s in Severity] else Severity.LOW
            weight = SEVERITY_WEIGHTS.get(sev_enum, 5)
            # Use specific score_impact if negative, else default to severity weight
            impact = abs(f.score_impact) if f.score_impact != 0 else weight
            total_deduction += impact

            # OWASP mapping
            owasp_cat = f.owasp_category or OWASP.A05_SECURITY_MISCONFIGURATION.value
            owasp_counts[owasp_cat] = owasp_counts.get(owasp_cat, 0) + 1

            failing_findings.append(f)
        else:
            if f.severity == Severity.INFO:
                severity_counts["info"] += 1

    final_score = max(0, min(100, base_score - total_deduction))
    letter_grade = calculate_letter_grade(final_score)

    # Sort failing findings by priority to extract top 3 fixes
    def sort_key(item: Finding):
        priority_order = {
            Severity.CRITICAL: 4,
            Severity.HIGH: 3,
            Severity.MEDIUM: 2,
            Severity.LOW: 1,
            Severity.INFO: 0
        }
        return (
            priority_order.get(item.severity, 0),
            abs(item.score_impact)
        )

    failing_sorted = sorted(failing_findings, key=sort_key, reverse=True)

    top_3_fixes = []
    seen_titles = set()
    for f in failing_sorted:
        if f.title not in seen_titles:
            seen_titles.add(f.title)
            top_3_fixes.append({
                "id": f.id,
                "title": f.title,
                "severity": f.severity.value,
                "owasp_category": f.owasp_category,
                "fix": f.fix,
                "impact": f.attacker_abuse[:180] + "..." if len(f.attacker_abuse) > 180 else f.attacker_abuse
            })
        if len(top_3_fixes) == 3:
            break

    return {
        "score": final_score,
        "grade": letter_grade,
        "severity_summary": severity_counts,
        "owasp_summary": owasp_counts,
        "top_fixes": top_3_fixes,
        "total_issues": sum(severity_counts[k] for k in ["critical", "high", "medium", "low"])
    }
