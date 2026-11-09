from typing import Any
from app.scanner.rules.base import Finding
from app.models.schemas import CategorySummary

def calculate_grade(numerical_score: int) -> str:
    """Map numerical score (0 - 100) to letter grade A-F."""
    if numerical_score >= 95:
        return "A+"
    elif numerical_score >= 85:
        return "A"
    elif numerical_score >= 75:
        return "B"
    elif numerical_score >= 65:
        return "C"
    elif numerical_score >= 50:
        return "D"
    else:
        return "F"

def score_audit(findings: list[Finding]) -> tuple[str, int, list[CategorySummary]]:
    """
    Computes overall score (0-100), letter grade (A-F), and per-category breakdowns.
    Baseline starts at 100 and applies deduction penalties.
    """
    base_score = 100
    total_deductions = sum(abs(f.score_impact) for f in findings if f.score_impact < 0)
    final_score = max(0, min(100, base_score - total_deductions))
    letter_grade = calculate_grade(final_score)

    # Compute category statistics
    category_map: dict[str, list[Finding]] = {}
    for f in findings:
        category_map.setdefault(f.category, []).append(f)

    category_summaries: list[CategorySummary] = []
    for cat_name, cat_findings in category_map.items():
        cat_deductions = sum(abs(f.score_impact) for f in cat_findings if f.score_impact < 0)
        cat_score = max(0, 100 - cat_deductions)
        category_summaries.append(CategorySummary(
            category=cat_name,
            score=cat_score,
            max_score=100,
            findings_count=len(cat_findings)
        ))

    return letter_grade, final_score, category_summaries
