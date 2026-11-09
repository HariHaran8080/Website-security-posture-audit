import pytest
from app.scanner.scoring import calculate_posture_score, calculate_letter_grade
from app.scanner.rules.base import Finding
from app.scanner.constants import Severity, FindingStatus, OWASP

def test_grade_calculation():
    assert calculate_letter_grade(98) == "A+"
    assert calculate_letter_grade(88) == "A"
    assert calculate_letter_grade(78) == "B"
    assert calculate_letter_grade(68) == "C"
    assert calculate_letter_grade(52) == "D"
    assert calculate_letter_grade(40) == "F"

def test_scoring_with_critical_issues():
    findings = [
        Finding(
            id="CRIT_1",
            category="Test",
            title="Critical Port Open",
            status=FindingStatus.FAIL,
            severity=Severity.CRITICAL,
            details="Telnet is open",
            attacker_abuse="Cleartext traffic interception",
            fix="Disable telnet",
            owasp_category=OWASP.A05_SECURITY_MISCONFIGURATION.value,
            score_impact=-25
        ),
        Finding(
            id="HIGH_1",
            category="Test",
            title="Missing CSP",
            status=FindingStatus.MISSING,
            severity=Severity.HIGH,
            details="No CSP",
            attacker_abuse="XSS execution",
            fix="Add CSP",
            owasp_category=OWASP.A05_SECURITY_MISCONFIGURATION.value,
            score_impact=-15
        )
    ]

    res = calculate_posture_score(findings)
    assert res["score"] == 60  # 100 - 25 - 15
    assert res["grade"] == "D"
    assert res["severity_summary"]["critical"] == 1
    assert res["severity_summary"]["high"] == 1
    assert len(res["top_fixes"]) == 2
    assert res["top_fixes"][0]["severity"] == "critical"
