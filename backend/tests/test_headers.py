import pytest
from app.scanner.rules.headers import SecurityHeadersRule
from app.scanner.constants import FindingStatus, Severity

def test_headers_all_missing():
    rule = SecurityHeadersRule()
    findings = rule.evaluate_headers({})

    assert len(findings) == 6
    for f in findings:
        assert f.status == FindingStatus.MISSING
        assert f.attacker_abuse != ""
        assert f.fix != ""
        assert f.severity in [Severity.HIGH, Severity.MEDIUM, Severity.LOW]

def test_headers_fully_secure():
    rule = SecurityHeadersRule()
    secure_headers = {
        "Content-Security-Policy": "default-src 'self'; script-src 'self';",
        "Strict-Transport-Security": "max-age=31536000; includeSubDomains; preload",
        "X-Frame-Options": "DENY",
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "strict-origin-when-cross-origin",
        "Permissions-Policy": "camera=(), microphone=(), geolocation=()"
    }
    findings = rule.evaluate_headers(secure_headers)
    assert len(findings) == 6
    for f in findings:
        assert f.status == FindingStatus.PASS
        assert f.score_impact == 0

def test_headers_weak_csp_and_hsts():
    rule = SecurityHeadersRule()
    weak_headers = {
        "Content-Security-Policy": "script-src 'self' 'unsafe-inline';",
        "Strict-Transport-Security": "max-age=300",
        "X-Frame-Options": "DENY",
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "unsafe-url",
        "Permissions-Policy": "camera=*"
    }
    findings = rule.evaluate_headers(weak_headers)
    status_map = {f.id: f.status for f in findings}
    assert status_map["HDR_CSP_WEAK"] == FindingStatus.WEAK
    assert status_map["HDR_HSTS_WEAK"] == FindingStatus.WEAK
    assert status_map["HDR_REF_WEAK"] == FindingStatus.WEAK
    assert status_map["HDR_PERM_WEAK"] == FindingStatus.WEAK
