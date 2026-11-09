import pytest
from app.scanner.rules.cookies import CookieSecurityRule
from app.scanner.rules.tls import TLSCheckRule
from app.scanner.constants import FindingStatus, Severity

def test_cookie_missing_flags():
    rule = CookieSecurityRule()
    raw_cookies = [
        "session_id=abc123456; Path=/;"
    ]
    findings = rule.evaluate_cookie_headers(raw_cookies)
    ids = {f.id for f in findings}
    assert "COOKIE_SESSION_ID_NO_SECURE" in ids
    assert "COOKIE_SESSION_ID_NO_HTTPONLY" in ids
    assert "COOKIE_SESSION_ID_NO_SAMESITE" in ids

def test_cookie_fully_hardened():
    rule = CookieSecurityRule()
    raw_cookies = [
        "auth_token=xyz789; Secure; HttpOnly; SameSite=Strict; Path=/;"
    ]
    findings = rule.evaluate_cookie_headers(raw_cookies)
    pass_finding = next((f for f in findings if f.id == "COOKIE_AUTH_TOKEN_FULLY_SECURE"), None)
    assert pass_finding is not None
    assert pass_finding.status == FindingStatus.PASS
    assert pass_finding.severity == Severity.INFO

def test_cookie_samesite_none_without_secure():
    rule = CookieSecurityRule()
    raw_cookies = [
        "tracking_id=track1; SameSite=None; Path=/;"
    ]
    findings = rule.evaluate_cookie_headers(raw_cookies)
    ids = {f.id for f in findings}
    assert "COOKIE_TRACKING_ID_SAMESITE_NONE_INSECURE" in ids

def test_tls_non_https():
    import asyncio
    rule = TLSCheckRule()
    findings = asyncio.run(rule.evaluate("http://example.com", {}))
    assert len(findings) == 1
    assert findings[0].id == "TLS_NOT_HTTPS"
    assert findings[0].severity == Severity.CRITICAL
