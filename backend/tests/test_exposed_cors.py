import pytest
from app.scanner.rules.cors import CORSRule
from app.scanner.constants import FindingStatus, Severity

def test_cors_no_headers():
    rule = CORSRule()
    findings = rule.evaluate_cors_headers({})
    assert len(findings) == 1
    assert findings[0].id == "CORS_NOT_ENABLED"
    assert findings[0].status == FindingStatus.PASS

def test_cors_reflected_origin_with_credentials():
    rule = CORSRule()
    evil = "https://unauthorized-attacker.example.com"
    headers = {
        "Access-Control-Allow-Origin": evil,
        "Access-Control-Allow-Credentials": "true"
    }
    findings = rule.evaluate_cors_headers(headers, test_origin=evil)
    assert len(findings) == 1
    f = findings[0]
    assert f.id == "CORS_REFLECTED_ORIGIN_WITH_CREDS"
    assert f.severity == Severity.CRITICAL
    assert f.status == FindingStatus.FAIL
    assert "cross-origin authenticated" in f.attacker_abuse.lower()

def test_cors_whitelisted():
    rule = CORSRule()
    headers = {
        "Access-Control-Allow-Origin": "https://trusted-client.example.com",
    }
    findings = rule.evaluate_cors_headers(headers)
    assert len(findings) == 1
    assert findings[0].id == "CORS_WHITELISTED"
    assert findings[0].status == FindingStatus.PASS
