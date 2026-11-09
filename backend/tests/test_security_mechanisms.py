import pytest
from app.scanner.security import (
    validate_and_sanitize_url,
    SSRFSecurityError,
    InvalidTargetURLError
)
from app.api.rate_limiter import InMemoryRateLimiter

def test_ssrf_blocks_cloud_metadata():
    with pytest.raises(SSRFSecurityError):
        validate_and_sanitize_url("http://169.254.169.254/latest/meta-data/", allow_local=False)

def test_ssrf_blocks_private_rfc1918():
    with pytest.raises(SSRFSecurityError):
        validate_and_sanitize_url("http://10.0.0.1/admin", allow_local=False)

    with pytest.raises(SSRFSecurityError):
        validate_and_sanitize_url("http://192.168.1.1", allow_local=False)

def test_rejects_insecure_protocols():
    with pytest.raises(InvalidTargetURLError):
        validate_and_sanitize_url("file:///etc/passwd")

    with pytest.raises(InvalidTargetURLError):
        validate_and_sanitize_url("gopher://127.0.0.1:70")

    with pytest.raises(InvalidTargetURLError):
        validate_and_sanitize_url("ftp://example.com")

def test_rejects_credentials_in_url():
    with pytest.raises(InvalidTargetURLError):
        validate_and_sanitize_url("https://admin:secret@example.com")

def test_valid_public_url_sanitized():
    sanitized = validate_and_sanitize_url("example.com")
    assert sanitized == "https://example.com"

    sanitized_http = validate_and_sanitize_url("http://example.com")
    assert sanitized_http == "http://example.com"

def test_rate_limiter():
    limiter = InMemoryRateLimiter(requests_per_minute=3)
    client_ip = "192.0.2.1"

    # First 3 should pass
    assert limiter.is_allowed(client_ip)[0] is True
    assert limiter.is_allowed(client_ip)[0] is True
    assert limiter.is_allowed(client_ip)[0] is True

    # 4th should be blocked with retry-after
    allowed, retry_after = limiter.is_allowed(client_ip)
    assert allowed is False
    assert retry_after > 0
