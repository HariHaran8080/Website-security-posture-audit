import asyncio
from unittest.mock import AsyncMock, patch
import pytest
from app.scanner.engine import SecurityScannerEngine
from app.scanner.exceptions import UnauthorizedScanError

def test_scanner_refuses_run_without_permission():
    engine = SecurityScannerEngine()

    with pytest.raises(UnauthorizedScanError) as exc_info:
        asyncio.run(engine.scan(target_url="https://example.com", has_permission=False))

    assert "CONSENT REFUSED" in str(exc_info.value)

def test_scanner_executes_when_permission_granted():
    engine = SecurityScannerEngine(rules=[])
    mock_context = {
        "target_url": "https://example.com",
        "has_permission": True,
        "hostname": "example.com",
        "headers": {},
        "raw_cookie_headers": [],
        "status_code": 200
    }
    with patch.object(engine, "_gather_context", new_callable=AsyncMock) as mock_gather:
        mock_gather.return_value = mock_context
        result = asyncio.run(engine.scan(target_url="https://example.com", has_permission=True))

        assert result["consent_acknowledged"] is True
        assert result["grade"] == "A+"
        assert result["numerical_score"] == 100
        assert "top_fixes" in result
        assert "severity_summary" in result
        assert "owasp_summary" in result
