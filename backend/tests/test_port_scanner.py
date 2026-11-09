import pytest
from app.scanner.rules.port_scanner import PortScannerRule, COMMON_PORTS
from app.scanner.exceptions import UnauthorizedScanError
from app.scanner.constants import Severity, FindingStatus

def test_port_scanner_refuses_without_permission():
    rule = PortScannerRule()
    with pytest.raises(UnauthorizedScanError):
        rule.scan_ports("127.0.0.1", has_permission=False)

def test_port_probe_mock_evaluation():
    rule = PortScannerRule()
    # Mocking port discovery findings by inspecting common ports dictionary mapping
    assert 23 in COMMON_PORTS
    assert COMMON_PORTS[23]["risk"] == Severity.CRITICAL
    assert 3306 in COMMON_PORTS
    assert COMMON_PORTS[3306]["risk"] == Severity.CRITICAL
    assert 443 in COMMON_PORTS
    assert COMMON_PORTS[443]["risk"] == Severity.INFO
