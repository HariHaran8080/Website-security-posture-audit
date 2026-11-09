from app.scanner.rules.base import BaseRule, Finding
from app.scanner.rules.headers import SecurityHeadersRule
from app.scanner.rules.tls import TLSCheckRule
from app.scanner.rules.cookies import CookieSecurityRule
from app.scanner.rules.exposed_files import ExposedFilesRule
from app.scanner.rules.cors import CORSRule
from app.scanner.rules.port_scanner import PortScannerRule

ALL_RULES: list[BaseRule] = [
    SecurityHeadersRule(),
    TLSCheckRule(),
    CookieSecurityRule(),
    ExposedFilesRule(),
    CORSRule(),
    PortScannerRule(),
]

__all__ = [
    "BaseRule",
    "Finding",
    "SecurityHeadersRule",
    "TLSCheckRule",
    "CookieSecurityRule",
    "ExposedFilesRule",
    "CORSRule",
    "PortScannerRule",
    "ALL_RULES",
]
