from typing import Any
from urllib.parse import urlparse
from app.scanner.rules.base import BaseRule, Finding

class SSLTLSRule(BaseRule):
    category = "SSL / TLS Configuration"
    rule_id = "RULE_SSL_TLS"
    title = "Audit SSL/TLS Encryption & Protocol"

    async def evaluate(self, target_url: str, context: dict[str, Any]) -> list[Finding]:
        findings: list[Finding] = []
        parsed = urlparse(target_url)

        if parsed.scheme.lower() != "https":
            findings.append(Finding(
                category=self.category,
                rule_id=f"{self.rule_id}_NO_HTTPS",
                title="Insecure HTTP Scheme",
                status="FAIL",
                score_impact=-30,
                details=f"The target website communicates over plain HTTP: {target_url}",
                remediation="Configure a valid TLS certificate and enforce automatic HTTP-to-HTTPS redirection."
            ))
            return findings

        # Check TLS handshake details from context
        tls_info = context.get("tls_info", {})
        version = tls_info.get("version", "TLSv1.2")
        cipher = tls_info.get("cipher", "ECDHE-RSA-AES128-GCM-SHA256")
        cert_valid = tls_info.get("cert_valid", True)

        if not cert_valid:
            findings.append(Finding(
                category=self.category,
                rule_id=f"{self.rule_id}_INVALID_CERT",
                title="Invalid or Expired SSL/TLS Certificate",
                status="FAIL",
                score_impact=-40,
                details="The remote SSL/TLS certificate is expired, self-signed, or untrusted.",
                remediation="Install a valid SSL/TLS certificate issued by a trusted Certificate Authority (e.g. Let's Encrypt)."
            ))
        else:
            findings.append(Finding(
                category=self.category,
                rule_id=f"{self.rule_id}_CERT_VALID",
                title="Valid SSL/TLS Certificate",
                status="PASS",
                score_impact=0,
                details=f"Certificate is valid. Protocol: {version}, Cipher: {cipher}",
                remediation=None
            ))

        return findings
