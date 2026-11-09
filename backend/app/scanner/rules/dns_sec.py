from typing import Any
from urllib.parse import urlparse
from app.scanner.rules.base import BaseRule, Finding

class DNSSECAndEmailAuthRule(BaseRule):
    category = "DNS & Domain Security"
    rule_id = "RULE_DNS_DOMAIN"
    title = "Audit DNSSEC, SPF, and DMARC Security"

    async def evaluate(self, target_url: str, context: dict[str, Any]) -> list[Finding]:
        findings: list[Finding] = []
        domain = context.get("domain", urlparse(target_url).hostname or "")

        dns_info = context.get("dns_info", {})
        has_spf = dns_info.get("has_spf", False)
        has_dmarc = dns_info.get("has_dmarc", False)

        if not has_spf:
            findings.append(Finding(
                category=self.category,
                rule_id=f"{self.rule_id}_SPF_MISSING",
                title="Missing SPF Record",
                status="WARN",
                score_impact=-5,
                details=f"No SPF (v=spf1) record detected for domain '{domain}'.",
                remediation="Publish an SPF TXT record on your apex domain to deter spoofed emails."
            ))
        else:
            findings.append(Finding(
                category=self.category,
                rule_id=f"{self.rule_id}_SPF_PRESENT",
                title="SPF Record Configured",
                status="PASS",
                score_impact=0,
                details=f"Valid SPF record discovered for domain '{domain}'.",
                remediation=None
            ))

        if not has_dmarc:
            findings.append(Finding(
                category=self.category,
                rule_id=f"{self.rule_id}_DMARC_MISSING",
                title="Missing DMARC Policy",
                status="WARN",
                score_impact=-5,
                details=f"No DMARC (_dmarc.{domain}) record detected.",
                remediation="Publish a DMARC policy (e.g. 'v=DMARC1; p=reject;') to protect against domain spoofing."
            ))
        else:
            findings.append(Finding(
                category=self.category,
                rule_id=f"{self.rule_id}_DMARC_PRESENT",
                title="DMARC Policy Configured",
                status="PASS",
                score_impact=0,
                details=f"DMARC record present for domain '{domain}'.",
                remediation=None
            ))

        return findings
