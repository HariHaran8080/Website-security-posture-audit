import socket
import ssl
from datetime import datetime, timezone
from urllib.parse import urlparse
from typing import Any

from app.scanner.rules.base import BaseRule, Finding
from app.scanner.constants import Severity, FindingStatus, OWASP

class TLSCheckRule(BaseRule):
    category = "TLS / SSL Configuration"
    rule_id = "RULE_TLS_CHECK"

    def inspect_tls(self, hostname: str, port: int = 443, timeout: float = 2.0) -> list[Finding]:
        findings: list[Finding] = []

        # 1. Primary Handshake & Certificate Validation
        cert_info = None
        negotiated_protocol = None
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((hostname, port), timeout=timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert_info = ssock.getpeercert()
                    negotiated_protocol = ssock.version()
        except ssl.SSLCertVerificationError as e:
            findings.append(Finding(
                id="TLS_CERT_UNTRUSTED",
                category=self.category,
                title="SSL/TLS Certificate Verification Failed",
                status=FindingStatus.FAIL,
                severity=Severity.CRITICAL,
                details=f"Certificate verification error: {e.verify_message if hasattr(e, 'verify_message') else str(e)}",
                attacker_abuse=(
                    "An untrusted, self-signed, or hostname-mismatched certificate allows an active Man-in-the-Middle (MitM) "
                    "attacker to spoof the server, intercept encrypted traffic, and decrypt all user communications."
                ),
                fix="Install a valid SSL/TLS certificate from a trusted Certificate Authority (e.g. Let's Encrypt) matching the host domain.",
                owasp_category=OWASP.A02_CRYPTOGRAPHIC_FAILURES.value,
                score_impact=-30
            ))
            return findings
        except Exception as e:
            findings.append(Finding(
                id="TLS_CONN_FAILED",
                category=self.category,
                title="TLS Handshake Failed",
                status=FindingStatus.FAIL,
                severity=Severity.HIGH,
                details=f"Unable to establish TLS connection to {hostname}:{port}: {str(e)}",
                attacker_abuse="The service does not support TLS or fails during standard cryptographic negotiation.",
                fix="Verify web server SSL/TLS listener configuration on port 443.",
                owasp_category=OWASP.A02_CRYPTOGRAPHIC_FAILURES.value,
                score_impact=-25
            ))
            return findings

        # 2. Check Expiry and Issuer
        if cert_info:
            not_after_str = cert_info.get("notAfter")
            issuer_dict = dict(x[0] for x in cert_info.get("issuer", []))
            issuer_name = issuer_dict.get("organizationName") or issuer_dict.get("commonName") or "Unknown Issuer"

            if not_after_str:
                # Format: 'May 10 12:00:00 2027 GMT'
                try:
                    expiry_date = datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                    now = datetime.now(timezone.utc)
                    days_remaining = (expiry_date - now).days

                    if days_remaining < 0:
                        findings.append(Finding(
                            id="TLS_CERT_EXPIRED",
                            category=self.category,
                            title="SSL/TLS Certificate Expired",
                            status=FindingStatus.FAIL,
                            severity=Severity.CRITICAL,
                            details=f"Certificate expired on {expiry_date.strftime('%Y-%m-%d')} ({abs(days_remaining)} days ago). Issuer: {issuer_name}",
                            attacker_abuse="Users receive scary browser security warnings, and expired certs can no longer guarantee cryptographic trust.",
                            fix="Renew the SSL/TLS certificate immediately and configure auto-renewal via Certbot/ACME.",
                            owasp_category=OWASP.A02_CRYPTOGRAPHIC_FAILURES.value,
                            score_impact=-30
                        ))
                    elif days_remaining < 30:
                        findings.append(Finding(
                            id="TLS_CERT_EXPIRING_SOON",
                            category=self.category,
                            title="SSL/TLS Certificate Expiring Soon",
                            status=FindingStatus.WEAK,
                            severity=Severity.MEDIUM,
                            details=f"Certificate expires in {days_remaining} days ({expiry_date.strftime('%Y-%m-%d')}). Issuer: {issuer_name}",
                            attacker_abuse="If not renewed in time, visitors will face complete service outage and browser security blocks.",
                            fix="Initiate certificate renewal and verify automated renewal scripts.",
                            owasp_category=OWASP.A02_CRYPTOGRAPHIC_FAILURES.value,
                            score_impact=-5
                        ))
                    else:
                        findings.append(Finding(
                            id="TLS_CERT_VALID",
                            category=self.category,
                            title="Valid SSL/TLS Certificate",
                            status=FindingStatus.PASS,
                            severity=Severity.INFO,
                            details=f"Certificate issued by {issuer_name}, valid for {days_remaining} more days.",
                            attacker_abuse="None. Certificate is valid and actively verified.",
                            fix="Maintain active automated monitoring for expiration.",
                            owasp_category=OWASP.A02_CRYPTOGRAPHIC_FAILURES.value,
                            score_impact=0
                        ))
                except Exception:
                    pass

        # 3. Protocol Version
        if negotiated_protocol in ["TLSv1.3", "TLSv1.2"]:
            findings.append(Finding(
                id="TLS_MODERN_PROTOCOL",
                category=self.category,
                title="Modern TLS Protocol Negotiated",
                status=FindingStatus.PASS,
                severity=Severity.INFO,
                details=f"Successfully negotiated secure protocol: {negotiated_protocol}",
                attacker_abuse="None. Robust modern cipher suites and protocol version in use.",
                fix="Continue prioritizing TLS 1.3 and TLS 1.2.",
                owasp_category=OWASP.A02_CRYPTOGRAPHIC_FAILURES.value,
                score_impact=0
            ))
        else:
            findings.append(Finding(
                id="TLS_OUTDATED_PROTOCOL",
                category=self.category,
                title="Outdated TLS Protocol in Use",
                status=FindingStatus.FAIL,
                severity=Severity.HIGH,
                details=f"Negotiated deprecated protocol: {negotiated_protocol}",
                attacker_abuse="Older protocols have known cryptographic flaws allowing cipher downgrade attacks.",
                fix="Disable protocols below TLS 1.2 in your web server / load balancer configuration.",
                owasp_category=OWASP.A02_CRYPTOGRAPHIC_FAILURES.value,
                score_impact=-15
            ))

        # 4. Check whether weak protocols (TLS 1.0 / TLS 1.1) are accepted
        weak_tls_accepted = self._test_weak_tls(hostname, port, timeout)
        if weak_tls_accepted:
            findings.append(Finding(
                id="TLS_WEAK_PROTOCOLS_ACCEPTED",
                category=self.category,
                title="Legacy Protocols (TLS 1.0 / 1.1) Accepted",
                status=FindingStatus.FAIL,
                severity=Severity.HIGH,
                details="The server successfully negotiates deprecated TLS 1.0 or TLS 1.1 connections.",
                attacker_abuse=(
                    "TLS 1.0 and 1.1 lack modern cipher strength and are vulnerable to protocol downgrade attacks "
                    "(e.g., POODLE, BEAST) enabling traffic decryption."
                ),
                fix="In Nginx/Apache/Cloudflare configuration, restrict protocols: `ssl_protocols TLSv1.2 TLSv1.3;`",
                owasp_category=OWASP.A02_CRYPTOGRAPHIC_FAILURES.value,
                score_impact=-15
            ))
        else:
            findings.append(Finding(
                id="TLS_WEAK_PROTOCOLS_REJECTED",
                category=self.category,
                title="Deprecated Protocols (TLS 1.0 / 1.1) Disabled",
                status=FindingStatus.PASS,
                severity=Severity.INFO,
                details="Legacy TLS 1.0 and 1.1 handshakes are rejected.",
                attacker_abuse="None. Attackers cannot force legacy protocol downgrade.",
                fix="Keep deprecated TLS versions disabled.",
                owasp_category=OWASP.A02_CRYPTOGRAPHIC_FAILURES.value,
                score_impact=0
            ))

        return findings

    def _test_weak_tls(self, hostname: str, port: int, timeout: float) -> bool:
        """Safely probe if TLS 1.0 or 1.1 can be negotiated."""
        for proto_version in [ssl.TLSVersion.TLSv1, ssl.TLSVersion.TLSv1_1]:
            try:
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                ctx.maximum_version = proto_version
                ctx.minimum_version = proto_version
                # Allow legacy ciphers if supported by local OpenSSL
                try:
                    ctx.set_ciphers("DEFAULT:@SECLEVEL=0")
                except Exception:
                    pass

                with socket.create_connection((hostname, port), timeout=timeout) as sock:
                    with ctx.wrap_socket(sock) as ssock:
                        if ssock.version() in ["TLSv1", "TLSv1.1"]:
                            return True
            except Exception:
                # Connection refused or handshake error means weak protocol rejected
                continue
        return False

    async def evaluate(self, target_url: str, context: dict[str, Any]) -> list[Finding]:
        parsed = urlparse(target_url)
        if parsed.scheme.lower() != "https":
            return [Finding(
                id="TLS_NOT_HTTPS",
                category=self.category,
                title="Target Communicates over Plain HTTP",
                status=FindingStatus.FAIL,
                severity=Severity.CRITICAL,
                details="The target website does not use HTTPS.",
                attacker_abuse="All credentials, cookies, and communications travel unencrypted over the network.",
                fix="Enforce HTTPS across all pages and redirect HTTP traffic to port 443.",
                owasp_category=OWASP.A02_CRYPTOGRAPHIC_FAILURES.value,
                score_impact=-30
            )]

        hostname = parsed.hostname or target_url
        port = parsed.port or 443
        return self.inspect_tls(hostname, port)
