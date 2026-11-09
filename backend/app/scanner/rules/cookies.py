from typing import Any
from http.cookies import SimpleCookie
from app.scanner.rules.base import BaseRule, Finding
from app.scanner.constants import Severity, FindingStatus, OWASP

class CookieSecurityRule(BaseRule):
    category = "Cookie Security"
    rule_id = "RULE_COOKIE_FLAGS"

    def evaluate_cookie_headers(self, raw_set_cookie_headers: list[str]) -> list[Finding]:
        findings: list[Finding] = []

        if not raw_set_cookie_headers:
            findings.append(Finding(
                id="COOKIE_NONE_SET",
                category=self.category,
                title="No Set-Cookie Headers Observed",
                status=FindingStatus.INFO,
                severity=Severity.INFO,
                details="No cookies were issued on the initial landing response.",
                attacker_abuse="None. No client cookies detected in scope.",
                fix="Ensure sensitive authentication cookies set later implement Secure, HttpOnly, and SameSite attributes.",
                owasp_category=OWASP.A05_SECURITY_MISCONFIGURATION.value,
                score_impact=0
            ))
            return findings

        for raw_header in raw_set_cookie_headers:
            cookie_parser = SimpleCookie()
            try:
                cookie_parser.load(raw_header)
            except Exception:
                continue

            for cookie_name, morsel in cookie_parser.items():
                cookie_attrs = {k.lower(): v for k, v in morsel.items()}
                # Check for Secure, HttpOnly, SameSite
                raw_lower = raw_header.lower()

                has_secure = bool(morsel.get("secure")) or "secure" in raw_lower
                has_httponly = bool(morsel.get("httponly")) or "httponly" in raw_lower
                samesite = morsel.get("samesite") or ""
                if not samesite and "samesite" in raw_lower:
                    for part in raw_header.split(";"):
                        if "samesite" in part.lower() and "=" in part:
                            samesite = part.split("=")[1].strip()

                samesite_lower = str(samesite).lower() if samesite else ""

                # 1. Missing Secure flag
                if not has_secure:
                    findings.append(Finding(
                        id=f"COOKIE_{cookie_name.upper()}_NO_SECURE",
                        category=self.category,
                        title=f"Cookie '{cookie_name}' Missing 'Secure' Flag",
                        status=FindingStatus.MISSING,
                        severity=Severity.HIGH,
                        details=f"The cookie '{cookie_name}' lacks the Secure attribute and may be transmitted over unencrypted HTTP.",
                        attacker_abuse=(
                            "If a user is tricked into navigating to an unencrypted HTTP URL (or an attacker on the same "
                            "network performs an active MITM or SSL stripping attack), the browser transmits this cookie "
                            "in plaintext, exposing session credentials to interception."
                        ),
                        fix=f"Set-Cookie: {cookie_name}=...; Secure; HttpOnly; SameSite=Lax",
                        owasp_category=OWASP.A02_CRYPTOGRAPHIC_FAILURES.value,
                        score_impact=-10
                    ))

                # 2. Missing HttpOnly flag
                if not has_httponly:
                    findings.append(Finding(
                        id=f"COOKIE_{cookie_name.upper()}_NO_HTTPONLY",
                        category=self.category,
                        title=f"Cookie '{cookie_name}' Missing 'HttpOnly' Flag",
                        status=FindingStatus.MISSING,
                        severity=Severity.HIGH,
                        details=f"The cookie '{cookie_name}' is accessible to client-side scripts via `document.cookie`.",
                        attacker_abuse=(
                            "If any Cross-Site Scripting (XSS) vulnerability exists anywhere on the domain, "
                            "an attacker's payload can immediately read this cookie and exfiltrate it to an external server, "
                            "leading to full session hijacking."
                        ),
                        fix=f"Set-Cookie: {cookie_name}=...; HttpOnly; Secure; SameSite=Lax",
                        owasp_category=OWASP.A07_AUTH_FAILURES.value,
                        score_impact=-10
                    ))

                # 3. SameSite evaluation
                if not samesite_lower:
                    findings.append(Finding(
                        id=f"COOKIE_{cookie_name.upper()}_NO_SAMESITE",
                        category=self.category,
                        title=f"Cookie '{cookie_name}' Missing 'SameSite' Attribute",
                        status=FindingStatus.MISSING,
                        severity=Severity.MEDIUM,
                        details=f"No SameSite directive defined for cookie '{cookie_name}'.",
                        attacker_abuse=(
                            "Without SameSite protection, the cookie is sent along with cross-site requests initiated by "
                            "malicious websites, exposing the application to Cross-Site Request Forgery (CSRF)."
                        ),
                        fix=f"Set-Cookie: {cookie_name}=...; SameSite=Lax; Secure; HttpOnly",
                        owasp_category=OWASP.A01_BROKEN_ACCESS_CONTROL.value,
                        score_impact=-5
                    ))
                elif samesite_lower == "none" and not has_secure:
                    findings.append(Finding(
                        id=f"COOKIE_{cookie_name.upper()}_SAMESITE_NONE_INSECURE",
                        category=self.category,
                        title=f"Cookie '{cookie_name}' SameSite=None without Secure",
                        status=FindingStatus.WEAK,
                        severity=Severity.HIGH,
                        details="SameSite=None was set without the mandatory Secure attribute.",
                        attacker_abuse="Modern browsers reject SameSite=None cookies unless accompanied by the Secure flag.",
                        fix=f"Set-Cookie: {cookie_name}=...; SameSite=None; Secure",
                        owasp_category=OWASP.A05_SECURITY_MISCONFIGURATION.value,
                        score_impact=-10
                    ))
                elif samesite_lower in ["lax", "strict"]:
                    findings.append(Finding(
                        id=f"COOKIE_{cookie_name.upper()}_SAMESITE_SECURE",
                        category=self.category,
                        title=f"Cookie '{cookie_name}' SameSite Configured ({samesite.capitalize()})",
                        status=FindingStatus.PASS,
                        severity=Severity.INFO,
                        details=f"Proper SameSite={samesite.capitalize()} attribute configured.",
                        attacker_abuse="None. SameSite attribute protects against unauthenticated cross-site requests.",
                        fix="Retain SameSite configuration.",
                        owasp_category=OWASP.A01_BROKEN_ACCESS_CONTROL.value,
                        score_impact=0
                    ))

                # Pass finding if all 3 are present
                if has_secure and has_httponly and samesite_lower in ["lax", "strict"]:
                    findings.append(Finding(
                        id=f"COOKIE_{cookie_name.upper()}_FULLY_SECURE",
                        category=self.category,
                        title=f"Cookie '{cookie_name}' Fully Hardened",
                        status=FindingStatus.PASS,
                        severity=Severity.INFO,
                        details="Cookie features Secure, HttpOnly, and SameSite protection.",
                        attacker_abuse="None. Cookie cannot be read by JS or transmitted over plaintext.",
                        fix="Maintain this configuration for all session identifiers.",
                        owasp_category=OWASP.A05_SECURITY_MISCONFIGURATION.value,
                        score_impact=0
                    ))

        return findings

    async def evaluate(self, target_url: str, context: dict[str, Any]) -> list[Finding]:
        raw_cookie_headers = context.get("raw_cookie_headers", [])
        return self.evaluate_cookie_headers(raw_cookie_headers)
