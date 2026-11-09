from typing import Any
import httpx
from app.scanner.rules.base import BaseRule, Finding
from app.scanner.constants import Severity, FindingStatus, OWASP

class SecurityHeadersRule(BaseRule):
    category = "HTTP Security Headers"
    rule_id = "RULE_HTTP_HEADERS"

    def evaluate_headers(self, headers: dict[str, str]) -> list[Finding]:
        findings: list[Finding] = []
        h = {k.lower(): v.strip() for k, v in headers.items()}

        # 1. Content-Security-Policy
        csp = h.get("content-security-policy")
        if not csp:
            findings.append(Finding(
                id="HDR_CSP_MISSING",
                category=self.category,
                title="Content-Security-Policy (CSP) Missing",
                status=FindingStatus.MISSING,
                severity=Severity.HIGH,
                details="No Content-Security-Policy header detected in the HTTP response.",
                attacker_abuse=(
                    "An attacker who discovers an HTML/DOM injection flaw can inject arbitrary JavaScript, "
                    "load malicious third-party scripts, hijack user sessions, or exfiltrate sensitive data. "
                    "Without CSP, the browser has no whitelist of trusted executable resources."
                ),
                fix="Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none';",
                owasp_category=OWASP.A05_SECURITY_MISCONFIGURATION.value,
                score_impact=-15
            ))
        elif "'unsafe-inline'" in csp or "'unsafe-eval'" in csp or "script-src *" in csp:
            findings.append(Finding(
                id="HDR_CSP_WEAK",
                category=self.category,
                title="Content-Security-Policy (CSP) Weak / Permissive",
                status=FindingStatus.WEAK,
                severity=Severity.MEDIUM,
                details=f"CSP includes permissive directives: `{csp}`",
                attacker_abuse=(
                    "Directives like 'unsafe-inline' or 'unsafe-eval' neutralize XSS defenses by permitting "
                    "inline script tags and string-to-code execution in the user browser."
                ),
                fix="Remove 'unsafe-inline' and 'unsafe-eval'. Use cryptographic nonces or SHA-256 hashes for necessary inline scripts.",
                owasp_category=OWASP.A05_SECURITY_MISCONFIGURATION.value,
                score_impact=-8
            ))
        else:
            findings.append(Finding(
                id="HDR_CSP_PASS",
                category=self.category,
                title="Content-Security-Policy Configured",
                status=FindingStatus.PASS,
                severity=Severity.INFO,
                details=f"Valid CSP configured: `{csp[:80]}...`",
                attacker_abuse="None. The browser enforces a strict resource loading policy.",
                fix="Maintain policy integrity and review regularly.",
                owasp_category=OWASP.A05_SECURITY_MISCONFIGURATION.value,
                score_impact=0
            ))

        # 2. Strict-Transport-Security (HSTS)
        hsts = h.get("strict-transport-security")
        if not hsts:
            findings.append(Finding(
                id="HDR_HSTS_MISSING",
                category=self.category,
                title="Strict-Transport-Security (HSTS) Missing",
                status=FindingStatus.MISSING,
                severity=Severity.HIGH,
                details="Strict-Transport-Security header is missing from the response.",
                attacker_abuse=(
                    "On public or untrusted Wi-Fi networks, an active Man-in-the-Middle (MitM) attacker can "
                    "intercept initial HTTP requests using SSL stripping (e.g. sslstrip), downgrading communication "
                    "to unencrypted HTTP and capturing credentials or session cookies."
                ),
                fix="Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
                owasp_category=OWASP.A02_CRYPTOGRAPHIC_FAILURES.value,
                score_impact=-15
            ))
        elif "max-age" in hsts:
            try:
                max_age_part = [p for p in hsts.split(";") if "max-age" in p.lower()][0]
                max_age_val = int(max_age_part.split("=")[1].strip())
            except Exception:
                max_age_val = 0

            if max_age_val < 15552000 or "includesubdomains" not in hsts.lower():
                findings.append(Finding(
                    id="HDR_HSTS_WEAK",
                    category=self.category,
                    title="Strict-Transport-Security (HSTS) Suboptimal",
                    status=FindingStatus.WEAK,
                    severity=Severity.LOW,
                    details=f"HSTS max-age is short ({max_age_val}s) or missing includeSubDomains: `{hsts}`",
                    attacker_abuse=(
                        "A short max-age expiration window leaves users vulnerable during subsequent visits after the "
                        "cache expires, or leaves unpinned subdomains exposed to HTTP downgrade."
                    ),
                    fix="Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
                    owasp_category=OWASP.A02_CRYPTOGRAPHIC_FAILURES.value,
                    score_impact=-5
                ))
            else:
                findings.append(Finding(
                    id="HDR_HSTS_PASS",
                    category=self.category,
                    title="Strict-Transport-Security (HSTS) Enforced",
                    status=FindingStatus.PASS,
                    severity=Severity.INFO,
                    details=f"HSTS correctly configured: `{hsts}`",
                    attacker_abuse="None. Browsers enforce encrypted HTTPS exclusively.",
                    fix="Maintain HSTS header and submit to the HSTS preload list.",
                    owasp_category=OWASP.A02_CRYPTOGRAPHIC_FAILURES.value,
                    score_impact=0
                ))
        else:
            findings.append(Finding(
                id="HDR_HSTS_WEAK",
                category=self.category,
                title="Strict-Transport-Security (HSTS) Malformed",
                status=FindingStatus.WEAK,
                severity=Severity.LOW,
                details=f"Invalid HSTS header format: `{hsts}`",
                attacker_abuse="Browsers fail to parse malformed HSTS values and fall back to insecure default handling.",
                fix="Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
                owasp_category=OWASP.A02_CRYPTOGRAPHIC_FAILURES.value,
                score_impact=-5
            ))

        # 3. X-Frame-Options
        xfo = h.get("x-frame-options")
        if not xfo:
            findings.append(Finding(
                id="HDR_XFO_MISSING",
                category=self.category,
                title="X-Frame-Options Missing (Clickjacking Risk)",
                status=FindingStatus.MISSING,
                severity=Severity.MEDIUM,
                details="X-Frame-Options header is missing and no CSP frame-ancestors directive was detected.",
                attacker_abuse=(
                    "An attacker can embed the vulnerable application inside a transparent <iframe> on a malicious "
                    "site. By aligning deceptive UI overlays, the attacker tricks an authenticated user into clicking "
                    "privileged action buttons (e.g. deleting an account or authorizing a transaction) without their knowledge."
                ),
                fix="X-Frame-Options: DENY\n# or\nX-Frame-Options: SAMEORIGIN",
                owasp_category=OWASP.A01_BROKEN_ACCESS_CONTROL.value,
                score_impact=-10
            ))
        elif xfo.upper() in ["DENY", "SAMEORIGIN"]:
            findings.append(Finding(
                id="HDR_XFO_PASS",
                category=self.category,
                title="X-Frame-Options Enforced",
                status=FindingStatus.PASS,
                severity=Severity.INFO,
                details=f"Framing restricted with: `{xfo}`",
                attacker_abuse="None. The page cannot be embedded in unauthorized iframes.",
                fix="Keep X-Frame-Options active alongside CSP frame-ancestors.",
                owasp_category=OWASP.A01_BROKEN_ACCESS_CONTROL.value,
                score_impact=0
            ))
        else:
            findings.append(Finding(
                id="HDR_XFO_WEAK",
                category=self.category,
                title="X-Frame-Options Deprecated / Weak Syntax",
                status=FindingStatus.WEAK,
                severity=Severity.LOW,
                details=f"X-Frame-Options has unexpected or deprecated value: `{xfo}`",
                attacker_abuse="Modern browsers ignore invalid or deprecated directives (like ALLOW-FROM), leaving framing unconstrained.",
                fix="X-Frame-Options: DENY",
                owasp_category=OWASP.A01_BROKEN_ACCESS_CONTROL.value,
                score_impact=-5
            ))

        # 4. X-Content-Type-Options
        xcto = h.get("x-content-type-options")
        if not xcto:
            findings.append(Finding(
                id="HDR_XCTO_MISSING",
                category=self.category,
                title="X-Content-Type-Options Missing (MIME-Sniffing Risk)",
                status=FindingStatus.MISSING,
                severity=Severity.MEDIUM,
                details="X-Content-Type-Options header is missing.",
                attacker_abuse=(
                    "Browsers will attempt to MIME-sniff response bodies. If an attacker uploads a file disguised "
                    "as an image containing malicious HTML/JS, the browser may interpret and execute it as HTML/JavaScript, "
                    "resulting in Cross-Site Scripting (XSS)."
                ),
                fix="X-Content-Type-Options: nosniff",
                owasp_category=OWASP.A05_SECURITY_MISCONFIGURATION.value,
                score_impact=-8
            ))
        elif xcto.lower() == "nosniff":
            findings.append(Finding(
                id="HDR_XCTO_PASS",
                category=self.category,
                title="X-Content-Type-Options Enforced",
                status=FindingStatus.PASS,
                severity=Severity.INFO,
                details="Configured to `nosniff`.",
                attacker_abuse="None. Browsers will strictly honor the declared Content-Type header.",
                fix="Retain header configuration across all static and dynamic responses.",
                owasp_category=OWASP.A05_SECURITY_MISCONFIGURATION.value,
                score_impact=0
            ))
        else:
            findings.append(Finding(
                id="HDR_XCTO_WEAK",
                category=self.category,
                title="X-Content-Type-Options Invalid",
                status=FindingStatus.WEAK,
                severity=Severity.LOW,
                details=f"Configured with non-standard value `{xcto}` instead of `nosniff`.",
                attacker_abuse="Non-standard values are disregarded by browsers.",
                fix="X-Content-Type-Options: nosniff",
                owasp_category=OWASP.A05_SECURITY_MISCONFIGURATION.value,
                score_impact=-5
            ))

        # 5. Referrer-Policy
        ref = h.get("referrer-policy")
        if not ref:
            findings.append(Finding(
                id="HDR_REF_MISSING",
                category=self.category,
                title="Referrer-Policy Missing (Information Leakage)",
                status=FindingStatus.MISSING,
                severity=Severity.LOW,
                details="Referrer-Policy header is missing.",
                attacker_abuse=(
                    "When users click outbound links, the full origin and URL path (which may contain reset tokens, "
                    "internal IDs, or search parameters) may be forwarded to external third parties in the HTTP Referer header."
                ),
                fix="Referrer-Policy: strict-origin-when-cross-origin",
                owasp_category=OWASP.A05_SECURITY_MISCONFIGURATION.value,
                score_impact=-4
            ))
        elif any(val in ref.lower() for val in ["strict-origin-when-cross-origin", "no-referrer", "same-origin", "strict-origin"]):
            findings.append(Finding(
                id="HDR_REF_PASS",
                category=self.category,
                title="Referrer-Policy Configured",
                status=FindingStatus.PASS,
                severity=Severity.INFO,
                details=f"Safe Referrer-Policy: `{ref}`",
                attacker_abuse="None. Outbound referrers are trimmed or omitted on cross-origin requests.",
                fix="Maintain recommended policy.",
                owasp_category=OWASP.A05_SECURITY_MISCONFIGURATION.value,
                score_impact=0
            ))
        else:
            findings.append(Finding(
                id="HDR_REF_WEAK",
                category=self.category,
                title="Referrer-Policy Permissive / Insecure",
                status=FindingStatus.WEAK,
                severity=Severity.LOW,
                details=f"Permissive policy detected: `{ref}`",
                attacker_abuse="Policies like 'unsafe-url' leak sensitive path and query string parameters to all origins.",
                fix="Referrer-Policy: strict-origin-when-cross-origin",
                owasp_category=OWASP.A05_SECURITY_MISCONFIGURATION.value,
                score_impact=-3
            ))

        # 6. Permissions-Policy
        perm = h.get("permissions-policy") or h.get("feature-policy")
        if not perm:
            findings.append(Finding(
                id="HDR_PERM_MISSING",
                category=self.category,
                title="Permissions-Policy Missing",
                status=FindingStatus.MISSING,
                severity=Severity.LOW,
                details="Permissions-Policy header is missing.",
                attacker_abuse=(
                    "If an attacker injects a malicious iframe or third-party script into the page, the embedded "
                    "context can request access to sensitive browser features (camera, microphone, geolocation, sensors) "
                    "without the top-level application restricting those permissions."
                ),
                fix="Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=()",
                owasp_category=OWASP.A05_SECURITY_MISCONFIGURATION.value,
                score_impact=-4
            ))
        elif "*" in perm:
            findings.append(Finding(
                id="HDR_PERM_WEAK",
                category=self.category,
                title="Permissions-Policy Wildcard Detected",
                status=FindingStatus.WEAK,
                severity=Severity.LOW,
                details=f"Permissive wildcard in Permissions-Policy: `{perm}`",
                attacker_abuse="Wildcards permit all nested contexts or iframes unrestricted device hardware access.",
                fix="Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=()",
                owasp_category=OWASP.A05_SECURITY_MISCONFIGURATION.value,
                score_impact=-3
            ))
        else:
            findings.append(Finding(
                id="HDR_PERM_PASS",
                category=self.category,
                title="Permissions-Policy Enforced",
                status=FindingStatus.PASS,
                severity=Severity.INFO,
                details=f"Configured policy: `{perm[:80]}...`",
                attacker_abuse="None. Sensitive hardware capabilities are constrained.",
                fix="Maintain policy as new browser capabilities are introduced.",
                owasp_category=OWASP.A05_SECURITY_MISCONFIGURATION.value,
                score_impact=0
            ))

        return findings

    async def evaluate(self, target_url: str, context: dict[str, Any]) -> list[Finding]:
        headers = context.get("headers", {})
        return self.evaluate_headers(headers)
