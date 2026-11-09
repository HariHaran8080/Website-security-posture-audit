from typing import Any
import httpx
from app.scanner.rules.base import BaseRule, Finding
from app.scanner.constants import Severity, FindingStatus, OWASP

class CORSRule(BaseRule):
    category = "CORS Configuration"
    rule_id = "RULE_CORS"

    def evaluate_cors_headers(self, headers: dict[str, str], test_origin: str = "https://unauthorized-attacker.example.com") -> list[Finding]:
        findings: list[Finding] = []
        h = {k.lower(): v.strip() for k, v in headers.items()}

        acao = h.get("access-control-allow-origin")
        acac = h.get("access-control-allow-credentials", "").lower() == "true"

        if not acao:
            findings.append(Finding(
                id="CORS_NOT_ENABLED",
                category=self.category,
                title="CORS Headers Not Set / Restricted by Default",
                status=FindingStatus.PASS,
                severity=Severity.INFO,
                details="No Access-Control-Allow-Origin header returned for untrusted origins. Default same-origin policy is enforced.",
                attacker_abuse="None. Browsers enforce the Same-Origin Policy (SOP).",
                fix="If cross-origin sharing is required in the future, whitelist specific trusted domains explicitly.",
                owasp_category=OWASP.A01_BROKEN_ACCESS_CONTROL.value,
                score_impact=0
            ))
            return findings

        # Misconfiguration 1: Reflected Origin with Credentials
        if acao == test_origin and acac:
            findings.append(Finding(
                id="CORS_REFLECTED_ORIGIN_WITH_CREDS",
                category=self.category,
                title="Critical CORS Misconfiguration: Arbitrary Origin Reflection with Credentials",
                status=FindingStatus.FAIL,
                severity=Severity.CRITICAL,
                details=f"The server dynamically reflected arbitrary origin `{test_origin}` and enabled `Access-Control-Allow-Credentials: true`.",
                attacker_abuse=(
                    "An attacker hosting a malicious site can issue cross-origin authenticated XHR/fetch requests "
                    "on behalf of a logged-in victim. Because credentials are sent and the origin is accepted, the attacker's "
                    "JavaScript can read the response data (e.g. personal profiles, messages, API keys, or financial data)."
                ),
                fix=(
                    "Do NOT dynamically reflect the request Origin header when Access-Control-Allow-Credentials is true. "
                    "Validate the incoming Origin against an immutable, hardcoded whitelist of trusted client domains."
                ),
                owasp_category=OWASP.A01_BROKEN_ACCESS_CONTROL.value,
                score_impact=-30
            ))
        elif acao == test_origin and not acac:
            findings.append(Finding(
                id="CORS_REFLECTED_ORIGIN_NO_CREDS",
                category=self.category,
                title="CORS Arbitrary Origin Reflection",
                status=FindingStatus.WEAK,
                severity=Severity.MEDIUM,
                details=f"The server reflected arbitrary origin `{test_origin}` without credentials.",
                attacker_abuse="Allows arbitrary third-party websites to read unauthenticated API responses via client browsers.",
                fix="Validate and restrict Allowed Origins to authorized applications.",
                owasp_category=OWASP.A01_BROKEN_ACCESS_CONTROL.value,
                score_impact=-10
            ))
        elif acao == "*":
            if acac:
                findings.append(Finding(
                    id="CORS_WILDCARD_WITH_CREDS",
                    category=self.category,
                    title="Invalid CORS Config: Wildcard '*' with Credentials",
                    status=FindingStatus.WEAK,
                    severity=Severity.HIGH,
                    details="Access-Control-Allow-Origin is set to '*' with Access-Control-Allow-Credentials: true (rejected by modern browsers, but indicates flawed logic).",
                    attacker_abuse="Indicates misunderstanding of CORS semantics and exposes misconfiguration risks if converted to reflection.",
                    fix="Specify exact trusted origin domains instead of '*'.",
                    owasp_category=OWASP.A01_BROKEN_ACCESS_CONTROL.value,
                    score_impact=-15
                ))
            else:
                findings.append(Finding(
                    id="CORS_WILDCARD_PUBLIC",
                    category=self.category,
                    title="Public CORS Wildcard ('*')",
                    status=FindingStatus.INFO,
                    severity=Severity.INFO,
                    details="Access-Control-Allow-Origin is set to '*'. Appropriate for public APIs, but dangerous if applied to private resources.",
                    attacker_abuse="Any site can read responses from this endpoint without credentials.",
                    fix="If this endpoint returns confidential user data, replace '*' with an explicit whitelist.",
                    owasp_category=OWASP.A01_BROKEN_ACCESS_CONTROL.value,
                    score_impact=0
                ))
        else:
            findings.append(Finding(
                id="CORS_WHITELISTED",
                category=self.category,
                title="CORS Origin Restricted",
                status=FindingStatus.PASS,
                severity=Severity.INFO,
                details=f"Access-Control-Allow-Origin set to specific domain: `{acao}`",
                attacker_abuse="None. Cross-origin access is constrained.",
                fix="Regularly audit the list of authorized origins.",
                owasp_category=OWASP.A01_BROKEN_ACCESS_CONTROL.value,
                score_impact=0
            ))

        return findings

    async def evaluate(self, target_url: str, context: dict[str, Any]) -> list[Finding]:
        test_origin = "https://unauthorized-attacker.example.com"
        try:
            async with httpx.AsyncClient(timeout=4.0, follow_redirects=False, verify=False) as client:
                resp = await client.get(target_url, headers={"Origin": test_origin})
                return self.evaluate_cors_headers(dict(resp.headers), test_origin)
        except Exception:
            # Fall back to headers already in context
            return self.evaluate_cors_headers(context.get("headers", {}), test_origin)
