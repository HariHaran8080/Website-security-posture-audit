import asyncio
from typing import Any
from urllib.parse import urlparse
import httpx

from app.scanner.exceptions import UnauthorizedScanError
from app.scanner.rules import ALL_RULES, BaseRule, Finding
from app.scanner.scoring import calculate_posture_score
from app.scanner.security import validate_and_sanitize_url
from app.config import settings

class SecurityScannerEngine:
    """
    Website Security Posture Auditor Engine.
    Executes modular checks:
      - Security Headers
      - TLS / SSL Handshake & Expiry
      - Cookie Flags (Secure, HttpOnly, SameSite)
      - Exposed Files & Sensitive Paths
      - CORS Misconfiguration
      - Port Scanner (Top 20 ports)
    Strictly refuses execution if has_permission is False.
    """

    def __init__(self, rules: list[BaseRule] | None = None):
        self.rules = ALL_RULES if rules is None else rules

    async def scan(self, target_url: str, has_permission: bool) -> dict[str, Any]:
        # --- Mandatory Consent Check ---
        if not has_permission:
            raise UnauthorizedScanError(
                target_url=target_url,
                message="CONSENT REFUSED: Explicit permission or ownership confirmation is strictly required to audit target."
            )

        # --- SSRF and URL Security Sanitization ---
        sanitized_url = validate_and_sanitize_url(target_url, allow_local=settings.ALLOW_LOCAL_SCANS)

        # Initial context gathering
        context = await self._gather_context(sanitized_url, has_permission)

        # Run all modular rules concurrently
        async def _safe_eval(rule: BaseRule) -> list[Finding]:
            try:
                return await rule.evaluate(sanitized_url, context)
            except Exception:
                return []

        results = await asyncio.gather(*[_safe_eval(r) for r in self.rules])
        all_findings: list[Finding] = [f for sublist in results for f in sublist]

        # Score calculations and OWASP aggregations
        score_data = calculate_posture_score(all_findings)

        return {
            "target_url": target_url,
            "grade": score_data["grade"],
            "numerical_score": score_data["score"],
            "total_issues": score_data["total_issues"],
            "severity_summary": score_data["severity_summary"],
            "owasp_summary": score_data["owasp_summary"],
            "top_fixes": score_data["top_fixes"],
            "consent_acknowledged": True,
            "findings": [f.model_dump() for f in all_findings]
        }

    async def _gather_context(self, target_url: str, has_permission: bool) -> dict[str, Any]:
        parsed = urlparse(target_url)
        context: dict[str, Any] = {
            "target_url": target_url,
            "has_permission": has_permission,
            "hostname": parsed.hostname or target_url,
            "headers": {},
            "raw_cookie_headers": [],
            "status_code": 0
        }

        try:
            async with httpx.AsyncClient(timeout=6.0, follow_redirects=True, verify=False) as client:
                resp = await client.get(target_url)
                context["status_code"] = resp.status_code
                context["headers"] = dict(resp.headers)
                # Extract Set-Cookie headers
                context["raw_cookie_headers"] = resp.headers.get_list("set-cookie")
        except Exception:
            pass

        return context
