import asyncio
from typing import Any
from urllib.parse import urljoin
import httpx

from app.scanner.rules.base import BaseRule, Finding
from app.scanner.constants import Severity, FindingStatus, OWASP

USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 (WASP Security Posture Auditor)"

class ExposedFilesRule(BaseRule):
    category = "Exposed Files & Sensitive Paths"
    rule_id = "RULE_EXPOSED_FILES"

    SENSITIVE_PATHS = [
        {
            "path": "/.git/HEAD",
            "name": "Git Repository Metadata",
            "severity": Severity.CRITICAL,
            "signature": "ref: refs/",
            "abuse": "Attackers can reconstruct the full source code repository, review commit history, and find hidden hardcoded secrets.",
            "fix": "Block HTTP access to `/.git` in your web server config: `location ~ /\\.git { deny all; }`",
            "owasp": OWASP.A05_SECURITY_MISCONFIGURATION.value,
            "penalty": -25
        },
        {
            "path": "/.env",
            "name": "Environment Variables Configuration",
            "severity": Severity.CRITICAL,
            "signature": "=",
            "abuse": "Exposes database passwords, cloud secret keys, JWT secrets, and third-party API credentials, leading to total server compromise.",
            "fix": "Store `.env` outside the public web root (`public_html`/`www`) and configure web server rules to deny access to dotfiles.",
            "owasp": OWASP.A05_SECURITY_MISCONFIGURATION.value,
            "penalty": -25
        },
        {
            "path": "/backup.zip",
            "name": "Archived Backup File",
            "severity": Severity.HIGH,
            "signature": None,
            "abuse": "Allows unauthenticated users to download full application archives, database dumps, and configuration backups.",
            "fix": "Never store `.zip`, `.tar.gz`, or `.bak` files inside public document directories.",
            "owasp": OWASP.A05_SECURITY_MISCONFIGURATION.value,
            "penalty": -15
        },
        {
            "path": "/phpinfo.php",
            "name": "PHP Diagnostic Info (phpinfo)",
            "severity": Severity.HIGH,
            "signature": "PHP Version",
            "abuse": "Discloses operating system details, PHP module versions, compile flags, and server environment variables to facilitate targeted exploits.",
            "fix": "Remove diagnostic `phpinfo.php` scripts from production environments immediately.",
            "owasp": OWASP.A05_SECURITY_MISCONFIGURATION.value,
            "penalty": -15
        },
        {
            "path": "/admin",
            "name": "Publicly Exposed Admin Portal",
            "severity": Severity.LOW,
            "signature": None,
            "abuse": "Exposes an administrative login portal to internet-wide brute force attacks, credential stuffing, and password spraying.",
            "fix": "Restrict `/admin` paths via IP whitelisting, VPN gateway, or multi-factor authentication (MFA).",
            "owasp": OWASP.A01_BROKEN_ACCESS_CONTROL.value,
            "penalty": -5
        },
        {
            "path": "/robots.txt",
            "name": "Robots.txt Directive File",
            "severity": Severity.INFO,
            "signature": "User-agent",
            "abuse": "Disallowed entries in robots.txt often advertise sensitive administrative directories or hidden staging endpoints to attackers.",
            "fix": "Review `robots.txt` to avoid listing sensitive internal paths; protect sensitive endpoints with proper authentication rather than security through obscurity.",
            "owasp": OWASP.A05_SECURITY_MISCONFIGURATION.value,
            "penalty": 0
        }
    ]

    async def _check_path(self, client: httpx.AsyncClient, base_url: str, item: dict[str, Any]) -> Finding | None:
        target_path = item["path"]
        full_url = urljoin(base_url, target_path)

        try:
            async with client.stream("GET", full_url) as resp:
                status_code = resp.status_code
                content_type = resp.headers.get("content-type", "").lower()

                raw_bytes = b""
                async for chunk in resp.aiter_bytes():
                    raw_bytes += chunk
                    if len(raw_bytes) >= 2048:
                        break

                text_snippet = raw_bytes[:1000].decode("utf-8", errors="ignore")

                is_exposed = False
                if status_code == 200:
                    sig = item["signature"]
                    if sig:
                        if sig in text_snippet:
                            is_exposed = True
                    else:
                        if "zip" in target_path:
                            if "zip" in content_type or raw_bytes.startswith(b"PK"):
                                is_exposed = True
                        elif target_path == "/admin":
                            is_exposed = True

            if is_exposed:
                if target_path == "/robots.txt":
                    return Finding(
                        id="EXPOSED_ROBOTS_TXT",
                        category=self.category,
                        title="robots.txt File Detected",
                        status=FindingStatus.INFO,
                        severity=Severity.INFO,
                        details=f"Accessible robots.txt found at {full_url}",
                        attacker_abuse=item["abuse"],
                        fix=item["fix"],
                        owasp_category=item["owasp"],
                        score_impact=0
                    )
                else:
                    return Finding(
                        id=f"EXPOSED_{target_path.replace('/', '_').replace('.', '_').upper()}",
                        category=self.category,
                        title=f"Exposed Sensitive Resource: {item['name']}",
                        status=FindingStatus.FAIL,
                        severity=item["severity"],
                        details=f"Potentially sensitive path `{target_path}` responded with HTTP 200 OK at {full_url}",
                        attacker_abuse=item["abuse"],
                        fix=item["fix"],
                        owasp_category=item["owasp"],
                        score_impact=item["penalty"]
                    )
            else:
                if target_path != "/robots.txt":
                    return Finding(
                        id=f"SAFE_{target_path.replace('/', '_').replace('.', '_').upper()}",
                        category=self.category,
                        title=f"Protected: {item['name']}",
                        status=FindingStatus.PASS,
                        severity=Severity.INFO,
                        details=f"Path `{target_path}` is properly blocked or not found (Status: {status_code}).",
                        attacker_abuse="None. The path is protected or absent.",
                        fix="Continue enforcing strict access control.",
                        owasp_category=item["owasp"],
                        score_impact=0
                    )
        except Exception:
            pass

        return None

    async def evaluate(self, target_url: str, context: dict[str, Any]) -> list[Finding]:
        base_url = target_url.rstrip("/")

        headers = {"User-Agent": USER_AGENT}
        async with httpx.AsyncClient(timeout=2.5, follow_redirects=False, verify=False, headers=headers) as client:
            tasks = [self._check_path(client, base_url, item) for item in self.SENSITIVE_PATHS]
            results = await asyncio.gather(*tasks, return_exceptions=True)

        findings: list[Finding] = []
        for res in results:
            if isinstance(res, Finding):
                findings.append(res)

        return findings
