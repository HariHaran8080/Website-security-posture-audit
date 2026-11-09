import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse
from typing import Any

from app.scanner.rules.base import BaseRule, Finding
from app.scanner.constants import Severity, FindingStatus, OWASP
from app.scanner.exceptions import UnauthorizedScanError

COMMON_PORTS = {
    21: {"service": "FTP", "risk": Severity.HIGH, "desc": "File Transfer Protocol (Cleartext)"},
    22: {"service": "SSH", "risk": Severity.LOW, "desc": "Secure Shell Remote Administration"},
    23: {"service": "Telnet", "risk": Severity.CRITICAL, "desc": "Telnet Remote Shell (Insecure Cleartext)"},
    25: {"service": "SMTP", "risk": Severity.MEDIUM, "desc": "Simple Mail Transfer Protocol"},
    53: {"service": "DNS", "risk": Severity.LOW, "desc": "Domain Name System"},
    80: {"service": "HTTP", "risk": Severity.INFO, "desc": "World Wide Web HTTP"},
    110: {"service": "POP3", "risk": Severity.MEDIUM, "desc": "Post Office Protocol (Cleartext)"},
    143: {"service": "IMAP", "risk": Severity.MEDIUM, "desc": "Internet Message Access Protocol"},
    443: {"service": "HTTPS", "risk": Severity.INFO, "desc": "Encrypted Web HTTPS"},
    445: {"service": "SMB", "risk": Severity.CRITICAL, "desc": "Server Message Block (Ransomware / Worm Vector)"},
    1433: {"service": "MSSQL", "risk": Severity.CRITICAL, "desc": "Microsoft SQL Server Database"},
    1521: {"service": "Oracle", "risk": Severity.CRITICAL, "desc": "Oracle Database Listener"},
    3306: {"service": "MySQL", "risk": Severity.CRITICAL, "desc": "MySQL / MariaDB Database"},
    3389: {"service": "RDP", "risk": Severity.HIGH, "desc": "Remote Desktop Protocol"},
    5432: {"service": "PostgreSQL", "risk": Severity.CRITICAL, "desc": "PostgreSQL Database"},
    5900: {"service": "VNC", "risk": Severity.HIGH, "desc": "Virtual Network Computing Remote Desktop"},
    6379: {"service": "Redis", "risk": Severity.CRITICAL, "desc": "Redis In-Memory Key-Value Store"},
    8080: {"service": "HTTP-Alt", "risk": Severity.LOW, "desc": "Alternative HTTP / Proxy Port"},
    8443: {"service": "HTTPS-Alt", "risk": Severity.INFO, "desc": "Alternative HTTPS Port"},
    27017: {"service": "MongoDB", "risk": Severity.CRITICAL, "desc": "MongoDB NoSQL Database"}
}

class PortScannerRule(BaseRule):
    category = "Exposed Network Services & Ports"
    rule_id = "RULE_PORT_SCANNER"

    def __init__(self, max_threads: int = 10, timeout: float = 1.0):
        self.max_threads = max_threads
        self.timeout = timeout

    def probe_port(self, host: str, port: int) -> dict[str, Any] | None:
        """Attempts a TCP connection and banner grab for a single port."""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(self.timeout)
                res = sock.connect_ex((host, port))
                if res == 0:
                    banner = ""
                    try:
                        sock.settimeout(0.6)
                        if port in [80, 8080]:
                            sock.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
                        else:
                            sock.sendall(b"\r\n")
                        raw_data = sock.recv(256)
                        banner = raw_data.decode("utf-8", errors="ignore").strip().splitlines()[0][:100]
                    except Exception:
                        banner = ""

                    return {
                        "port": port,
                        "open": True,
                        "banner": banner
                    }
        except Exception:
            pass
        return None

    def scan_ports(self, host: str, has_permission: bool) -> list[Finding]:
        """
        Scans top ~20 TCP ports.
        STRICT CONSENT CHECK: Refuses execution unless has_permission is True.
        """
        if not has_permission:
            raise UnauthorizedScanError(
                target_url=host,
                message="PORT SCANNER REFUSED: Network socket scanning requires explicit ownership/authorization confirmation."
            )

        findings: list[Finding] = []
        open_ports: list[dict[str, Any]] = []

        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            future_to_port = {
                executor.submit(self.probe_port, host, port): port
                for port in COMMON_PORTS.keys()
            }
            for future in as_completed(future_to_port):
                res = future.result()
                if res and res.get("open"):
                    open_ports.append(res)

        if not open_ports:
            findings.append(Finding(
                id="PORT_ALL_FILTERED",
                category=self.category,
                title="Common Ports Filtered or Closed",
                status=FindingStatus.PASS,
                severity=Severity.INFO,
                details=f"All {len(COMMON_PORTS)} monitored TCP ports were closed or filtered to inbound probes.",
                attacker_abuse="None. Attackers cannot directly reach unsegmented services on these ports.",
                fix="Maintain robust firewall and network security groups.",
                owasp_category=OWASP.A05_SECURITY_MISCONFIGURATION.value,
                score_impact=0
            ))
            return findings

        # Evaluate each open port
        for op in open_ports:
            port_num = op["port"]
            banner = op["banner"]
            meta = COMMON_PORTS.get(port_num, {"service": "Unknown", "risk": Severity.LOW, "desc": "Custom Port"})
            service_name = meta["service"]
            risk = meta["risk"]

            banner_note = f" (Banner: `{banner}`)" if banner else ""

            if risk == Severity.CRITICAL:
                findings.append(Finding(
                    id=f"PORT_{port_num}_EXPOSED_CRITICAL",
                    category=self.category,
                    title=f"Critical Port Exposed: {port_num} ({service_name})",
                    status=FindingStatus.FAIL,
                    severity=Severity.CRITICAL,
                    details=f"High-risk service {service_name} on port {port_num} is exposed to the public internet{banner_note}.",
                    attacker_abuse=(
                        f"Exposed {service_name} services on WAN are targeted by automated exploitation bots, "
                        f"brute-force attacks, and ransomware operators. Direct WAN access to database or internal "
                        f"management protocols bypasses application-tier controls."
                    ),
                    fix=f"Bind {service_name} exclusively to localhost (127.0.0.1) or an internal VPC. Block port {port_num} via firewall / Security Groups.",
                    owasp_category=OWASP.A05_SECURITY_MISCONFIGURATION.value,
                    score_impact=-25
                ))
            elif risk == Severity.HIGH:
                findings.append(Finding(
                    id=f"PORT_{port_num}_EXPOSED_HIGH",
                    category=self.category,
                    title=f"High Risk Service Exposed: {port_num} ({service_name})",
                    status=FindingStatus.FAIL,
                    severity=Severity.HIGH,
                    details=f"Service {service_name} on port {port_num} is open to external probes{banner_note}.",
                    attacker_abuse=f"Attackers can attempt credential brute-forcing, password spraying, or exploit known {service_name} vulnerabilities.",
                    fix=f"Place port {port_num} behind a VPN or bastion host with IP allowlisting and mandatory MFA.",
                    owasp_category=OWASP.A05_SECURITY_MISCONFIGURATION.value,
                    score_impact=-15
                ))
            elif risk == Severity.MEDIUM:
                findings.append(Finding(
                    id=f"PORT_{port_num}_EXPOSED_MEDIUM",
                    category=self.category,
                    title=f"Potentially Insecure Service: {port_num} ({service_name})",
                    status=FindingStatus.WEAK,
                    severity=Severity.MEDIUM,
                    details=f"Port {port_num} ({service_name}) is reachable{banner_note}.",
                    attacker_abuse="May transmit credentials in cleartext or allow service enumeration.",
                    fix=f"Enforce encrypted alternatives (e.g. IMAPS/SMTPS) or restrict inbound access.",
                    owasp_category=OWASP.A02_CRYPTOGRAPHIC_FAILURES.value,
                    score_impact=-8
                ))
            else:
                findings.append(Finding(
                    id=f"PORT_{port_num}_OPEN_STANDARD",
                    category=self.category,
                    title=f"Standard Web Port Open: {port_num} ({service_name})",
                    status=FindingStatus.PASS if port_num in [80, 443] else FindingStatus.INFO,
                    severity=Severity.INFO,
                    details=f"Port {port_num} ({service_name}) is accessible as expected{banner_note}.",
                    attacker_abuse="Standard web traffic; attackers probe web applications hosted on this port.",
                    fix="Ensure web server software is patched to the latest version and unnecessary headers are hidden.",
                    owasp_category=OWASP.A05_SECURITY_MISCONFIGURATION.value,
                    score_impact=0
                ))

        return findings

    async def evaluate(self, target_url: str, context: dict[str, Any]) -> list[Finding]:
        has_permission = context.get("has_permission", False)
        parsed = urlparse(target_url)
        host = parsed.hostname or target_url
        return self.scan_ports(host, has_permission=has_permission)
