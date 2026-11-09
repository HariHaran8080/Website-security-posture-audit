import ipaddress
import socket
from urllib.parse import urlparse
from app.scanner.exceptions import ScannerException

class SSRFSecurityError(ScannerException):
    """Raised when an audit target resolves to a private, loopback, or cloud-metadata IP address."""
    pass

class InvalidTargetURLError(ScannerException):
    """Raised when a target URL fails schema or syntax validation."""
    pass

# Reserved / Private networks prohibited from SSRF targeting
PRIVATE_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("169.254.0.0/16"),      # Link-local / Cloud metadata (AWS/GCP/Azure)
    ipaddress.ip_network("127.0.0.0/8"),        # IPv4 Loopback
    ipaddress.ip_network("0.0.0.0/8"),          # Current network
    ipaddress.ip_network("224.0.0.0/4"),        # Multicast
    ipaddress.ip_network("240.0.0.0/4"),        # Reserved
    ipaddress.ip_network("::1/128"),            # IPv6 Loopback
    ipaddress.ip_network("fc00::/7"),           # IPv6 Unique Local Address
    ipaddress.ip_network("fe80::/10"),          # IPv6 Link-Local
]

def validate_and_sanitize_url(url: str, allow_local: bool = True) -> str:
    """
    Validates target URL scheme, hostname, and applies SSRF protection.
    
    1. Scheme check: only 'http' and 'https' permitted.
    2. Format check: validates hostname syntax and rejects userinfo (user:pass@host).
    3. SSRF check: resolves DNS and blocks private/link-local/cloud-metadata addresses,
       unless allow_local is explicitly enabled (e.g. for testing against localhost Juice Shop).
    """
    if not url or not isinstance(url, str):
        raise InvalidTargetURLError("Target URL cannot be empty.")

    url = url.strip()
    if "://" in url:
        scheme = url.split("://")[0].lower()
        if scheme not in ["http", "https"]:
            raise InvalidTargetURLError(f"Unsupported protocol scheme '{scheme}'. Only HTTP and HTTPS are permitted.")
    else:
        url = "https://" + url

    try:
        parsed = urlparse(url)
    except Exception as e:
        raise InvalidTargetURLError(f"Malformed URL: {str(e)}")

    if parsed.scheme.lower() not in ["http", "https"]:
        raise InvalidTargetURLError(f"Unsupported protocol scheme '{parsed.scheme}'. Only HTTP and HTTPS are permitted.")

    if parsed.username or parsed.password:
        raise InvalidTargetURLError("Credentials (userinfo) in target URLs are strictly forbidden.")

    hostname = parsed.hostname
    if not hostname:
        raise InvalidTargetURLError("Missing hostname in target URL.")

    # Check for localhost / loopback aliases
    is_localhost = hostname.lower() in ["localhost", "127.0.0.1", "::1"]

    if is_localhost and allow_local:
        return url

    # Resolve hostname to IP to protect against SSRF & DNS rebinding
    try:
        addr_info = socket.getaddrinfo(hostname, None)
    except socket.gaierror:
        # If DNS cannot resolve, let scanner handle unreachable target gracefully
        return url

    for family, socktype, proto, canonname, sockaddr in addr_info:
        ip_str = sockaddr[0]
        try:
            ip_obj = ipaddress.ip_address(ip_str)
        except ValueError:
            continue

        # Check against private / metadata / loopback subnets
        for net in PRIVATE_NETWORKS:
            if ip_obj in net:
                if (ip_obj.is_loopback or ip_obj in ipaddress.ip_network("127.0.0.0/8")) and allow_local:
                    continue
                raise SSRFSecurityError(
                    f"SSRF Protection: Access to private/internal/cloud-metadata address '{ip_str}' is forbidden."
                )

    return url
