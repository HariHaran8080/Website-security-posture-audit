class ScannerException(Exception):
    """Base exception for scanner operations."""
    pass

class UnauthorizedScanError(ScannerException):
    """
    Raised when an audit is initiated without explicit permission / consent confirmation.
    Scanning third-party infrastructure without authorization is strictly prohibited.
    """
    def __init__(
        self,
        target_url: str,
        message: str = "Scan refused: Explicit permission/ownership confirmation is required before scanning."
    ):
        self.target_url = target_url
        self.message = f"{message} (Target: {target_url})"
        super().__init__(self.message)

class TargetUnreachableError(ScannerException):
    """Raised when the target URL fails DNS resolution or connection establishment."""
    pass
