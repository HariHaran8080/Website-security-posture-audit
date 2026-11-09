from app.database import get_db
from app.scanner.engine import SecurityScannerEngine

def get_scanner() -> SecurityScannerEngine:
    """Dependency provider for the SecurityScannerEngine instance."""
    return SecurityScannerEngine()
