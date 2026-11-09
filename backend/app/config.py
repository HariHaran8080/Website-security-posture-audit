from pydantic_settings import BaseSettings, SettingsConfigDict
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    PROJECT_NAME: str = "WASP - Website Security Posture Auditor"
    PROJECT_VERSION: str = "0.1.0"
    API_V1_PREFIX: str = "/api/v1"
    DATABASE_URL: str = f"sqlite+aiosqlite:///{BASE_DIR}/auditor.db"
    
    # CORS Origins
    ALLOWED_ORIGINS: list[str] = [
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:3000",
        "http://127.0.0.1:3000"
    ]

    # Security Controls
    ALLOW_LOCAL_SCANS: bool = True  # Allows localhost / 127.0.0.1 for local dev/testing
    RATE_LIMIT_PER_MINUTE: int = 15
    MAX_SCAN_TIMEOUT_SECONDS: int = 20

settings = Settings()
