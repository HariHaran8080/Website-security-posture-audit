from contextlib import asynccontextmanager
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware

from app.config import settings
from app.database import init_db
from app.api.routes import router as api_router
from app.scanner.exceptions import ScannerException
from app.scanner.security import SSRFSecurityError, InvalidTargetURLError

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: Ensure SQLite tables exist
    await init_db()
    yield

app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.PROJECT_VERSION,
    description="Automated Website Security Posture Auditor evaluating HTTP headers, TLS, cookies, and DNS.",
    lifespan=lifespan
)

# 1. Security Headers Middleware (Defensive HTTP configuration for the auditor API itself)
@app.middleware("http")
async def add_security_headers_middleware(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return response

# 2. CORS setup for React frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)

# 3. Secure Error Handlers (Prevents stack trace / system path leakage)
@app.exception_handler(SSRFSecurityError)
async def ssrf_security_exception_handler(request: Request, exc: SSRFSecurityError):
    return JSONResponse(
        status_code=400,
        content={"detail": str(exc), "type": "SSRF_SECURITY_BLOCKED"}
    )

@app.exception_handler(InvalidTargetURLError)
async def invalid_url_exception_handler(request: Request, exc: InvalidTargetURLError):
    return JSONResponse(
        status_code=400,
        content={"detail": str(exc), "type": "INVALID_TARGET_URL"}
    )

app.include_router(api_router, prefix=settings.API_V1_PREFIX)

@app.get("/health", tags=["Health"])
async def health_check():
    return {
        "status": "healthy",
        "service": settings.PROJECT_NAME,
        "version": settings.PROJECT_VERSION
    }
