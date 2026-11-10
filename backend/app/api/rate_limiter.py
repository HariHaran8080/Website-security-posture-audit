import time
from collections import defaultdict
from fastapi import Request, HTTPException, status

class InMemoryRateLimiter:
    """
    Sliding-window rate limiter for sensitive endpoints.
    Protects against denial-of-service, API abuse, and automated flooding.
    """
    def __init__(self, requests_per_minute: int = 15):
        self.rpm = requests_per_minute
        self.window = 60.0  # seconds
        self.client_requests = defaultdict(list)

    def is_allowed(self, client_id: str) -> tuple[bool, int]:
        now = time.time()
        timestamps = self.client_requests[client_id]

        # Evict timestamps older than 60 seconds
        cutoff = now - self.window
        self.client_requests[client_id] = [t for t in timestamps if t > cutoff]

        if len(self.client_requests[client_id]) < self.rpm:
            self.client_requests[client_id].append(now)
            remaining = self.rpm - len(self.client_requests[client_id])
            return True, remaining
        else:
            oldest = self.client_requests[client_id][0]
            retry_after = int(self.window - (now - oldest)) + 1
            return False, retry_after

scan_rate_limiter = InMemoryRateLimiter(requests_per_minute=15)

def check_scan_rate_limit(request: Request):
    """FastAPI dependency to rate-limit scans."""
    client_ip = request.client.host if request.client else "unknown"
    allowed, retry_after = scan_rate_limiter.is_allowed(client_ip)

    if not allowed:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Rate limit exceeded. Maximum 15 scans per minute allowed. Try again in {retry_after} seconds.",
            headers={"Retry-After": str(retry_after)}
        )

