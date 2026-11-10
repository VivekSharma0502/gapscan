from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from redis.exceptions import RedisError
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded

from app.api.dashboard import router as dashboard_router
from app.api.domains import router as domains_router
from app.api.github import router as github_router
from app.api.github_webhook import router as github_webhook_router
from app.api.health import router as health_router
from app.api.repo_links import router as repo_links_router
from app.api.scans import router as scans_router
from app.core.config import settings
from app.core.product import PRODUCT_NAME
from app.core.rate_limit import limiter

app = FastAPI(title=f"{PRODUCT_NAME} API")


def redis_unavailable(_request: Request, _exc: Exception) -> JSONResponse:
    # Security: fails closed. If the limiter can't count a request, the scan doesn't start.
    return JSONResponse(
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        content={"detail": "Scanning is unavailable right now."},
    )


app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
app.add_exception_handler(RedisError, redis_unavailable)

# Security: only the configured frontend origins, and only the methods and headers in use.
# Extend allow_methods/allow_headers when routes need them, not preemptively.
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_methods=["GET", "POST", "DELETE"],
    # Security: sign-in uses this bearer header, not cookies, so allow_credentials stays off
    # and another site can't ride on a visitor's session.
    allow_headers=["Authorization", "Content-Type"],
)

app.include_router(health_router)
app.include_router(scans_router)
app.include_router(domains_router)
app.include_router(dashboard_router)
app.include_router(github_router)
app.include_router(repo_links_router)
app.include_router(github_webhook_router)
