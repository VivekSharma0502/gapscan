from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.health import router as health_router
from app.core.config import settings

app = FastAPI(title="ScanKit API")

# Security: only the configured frontend origins, and only the methods in use.
# Extend allow_methods/allow_headers when routes need them, not preemptively.
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_methods=["GET"],
)

app.include_router(health_router)
