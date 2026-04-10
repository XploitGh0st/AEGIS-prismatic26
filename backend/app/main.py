"""
AEGIS Main — FastAPI application entry point.
"""

from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.router import api_router
from app.core.config import get_settings
from app.core.database import init_db, close_db
from app.core.logging import setup_logging
from app.core.redis import close_redis

settings = get_settings()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup and shutdown lifecycle."""
    setup_logging()

    # Startup: initialize database tables
    await init_db()

    yield

    # Shutdown: close connections
    await close_db()
    await close_redis()


app = FastAPI(
    title="AEGIS — Cybersecurity Incident Triage API",
    description=(
        "AEGIS ingests raw security alerts from SIEM, EDR, IDS, and Cowrie honeypot sources. "
        "It normalizes, correlates, scores, classifies, and generates AI-powered investigation "
        "summaries — turning alert noise into explainable incidents."
    ),
    version="0.1.0",
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
)

# CORS — allow frontend and demo access
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        settings.frontend_url,
        "http://localhost:5173",
        "http://localhost:3000",
        "http://127.0.0.1:5173",
        "*",  # Permissive for hackathon demo
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount API routes
app.include_router(api_router)


@app.get("/", tags=["root"])
async def root():
    """Root endpoint."""
    return {
        "service": settings.app_name,
        "version": "0.1.0",
        "docs": "/docs",
        "health": "/api/v1/health",
    }
