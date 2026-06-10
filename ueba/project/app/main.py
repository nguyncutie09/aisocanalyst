"""
UEBA - User & Entity Behavior Analytics System.
FastAPI application entry point.

Usage:
    uvicorn app.main:app --host 0.0.0.0 --port 8000
    python -m app.main
"""

import os
import sys
import logging
from pathlib import Path

# Ensure project root is in path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from contextlib import asynccontextmanager

from app.config import settings
from app.api.routes import router as api_router, init_models

# ─── Logging ───
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifecycle: startup and shutdown."""
    # Startup
    logger.info("=" * 60)
    logger.info(f"  {settings.APP_NAME} v{settings.APP_VERSION}")
    logger.info("=" * 60)

    # Create data directories
    os.makedirs(settings.DATA_DIR, exist_ok=True)
    os.makedirs(settings.MODEL_DIR, exist_ok=True)
    os.makedirs(settings.RAW_LOG_DIR, exist_ok=True)
    os.makedirs(settings.PROCESSED_DIR, exist_ok=True)

    # Initialize models
    init_models()

    logger.info(f"Server starting on http://{settings.HOST}:{settings.PORT}")
    yield

    # Shutdown
    logger.info("Shutting down UEBA system...")


app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
)

# ─── Mount static files and templates ───
base_dir = Path(__file__).parent
templates = Jinja2Templates(directory=str(base_dir / "dashboard" / "templates"))

# Serve static files
static_dir = base_dir / "dashboard" / "static"
if static_dir.exists():
    app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")

# ─── API Router ───
app.include_router(api_router)


# ─── Web Dashboard Routes ───

@app.get("/", include_in_schema=False)
async def root():
    return RedirectResponse(url="/dashboard")


@app.get("/dashboard", include_in_schema=False)
async def dashboard_page(request: Request):
    return templates.TemplateResponse(request, "dashboard.html")


@app.get("/alerts", include_in_schema=False)
async def alerts_page(request: Request):
    return templates.TemplateResponse(request, "alerts.html")


@app.get("/analytics", include_in_schema=False)
async def analytics_page(request: Request):
    return templates.TemplateResponse(request, "analytics.html")


@app.get("/mitre", include_in_schema=False)
async def mitre_page(request: Request):
    return templates.TemplateResponse(request, "mitre_heatmap.html")


@app.get("/settings", include_in_schema=False)
async def settings_page(request: Request):
    return templates.TemplateResponse(request, "settings.html")


# ─── Entry point ───

if __name__ == "__main__":
    uvicorn.run(
        "app.main:app",
        host=settings.HOST,
        port=settings.PORT,
        reload=settings.DEBUG,
        log_level="info",
    )
