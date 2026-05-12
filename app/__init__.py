"""
RedSurface Web Application — FastAPI App Factory
"""
import os
from pathlib import Path
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from app.database import init_db

APP_DIR = Path(__file__).parent
TEMPLATES_DIR = APP_DIR / "templates"
STATIC_DIR = APP_DIR / "static"


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Initialize resources on startup, cleanup on shutdown."""
    # Initialize database
    await init_db()

    # Load plugins
    from plugins import registry
    registry.discover_plugins()

    yield
    # Shutdown cleanup (if needed)


def create_app() -> FastAPI:
    """Create and configure the FastAPI application."""
    app = FastAPI(
        title="RedSurface",
        description="Attack Surface Intelligence Platform",
        version="2.0.0",
        lifespan=lifespan,
    )

    # Mount static files
    if STATIC_DIR.exists():
        app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

    # Register API routes
    from app.api import scans, modules, settings
    app.include_router(scans.router, prefix="/api")
    app.include_router(modules.router, prefix="/api")
    app.include_router(settings.router, prefix="/api")

    # Register page routes (Jinja2 rendered)
    from app.views import pages
    app.include_router(pages.router)

    return app
