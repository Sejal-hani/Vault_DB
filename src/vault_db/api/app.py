"""
FastAPI Application Configuration and Lifecycle
"""

from contextlib import asynccontextmanager
from pathlib import Path
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse

from config.settings import settings
from src.vault_db.api.routes import router, get_engine
import src.vault_db.api.routes as routes_module


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: initialize engine
    engine = get_engine()
    routes_module.engine = engine
    yield
    # Shutdown: clean up connection pools and sessions
    if routes_module.engine:
        routes_module.engine.close()


def create_app() -> FastAPI:
    app = FastAPI(
        title=settings.PROJECT_NAME,
        version=settings.VERSION,
        description=settings.DESCRIPTION,
        lifespan=lifespan,
    )

    # CORS configuration
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Include API router
    app.include_router(router)

    # Static files and root UI
    base_dir = Path(__file__).resolve().parent.parent.parent.parent
    static_dir = base_dir / "static"
    templates_dir = base_dir / "templates"

    if static_dir.exists():
        app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")

    @app.get("/", include_in_schema=False)
    @app.get("/index.html", include_in_schema=False)
    async def serve_ui():
        index_file = templates_dir / "index.html"
        if not index_file.exists():
            # Fallback to root index.html if present
            index_file = base_dir / "index.html"
        return FileResponse(index_file)

    return app


app = create_app()
