from __future__ import annotations

from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from vulnscout.api.router import api_router
from vulnscout.api.ws import router as ws_router
from vulnscout.models.db import init_db


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan: init DB on startup."""
    init_db()
    yield


app = FastAPI(
    title="VulnScout API",
    description="AI Vulnerability Code Audit Assistant",
    version="0.1.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# API routes
app.include_router(api_router)
app.include_router(ws_router)


@app.get("/health")
async def health():
    return {"status": "ok", "version": "0.1.0"}


# Serve built frontend as SPA (catch-all for non-API routes)
frontend_dist = Path(__file__).resolve().parent.parent / "frontend" / "dist"
if frontend_dist.exists():
    app.mount("/assets", StaticFiles(directory=str(frontend_dist / "assets")), name="frontend_assets")

    @app.get("/{full_path:path}")
    async def serve_frontend(full_path: str):
        # Don't catch API or WebSocket paths
        if full_path.startswith("api/") or full_path.startswith("ws/") or full_path == "health":
            from fastapi.responses import JSONResponse
            return JSONResponse({"detail": "Not Found"}, status_code=404)
        file_path = frontend_dist / full_path
        if file_path.exists() and file_path.is_file():
            return FileResponse(str(file_path))
        return FileResponse(str(frontend_dist / "index.html"))
