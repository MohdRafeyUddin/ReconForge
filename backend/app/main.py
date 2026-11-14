import logging
import os
from contextlib import asynccontextmanager
from fastapi import FastAPI, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from app.config import settings
from app.database import connect_to_mongo, close_mongo_connection, get_database
from app.routers import auth, projects, assets, jobs, reports, iot, system, diffs, runs
from app.services.scheduler import scheduler, recover_stuck_jobs
from app.services.migration import run_asset_backfill_migration

# Setup Logger
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("reconforge.main")


def check_startup_dependencies() -> None:
    """Verifies that all core external dependencies are available and importable."""
    required = [
        ("fastapi", "fastapi"),
        ("uvicorn", "uvicorn"),
        ("motor", "motor"),
        ("pymongo", "pymongo"),
        ("passlib", "passlib"),
        ("jose", "python-jose"),
        ("pydantic", "pydantic"),
        ("dotenv", "python-dotenv"),
        ("aiohttp", "aiohttp"),
        ("httpx", "httpx"),
        ("websockets", "websockets"),
    ]
    missing = []
    for mod, pkg in required:
        try:
            __import__(mod)
        except ImportError as err:
            missing.append(f"{pkg} (module: {mod}, error: {err})")
    if missing:
        msg = f"[FATAL] Missing required packages from requirements.txt: {', '.join(missing)}"
        logger.critical(msg)
        raise RuntimeError(msg)


# Enforce startup import check
check_startup_dependencies()

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Connect to database on startup
    await connect_to_mongo()
    db = get_database()
    if db is not None:
        try:
            # 1. Backfill migration (idempotent, runnable on startup or via script)
            await run_asset_backfill_migration(db)
        except Exception as mig_err:
            logger.error(f"[main] Asset backfill migration failed on startup: {mig_err}")
            
        try:
            # 2. Startup recovery: mark jobs stuck in running with no live process as interrupted
            await recover_stuck_jobs(db)
        except Exception as rec_err:
            logger.error(f"[main] Startup job recovery failed: {rec_err}")

    # Start in-process scan scheduler
    scheduler.start()
    yield
    # Stop scheduler and close connection on shutdown
    await scheduler.stop()
    await close_mongo_connection()

app = FastAPI(
    title=settings.PROJECT_NAME,
    version="1.0.0",
    description="Attack Surface Discovery & Asset Management Platform",
    lifespan=lifespan
)

class SecurityGuardMiddleware:
    """
    DNS-rebinding protection and Origin enforcement for single-user local mode.
    - Validates Host header against settings.ALLOWED_HOSTS.
    - Enforces Origin header on state-changing HTTP requests and WebSocket connections.
    """
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] in ("http", "websocket"):
            headers = dict(scope.get("headers", []))

            # 1. Host header validation (DNS-rebinding prevention)
            host_raw = headers.get(b"host", b"").decode("latin1").strip()
            if host_raw:
                if ":" in host_raw and not host_raw.startswith("["):
                    clean_host = host_raw.split(":")[0].lower()
                elif host_raw.startswith("[") and "]" in host_raw:
                    clean_host = host_raw.split("]")[0].lower() + "]"
                else:
                    clean_host = host_raw.lower()

                if clean_host not in settings.ALLOWED_HOSTS:
                    if scope["type"] == "http":
                        response = Response("Invalid Host header (DNS-rebinding protection)", status_code=400)
                        await response(scope, receive, send)
                        return
                    else:
                        await send({"type": "websocket.close", "code": 4403})
                        return

            # 2. Origin validation for state-changing HTTP requests
            if scope["type"] == "http":
                method = scope.get("method", "").upper()
                if method in ("POST", "PUT", "DELETE", "PATCH"):
                    origin_raw = headers.get(b"origin", b"").decode("latin1").strip()
                    if origin_raw and origin_raw not in settings.ALLOWED_ORIGINS:
                        response = Response("Forbidden Origin", status_code=403)
                        await response(scope, receive, send)
                        return

            # 3. Origin validation for WebSocket connections
            if scope["type"] == "websocket":
                origin_raw = headers.get(b"origin", b"").decode("latin1").strip()
                if origin_raw and origin_raw not in settings.ALLOWED_ORIGINS:
                    await send({"type": "websocket.close", "code": 4403})
                    return

        await self.app(scope, receive, send)


app.add_middleware(SecurityGuardMiddleware)

# Enable CORS for React frontend (strictly restricted in single-user local mode)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount screenshots statically
os.makedirs("screenshots", exist_ok=True)
app.mount("/screenshots", StaticFiles(directory="screenshots"), name="screenshots")

# Mount API Routers
app.include_router(auth.router, prefix=settings.API_V1_STR)
app.include_router(projects.router, prefix=settings.API_V1_STR)
app.include_router(assets.router, prefix=settings.API_V1_STR)
app.include_router(jobs.router, prefix=settings.API_V1_STR)
app.include_router(reports.router, prefix=settings.API_V1_STR)
app.include_router(iot.router, prefix=settings.API_V1_STR)
app.include_router(system.router, prefix=settings.API_V1_STR)
app.include_router(diffs.router, prefix=settings.API_V1_STR)
app.include_router(runs.router, prefix=settings.API_V1_STR)

@app.get("/")
def read_root():
    from app.database import db_helper
    is_mock = getattr(db_helper, "is_mock", False)
    return {
        "status": "online",
        "service": settings.PROJECT_NAME,
        "message": "ReconForge ASM platform API is running.",
        "in_memory_db": is_mock,
        "db_type": "in_memory" if is_mock else "mongodb",
        "warning": "Running on in-memory DB, data will be lost" if is_mock else None,
    }
