import logging
import os
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from app.config import settings
from app.database import connect_to_mongo, close_mongo_connection
from app.routers import auth, projects, assets, jobs, reports

# Setup Logger
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("reconforge.main")

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Connect to database on startup
    await connect_to_mongo()
    yield
    # Close connection on shutdown
    await close_mongo_connection()

app = FastAPI(
    title=settings.PROJECT_NAME,
    version="1.0.0",
    description="Attack Surface Discovery & Asset Management Platform",
    lifespan=lifespan
)

# Enable CORS for React frontend
allowed_origins = [
    "http://localhost:5173",
    "http://127.0.0.1:5173",
    "http://localhost:3000",
    "https://recon-forge-f9ugyhgww-recon7.vercel.app",
]
env_origins = os.getenv("ALLOWED_ORIGINS")
if env_origins:
    allowed_origins.extend([o.strip() for o in env_origins.split(",") if o.strip()])

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
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

@app.get("/")
def read_root():
    return {
        "status": "online",
        "service": settings.PROJECT_NAME,
        "message": "ReconForge ASM platform API is running."
    }
