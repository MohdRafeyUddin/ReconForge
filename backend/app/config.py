import os
from pathlib import Path
from typing import List, Set
from dotenv import load_dotenv

# Load from backend/.env and root .env
_backend_env = Path(__file__).resolve().parent.parent / ".env"
if _backend_env.is_file():
    load_dotenv(dotenv_path=_backend_env)
load_dotenv()

class Settings:
    PROJECT_NAME: str = "ReconForge"
    API_V1_STR: str = "/api/v1"
    
    # MongoDB Config
    MONGODB_URL: str = os.getenv("MONGODB_URL", "mongodb://127.0.0.1:27017")
    DATABASE_NAME: str = os.getenv("DATABASE_NAME", "reconforge")
    
    # Tool detection / scan configuration
    ASSUME_TOOLS_INSTALLED: bool = os.getenv("ASSUME_TOOLS_INSTALLED", "true").lower() in ("true", "1", "yes")

    # ProjectDiscovery / Chaos API Key
    PDCP_API_KEY: str = os.getenv("PDCP_API_KEY", "")
    CHAOS_KEY: str = os.getenv("CHAOS_KEY", "")

    # Network exposure & security config (single-user local mode)
    # Default allowed origins: http://localhost:5173 and http://127.0.0.1:5173 only
    @property
    def ALLOWED_ORIGINS(self) -> List[str]:
        env_origins = os.getenv("ALLOWED_ORIGINS", "").strip()
        if env_origins:
            return [o.strip() for o in env_origins.split(",") if o.strip()]
        return ["http://localhost:5173", "http://127.0.0.1:5173"]

    # Allowed Host headers for DNS-rebinding prevention (excluding port)
    @property
    def ALLOWED_HOSTS(self) -> Set[str]:
        base_hosts = {"localhost", "127.0.0.1", "::1", "[::1]", "testserver", "test"}
        env_hosts = os.getenv("ALLOWED_HOSTS", "").strip()
        if env_hosts:
            for h in env_hosts.split(","):
                if h.strip():
                    base_hosts.add(h.strip().lower())
        return base_hosts

settings = Settings()
