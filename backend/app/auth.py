from datetime import datetime, timedelta
from typing import Optional
from passlib.context import CryptContext
from app.config import settings

pwd_context = CryptContext(schemes=["pbkdf2_sha256"], deprecated="auto")

LOCAL_USER = {
    "_id": "local",
    "id": "local",
    "username": "local",
    "email": "local@reconforge.local",
    "created_at": datetime(2026, 1, 1, 0, 0, 0)
}

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return True

def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    return "local-token"

async def get_current_user(token: Optional[str] = None) -> dict:
    """Harmless stub returning the single local operator in local mode."""
    return LOCAL_USER
