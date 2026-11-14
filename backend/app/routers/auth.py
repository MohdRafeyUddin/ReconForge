print("ROUTER AUTH LOADED")

from datetime import datetime
from typing import Optional
from fastapi import APIRouter
from pydantic import BaseModel
from app.auth import LOCAL_USER

router = APIRouter(prefix="/auth", tags=["Authentication"])

class RegisterPayload(BaseModel):
    username: Optional[str] = "local"
    email: Optional[str] = "local@reconforge.local"
    password: Optional[str] = ""

@router.post("/register")
async def register(payload: Optional[RegisterPayload] = None):
    return {
        "id": "local",
        "username": payload.username if payload and payload.username else "local",
        "email": payload.email if payload and payload.email else "local@reconforge.local",
        "created_at": datetime(2026, 1, 1, 0, 0, 0).isoformat()
    }

@router.post("/login")
async def login():
    return {
        "access_token": "local-token", 
        "token_type": "bearer",
        "user": {
            "id": "local",
            "username": "local",
            "email": "local@reconforge.local"
        }
    }

@router.get("/me")
async def get_me():
    return {
        "id": LOCAL_USER["id"],
        "username": LOCAL_USER["username"],
        "email": LOCAL_USER["email"],
        "created_at": LOCAL_USER["created_at"].isoformat()
    }
