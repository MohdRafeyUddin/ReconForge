from datetime import datetime
from bson import ObjectId
from pydantic import BaseModel, Field, EmailStr
from typing import Optional, List, Dict, Any

def serialize_doc(doc: Any) -> Any:
    """Recursively serializes MongoDB documents (like converting ObjectId to str)."""
    if doc is None:
        return None
    if isinstance(doc, list):
        return [serialize_doc(item) for item in doc]
    if isinstance(doc, dict):
        new_doc = {}
        for k, v in doc.items():
            if k == "_id":
                new_doc["id"] = str(v)
            else:
                new_doc[k] = serialize_doc(v)
        return new_doc
    if isinstance(doc, ObjectId):
        return str(doc)
    if isinstance(doc, datetime):
        return doc.isoformat()
    return doc

# Pydantic models for request validation and response mapping
class UserBase(BaseModel):
    username: str
    email: EmailStr

class UserCreate(UserBase):
    password: str

class UserResponse(UserBase):
    id: str
    created_at: datetime

    class Config:
        from_attributes = True

class ProjectBase(BaseModel):
    name: str
    description: Optional[str] = ""
    seed_domains: List[str] = []

class ProjectCreate(ProjectBase):
    pass

class ProjectResponse(ProjectBase):
    id: str
    owner_id: str
    created_at: datetime

    class Config:
        from_attributes = True

class AssetBase(BaseModel):
    domain: str
    type: str  # domain, subdomain, ip, service
    status: str  # live, inactive, unknown
    open_ports: List[int] = []
    metadata: Dict[str, Any] = {}
    project_id: str
    discovered_by: str
    sources: List[str] = []

class AssetResponse(AssetBase):
    id: str
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None

    class Config:
        from_attributes = True

class JobBase(BaseModel):
    project_id: str
    provider_name: str
    status: str  # pending, running, completed, failed
    logs: List[str] = []

class JobResponse(JobBase):
    id: str
    started_at: datetime
    finished_at: Optional[datetime] = None

    class Config:
        from_attributes = True
