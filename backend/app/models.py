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
    target_type: Optional[str] = "DOMAIN"
    scope: Optional[Dict[str, List[str]]] = Field(default_factory=lambda: {"in_scope": [], "out_of_scope": []})
    rate_limits: Optional[Dict[str, Any]] = Field(
        default_factory=lambda: {
            "global_rps": 10,
            "per_tool": {
                "httpx": 20,
                "katana": 10,
                "nuclei": 10,
                "naabu": 300,
            },
        }
    )
    custom_headers: Optional[Dict[str, str]] = Field(default_factory=dict)
    schedule: Optional[Dict[str, Any]] = Field(
        default_factory=lambda: {
            "enabled": False,
            "interval_hours": 24,
            "scan_mode": "fast",
            "last_run": None,
            "next_run": None,
        }
    )
    alerts: Optional[Dict[str, Any]] = Field(
        default_factory=lambda: {
            "enabled": False,
            "discord_webhook_url": "",
            "telegram_bot_token": "",
            "telegram_chat_id": "",
            "min_priority": "medium",
            "events": {
                "new_subdomains": True,
                "new_live_hosts": True,
                "new_ports": True,
                "new_findings": True,
                "scan_completed": True,
            },
        }
    )
    clustering: Optional[Dict[str, Any]] = Field(
        default_factory=lambda: {
            "scan_all_cluster_members": False,
        }
    )
    port_range: Optional[str] = "1-10000"
    response_body_max_kb: Optional[int] = 500
    wordlists: Optional[Dict[str, str]] = None
    per_host_url_cap: Optional[int] = None
    scan_profile: Optional[str] = "recon"
    assume_tools_installed: Optional[bool] = True
    enable_root_expansion: Optional[bool] = False
    max_permutations: Optional[int] = 50000

class ProjectCreate(ProjectBase):
    pass

class ProjectUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    seed_domains: Optional[List[str]] = None
    target_type: Optional[str] = None
    scope: Optional[Dict[str, List[str]]] = None
    rate_limits: Optional[Dict[str, Any]] = None
    custom_headers: Optional[Dict[str, str]] = None
    schedule: Optional[Dict[str, Any]] = None
    alerts: Optional[Dict[str, Any]] = None
    clustering: Optional[Dict[str, Any]] = None
    port_range: Optional[str] = None
    response_body_max_kb: Optional[int] = None
    wordlists: Optional[Dict[str, str]] = None
    per_host_url_cap: Optional[int] = None
    scan_profile: Optional[str] = None
    assume_tools_installed: Optional[bool] = None
    enable_root_expansion: Optional[bool] = None
    max_permutations: Optional[int] = None

class ProjectResponse(ProjectBase):
    id: str
    owner_id: str
    created_at: datetime

    class Config:
        from_attributes = True

class AssetBase(BaseModel):
    domain: str
    type: str  # domain, subdomain, ip, service, content_path, api_spec, graphql_endpoint, param
    status: str  # live, dead, inactive, unknown
    value: Optional[str] = None
    status_class: Optional[str] = None
    is_interesting: Optional[bool] = False
    interesting_reason: Optional[str] = None
    liveness_version: Optional[int] = 2
    cdn_waf: Optional[Dict[str, Any]] = None
    cluster_id: Optional[str] = None
    cluster_role: Optional[str] = None
    is_cluster_representative: Optional[bool] = None
    cluster_size: Optional[int] = None
    cluster_representative_host: Optional[str] = None
    cluster_skip_reason: Optional[str] = None
    services: Optional[List[Dict[str, Any]]] = None
    open_ports: List[int] = []
    metadata: Dict[str, Any] = {}
    project_id: str
    discovered_by: str
    sources: List[str] = []
    risk: Optional[Dict[str, Any]] = None
    risk_history: Optional[List[Dict[str, Any]]] = None
    hunt_priority: Optional[int] = None
    hunt_reasons: Optional[List[str]] = None

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
