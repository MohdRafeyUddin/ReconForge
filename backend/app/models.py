from datetime import datetime
from bson import ObjectId
from pydantic import BaseModel, Field, EmailStr
from typing import Optional, List, Dict, Any

from app.core.scan_options import default_phase_switches

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
            "last_run": None,
            "next_run": None,
        }
    )
    # Stage 1 — per-phase switches, all default OFF. Legacy projects without
    # this field are treated as all-OFF by normalize_phase_switches().
    phase_switches: Optional[Dict[str, Any]] = Field(default_factory=default_phase_switches)
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

    # Phase 8 — JS analysis, secrets, cloud buckets, OAST, Nuclei, tech routing
    js_analysis: Optional[Dict[str, Any]] = Field(
        default_factory=lambda: {
            "enabled": True,
            "max_files_fast": 25,
            "max_files_deep": 100,
            "max_file_kb": 500,
            "timeout_seconds": 15,
            "sourcemaps_deep_only": True,
            "sourcemap_max_files": 10,
        }
    )
    secrets_scan: Optional[Dict[str, Any]] = Field(
        default_factory=lambda: {"enabled": True, "max_files": 500, "timeout_seconds": 180}
    )
    cloud_enum: Optional[Dict[str, Any]] = Field(
        default_factory=lambda: {"enabled": False, "max_keywords": 10, "timeout_seconds": 180}
    )
    oast: Optional[Dict[str, Any]] = Field(
        default_factory=lambda: {"enabled": False, "server": "", "token": "", "startup_timeout_seconds": 20}
    )
    nuclei_options: Optional[Dict[str, Any]] = Field(
        default_factory=lambda: {"auto_scan": False, "update_templates": False, "custom_templates_dir": ""}
    )
    tech_routing: Optional[Dict[str, Any]] = Field(
        default_factory=lambda: {"enabled": True, "max_hosts_per_tech": 25}
    )
    nmap_options: Optional[Dict[str, Any]] = Field(
        default_factory=lambda: {
            "enabled": True,
            "scan_modes": ["deep"],
            "max_hosts": 25,
            "concurrency": 5,
            "timeout_seconds": 15,
            "version_light": True,
            "priority": "interesting",
        }
    )
    ffuf_options: Optional[Dict[str, Any]] = Field(
        default_factory=lambda: {
            "enabled": True,
            "concurrency": 3,
            "rate_strategy": "split",
        }
    )
    screenshot_options: Optional[Dict[str, Any]] = Field(
        default_factory=lambda: {
            "per_url_timeout_seconds": 60,
            "concurrency": 3,
            "max_urls": 50,
            "max_urls_per_host": 5,
        }
    )

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
    phase_switches: Optional[Dict[str, Any]] = None
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
    js_analysis: Optional[Dict[str, Any]] = None
    secrets_scan: Optional[Dict[str, Any]] = None
    cloud_enum: Optional[Dict[str, Any]] = None
    oast: Optional[Dict[str, Any]] = None
    nuclei_options: Optional[Dict[str, Any]] = None
    tech_routing: Optional[Dict[str, Any]] = None
    nmap_options: Optional[Dict[str, Any]] = None
    ffuf_options: Optional[Dict[str, Any]] = None
    screenshot_options: Optional[Dict[str, Any]] = None

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
    # Stage 1 additive fields (old jobs simply omit them)
    scan_mode: Optional[str] = None
    job_kind: Optional[str] = None
    targeted: Optional[Dict[str, Any]] = None
    executed_phases: Optional[List[str]] = None
    skipped_phases: Optional[List[Dict[str, Any]]] = None
    phase_durations: Optional[List[Dict[str, Any]]] = None

    class Config:
        from_attributes = True
