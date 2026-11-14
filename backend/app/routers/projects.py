from datetime import datetime
from fastapi import APIRouter, HTTPException, status
from bson import ObjectId
from typing import List, Any
from app.database import get_database
from app.models import ProjectCreate, ProjectUpdate, ProjectResponse, serialize_doc
from app.providers.unified_discovery_provider import detect_target_type

router = APIRouter(prefix="/projects", tags=["Projects"])

def mask_project_secrets(doc: Any) -> Any:
    """Masks secret notification credentials (Discord webhook and Telegram bot token/chat_id)."""
    if not doc:
        return doc
    if isinstance(doc, list):
        return [mask_project_secrets(d) for d in doc]
    if not isinstance(doc, dict):
        return doc

    doc_copy = dict(doc)
    alerts = doc_copy.get("alerts")
    if isinstance(alerts, dict):
        masked_alerts = dict(alerts)
        for key in ("discord_webhook_url", "telegram_bot_token", "telegram_chat_id"):
            val = str(masked_alerts.get(key) or "").strip()
            if val:
                if key == "discord_webhook_url" and "discord.com/api/webhooks" in val:
                    masked_alerts[key] = "https://discord.com/api/webhooks/********"
                else:
                    masked_alerts[key] = "********"
        doc_copy["alerts"] = masked_alerts
    return doc_copy


def is_masked_placeholder(val: Any) -> bool:
    """Detects whether a secret value is a masked placeholder returned by the API."""
    if not val or not isinstance(val, str):
        return False
    return "****" in val or val.strip() == "********"


def validate_schedule_scope(scope_dict: Any, schedule_dict: Any):
    """Refuses to enable recurring schedule when scope is not configured."""
    if schedule_dict and schedule_dict.get("enabled"):
        in_scope = (scope_dict or {}).get("in_scope") or []
        valid_in_scope = [s for s in in_scope if isinstance(s, str) and s.strip()]
        if not valid_in_scope:
            raise HTTPException(
                status_code=400,
                detail="Cannot enable recurring schedule without configured in-scope targets. Please define at least one in-scope rule."
            )


@router.post("", response_model=ProjectResponse)
async def create_project(project_in: ProjectCreate):
    db = get_database()
    
    # Scope validation for recurring schedule
    validate_schedule_scope(project_in.scope, project_in.schedule)

    # Resolve target_type from seed domains
    seed = project_in.seed_domains[0] if project_in.seed_domains else ""
    detected_type = detect_target_type(seed)
    
    project_dict = {
        "name": project_in.name,
        "description": project_in.description,
        "seed_domains": project_in.seed_domains,
        "target_type": detected_type,
        "scope": project_in.scope or {"in_scope": [], "out_of_scope": []},
        "rate_limits": project_in.rate_limits or {
            "global_rps": 10,
            "per_tool": {
                "httpx": 20,
                "katana": 10,
                "nuclei": 10,
                "naabu": 300,
            },
        },
        "custom_headers": project_in.custom_headers or {},
        "schedule": project_in.schedule or {
            "enabled": False,
            "interval_hours": 24,
            "scan_mode": "fast",
            "last_run": None,
            "next_run": None,
        },
        "alerts": project_in.alerts or {
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
        },
        "clustering": project_in.clustering or {
            "scan_all_cluster_members": False,
        },
        "port_range": project_in.port_range or "1-10000",
        "response_body_max_kb": project_in.response_body_max_kb or 500,
        "scan_profile": project_in.scan_profile or "recon",
        "enable_root_expansion": bool(project_in.enable_root_expansion),
        "max_permutations": project_in.max_permutations or 50000,
        "owner_id": "local",
        "created_at": datetime.utcnow()
    }
    
    result = await db.projects.insert_one(project_dict)
    project_dict["_id"] = result.inserted_id
    return serialize_doc(mask_project_secrets(project_dict))

@router.put("/{project_id}", response_model=ProjectResponse)
async def update_project(
    project_id: str,
    project_update: ProjectUpdate,
):
    db = get_database()
    if not ObjectId.is_valid(project_id):
        raise HTTPException(status_code=400, detail="Invalid project ID format")
        
    project = await db.projects.find_one({
        "_id": ObjectId(project_id),
    })
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    update_dict = {k: v for k, v in project_update.dict(exclude_unset=True).items() if v is not None}
    
    # Validate recurring schedule requirement
    merged_scope = update_dict.get("scope", project.get("scope"))
    merged_schedule = update_dict.get("schedule", project.get("schedule"))
    validate_schedule_scope(merged_scope, merged_schedule)

    # Preserve unmasked credentials when masked placeholder is submitted
    if "alerts" in update_dict and isinstance(update_dict["alerts"], dict):
        existing_alerts = project.get("alerts") or {}
        incoming_alerts = update_dict["alerts"]
        for key in ("discord_webhook_url", "telegram_bot_token", "telegram_chat_id"):
            if key in incoming_alerts:
                val = incoming_alerts[key]
                if is_masked_placeholder(val):
                    incoming_alerts[key] = existing_alerts.get(key, "")

    if "seed_domains" in update_dict and update_dict["seed_domains"]:
        seed = update_dict["seed_domains"][0]
        update_dict["target_type"] = detect_target_type(seed)

    if update_dict:
        update_dict["updated_at"] = datetime.utcnow()
        await db.projects.update_one(
            {"_id": ObjectId(project_id)},
            {"$set": update_dict}
        )

    updated = await db.projects.find_one({"_id": ObjectId(project_id)})
    return serialize_doc(mask_project_secrets(updated))

@router.get("", response_model=List[ProjectResponse])
async def get_projects():
    db = get_database()
    cursor = db.projects.find({})
    projects = await cursor.to_list(length=100)
    return serialize_doc(mask_project_secrets(projects))

@router.get("/{project_id}", response_model=ProjectResponse)
async def get_project(project_id: str):
    db = get_database()
    if not ObjectId.is_valid(project_id):
        raise HTTPException(status_code=400, detail="Invalid project ID format")
        
    project = await db.projects.find_one({
        "_id": ObjectId(project_id),
    })
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    return serialize_doc(mask_project_secrets(project))

@router.delete("/{project_id}")
async def delete_project(project_id: str):
    db = get_database()
    if not ObjectId.is_valid(project_id):
        raise HTTPException(status_code=400, detail="Invalid project ID format")
        
    project = await db.projects.find_one({
        "_id": ObjectId(project_id),
    })
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
        
    # Delete project
    await db.projects.delete_one({"_id": ObjectId(project_id)})
    # Clean up associated assets and jobs
    await db.assets.delete_many({"project_id": project_id})
    await db.jobs.delete_many({"project_id": project_id})
    
    return {"message": "Project and all associated data deleted successfully"}

@router.get("/{project_id}/risk-scores")
async def get_project_risk_scores(project_id: str):
    db = get_database()
    if not ObjectId.is_valid(project_id):
        raise HTTPException(status_code=400, detail="Invalid project ID format")
        
    project = await db.projects.find_one({
        "_id": ObjectId(project_id),
    })
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
        
    cursor = db.assets.find({"project_id": project_id})
    all_assets = await cursor.to_list(length=100000)
    hosts = [a for a in all_assets if a.get("type") in ("subdomain", "domain", "ip", "service")]
    
    stale_or_missing = False
    cached_scores = []
    
    # Check if there are no hosts
    if not hosts:
        return []
        
    now = datetime.utcnow()
    
    for h in hosts:
        risk = h.get("risk")
        if not risk:
            stale_or_missing = True
            break
        updated_at = risk.get("updated_at")
        if isinstance(updated_at, str):
            try:
                # Remove Z or parse timezone offset
                clean_time = updated_at.replace("Z", "")
                if "+" in clean_time:
                    clean_time = clean_time.split("+")[0]
                updated_at = datetime.fromisoformat(clean_time)
            except Exception:
                pass
        if not isinstance(updated_at, datetime) or (now - updated_at).total_seconds() > 3600:
            stale_or_missing = True
            break
            
        cached_scores.append({
            "asset": h.get("domain"),
            "score": risk.get("score"),
            "level": risk.get("level"),
            "reasons": risk.get("reasons"),
            "exposure_factors": risk.get("exposure_factors"),
            "recommended_priority": risk.get("recommended_priority"),
            "importance_score": risk.get("importance_score"),
            "exposure_score": risk.get("exposure_score"),
            "updated_at": updated_at
        })
        
    if stale_or_missing or not cached_scores:
        from app.services.risk_scoring import recalculate_all_scores
        scores = await recalculate_all_scores(project_id)
        return serialize_doc(scores)
        
    return serialize_doc(cached_scores)

@router.post("/{project_id}/risk-scores/recalculate")
async def force_recalculate_risk_scores(project_id: str):
    db = get_database()
    if not ObjectId.is_valid(project_id):
        raise HTTPException(status_code=400, detail="Invalid project ID format")
        
    project = await db.projects.find_one({
        "_id": ObjectId(project_id),
    })
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
        
    from app.services.risk_scoring import recalculate_all_scores
    scores = await recalculate_all_scores(project_id)
    return serialize_doc(scores)


@router.get("/{project_id}/suggested-roots")
async def get_suggested_roots(project_id: str):
    """Returns all root domain suggestions discovered by ASNMap/DNSx/Amass."""
    db = get_database()
    if not ObjectId.is_valid(project_id):
        raise HTTPException(status_code=400, detail="Invalid project ID format")

    cursor = db.assets.find({"project_id": project_id, "type": "suggested_root"}).sort([("created_at", -1)])
    items = await cursor.to_list(length=500)
    return serialize_doc(items)


@router.post("/{project_id}/suggested-roots/{domain}/approve")
async def approve_suggested_root(project_id: str, domain: str):
    """
    Approves a suggested root domain.
    Explicitly adds the domain to project seeds and in_scope list.
    Marks suggestion as approved. Never scans automatically.
    """
    db = get_database()
    if not ObjectId.is_valid(project_id):
        raise HTTPException(status_code=400, detail="Invalid project ID format")

    project = await db.projects.find_one({"_id": ObjectId(project_id)})
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    clean_dom = domain.strip().lower()
    seeds = list(project.get("seed_domains") or [])
    if clean_dom not in seeds:
        seeds.append(clean_dom)

    scope = dict(project.get("scope") or {"in_scope": [], "out_of_scope": []})
    in_scope = list(scope.get("in_scope") or [])
    if clean_dom not in in_scope:
        in_scope.append(clean_dom)
    scope["in_scope"] = in_scope

    await db.projects.update_one(
        {"_id": ObjectId(project_id)},
        {"$set": {"seed_domains": seeds, "scope": scope, "updated_at": datetime.utcnow()}}
    )

    await db.assets.update_many(
        {"project_id": project_id, "type": "suggested_root", "domain": clean_dom},
        {"$set": {"status": "approved", "updated_at": datetime.utcnow()}}
    )

    return {
        "status": "approved",
        "domain": clean_dom,
        "message": f"Domain {clean_dom} approved and added to scope and seeds.",
    }


@router.post("/{project_id}/suggested-roots/{domain}/reject")
async def reject_suggested_root(project_id: str, domain: str):
    """Rejects a suggested root domain."""
    db = get_database()
    if not ObjectId.is_valid(project_id):
        raise HTTPException(status_code=400, detail="Invalid project ID format")

    clean_dom = domain.strip().lower()
    await db.assets.update_many(
        {"project_id": project_id, "type": "suggested_root", "domain": clean_dom},
        {"$set": {"status": "rejected", "updated_at": datetime.utcnow()}}
    )

    return {
        "status": "rejected",
        "domain": clean_dom,
    }

