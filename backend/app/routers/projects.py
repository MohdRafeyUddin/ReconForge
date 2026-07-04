from datetime import datetime
from fastapi import APIRouter, HTTPException, Depends, status
from bson import ObjectId
from typing import List
from app.database import get_database
from app.auth import get_current_user
from app.models import ProjectCreate, ProjectResponse, serialize_doc
from app.providers.unified_discovery_provider import detect_target_type

router = APIRouter(prefix="/projects", tags=["Projects"])

@router.post("", response_model=ProjectResponse)
async def create_project(project_in: ProjectCreate, current_user: dict = Depends(get_current_user)):
    db = get_database()
    
    # Resolve target_type from seed domains
    seed = project_in.seed_domains[0] if project_in.seed_domains else ""
    detected_type = detect_target_type(seed)
    
    project_dict = {
        "name": project_in.name,
        "description": project_in.description,
        "seed_domains": project_in.seed_domains,
        "target_type": detected_type,
        "owner_id": str(current_user["_id"]),
        "created_at": datetime.utcnow()
    }
    
    result = await db.projects.insert_one(project_dict)
    project_dict["_id"] = result.inserted_id
    return serialize_doc(project_dict)

@router.get("", response_model=List[ProjectResponse])
async def get_projects(current_user: dict = Depends(get_current_user)):
    db = get_database()
    cursor = db.projects.find({"owner_id": str(current_user["_id"])})
    projects = await cursor.to_list(length=100)
    return serialize_doc(projects)

@router.get("/{project_id}", response_model=ProjectResponse)
async def get_project(project_id: str, current_user: dict = Depends(get_current_user)):
    db = get_database()
    if not ObjectId.is_valid(project_id):
        raise HTTPException(status_code=400, detail="Invalid project ID format")
        
    project = await db.projects.find_one({
        "_id": ObjectId(project_id),
        "owner_id": str(current_user["_id"])
    })
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    return serialize_doc(project)

@router.delete("/{project_id}")
async def delete_project(project_id: str, current_user: dict = Depends(get_current_user)):
    db = get_database()
    if not ObjectId.is_valid(project_id):
        raise HTTPException(status_code=400, detail="Invalid project ID format")
        
    # Verify ownership
    project = await db.projects.find_one({
        "_id": ObjectId(project_id),
        "owner_id": str(current_user["_id"])
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
async def get_project_risk_scores(project_id: str, current_user: dict = Depends(get_current_user)):
    db = get_database()
    if not ObjectId.is_valid(project_id):
        raise HTTPException(status_code=400, detail="Invalid project ID format")
        
    project = await db.projects.find_one({
        "_id": ObjectId(project_id),
        "owner_id": str(current_user["_id"])
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
async def force_recalculate_risk_scores(project_id: str, current_user: dict = Depends(get_current_user)):
    db = get_database()
    if not ObjectId.is_valid(project_id):
        raise HTTPException(status_code=400, detail="Invalid project ID format")
        
    project = await db.projects.find_one({
        "_id": ObjectId(project_id),
        "owner_id": str(current_user["_id"])
    })
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
        
    from app.services.risk_scoring import recalculate_all_scores
    scores = await recalculate_all_scores(project_id)
    return serialize_doc(scores)
