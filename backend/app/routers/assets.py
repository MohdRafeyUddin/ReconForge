from fastapi import APIRouter, HTTPException, Depends
from bson import ObjectId
from typing import List, Dict, Any
from app.database import get_database
from app.auth import get_current_user
from app.models import AssetResponse, serialize_doc

router = APIRouter(prefix="/assets", tags=["Assets"])

UNIFIED_PROVIDERS = ["subfinder", "assetfinder", "amass", "chaos"]


@router.get("/project/{project_id}", response_model=List[AssetResponse])
async def get_project_assets(project_id: str, current_user: dict = Depends(get_current_user)):
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
    assets = await cursor.to_list(length=1000)
    return serialize_doc(assets)


@router.get("/project/{project_id}/subdomains")
async def get_project_subdomains(project_id: str, current_user: dict = Depends(get_current_user)):
    """Returns all subdomain assets with source attribution and timestamps."""
    db = get_database()
    if not ObjectId.is_valid(project_id):
        raise HTTPException(status_code=400, detail="Invalid project ID format")

    project = await db.projects.find_one({
        "_id": ObjectId(project_id),
        "owner_id": str(current_user["_id"])
    })
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    cursor = db.assets.find({"project_id": project_id, "type": "subdomain"})
    assets = await cursor.to_list(length=2000)
    return serialize_doc(assets)


@router.get("/project/{project_id}/dashboard-stats")
async def get_dashboard_stats(project_id: str, current_user: dict = Depends(get_current_user)):
    db = get_database()
    if not ObjectId.is_valid(project_id):
        raise HTTPException(status_code=400, detail="Invalid project ID format")

    project = await db.projects.find_one({
        "_id": ObjectId(project_id),
        "owner_id": str(current_user["_id"])
    })
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    total_assets = await db.assets.count_documents({"project_id": project_id})
    subdomains_count = await db.assets.count_documents({
        "project_id": project_id,
        "type": "subdomain"
    })
    live_hosts = await db.assets.count_documents({
        "project_id": project_id,
        "status": "live"
    })

    pipeline = [
        {"$match": {"project_id": project_id}},
        {"$unwind": "$open_ports"},
        {"$group": {"_id": "$open_ports", "count": {"$sum": 1}}},
        {"$sort": {"count": -1}}
    ]
    ports_cursor = db.assets.aggregate(pipeline)
    ports_distribution = await ports_cursor.to_list(length=50)
    total_open_ports = len(ports_distribution)

    last_job = await db.jobs.find_one(
        {"project_id": project_id, "status": "completed"},
        sort=[("finished_at", -1)]
    )
    last_scan_time = (
        last_job["finished_at"].isoformat()
        if last_job and last_job.get("finished_at")
        else None
    )

    # Per-provider breakdown by discovered_by field
    source_pipeline = [
        {"$match": {"project_id": project_id}},
        {"$group": {"_id": "$discovered_by", "count": {"$sum": 1}}}
    ]
    sources_cursor = db.assets.aggregate(source_pipeline)
    sources_distribution = await sources_cursor.to_list(length=20)
    sources_data = [{"name": item["_id"], "value": item["count"]} for item in sources_distribution]

    # Per-tool counts from sources array (set by Unified Discovery)
    all_assets_cursor = db.assets.find({"project_id": project_id})
    all_assets = await all_assets_cursor.to_list(length=5000)
    provider_counts: Dict[str, int] = {
        tool: sum(1 for a in all_assets if tool in a.get("sources", []))
        for tool in UNIFIED_PROVIDERS
    }

    return {
        "total_assets": total_assets,
        "total_subdomains": subdomains_count,
        "live_hosts": live_hosts,
        "open_ports_count": total_open_ports,
        "last_scan_time": last_scan_time,
        "ports_distribution": [{"port": item["_id"], "count": item["count"]} for item in ports_distribution],
        "sources_distribution": sources_data,
        "provider_counts": provider_counts,
    }
