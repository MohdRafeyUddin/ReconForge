from fastapi import APIRouter, HTTPException, Query
from bson import ObjectId
from datetime import datetime
from typing import List, Dict, Any, Optional
import logging

from app.database import get_database
from app.models import AssetResponse, serialize_doc

logger = logging.getLogger("reconforge.assets")
router = APIRouter(prefix="/assets", tags=["Assets"])

UNIFIED_PROVIDERS = ["subfinder", "assetfinder", "amass", "chaos"]


@router.get("/project/{project_id}", response_model=List[AssetResponse])
async def get_project_assets(project_id: str):
    db = get_database()
    if not ObjectId.is_valid(project_id):
        raise HTTPException(status_code=400, detail="Invalid project ID format")

    project = await db.projects.find_one({
        "_id": ObjectId(project_id),
    })
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    cursor = db.assets.find({"project_id": project_id})
    assets = await cursor.to_list(length=1000)
    return serialize_doc(assets)


@router.get("/project/{project_id}/subdomains")
async def get_project_subdomains(project_id: str):
    """Returns all subdomain assets with source attribution and timestamps."""
    db = get_database()
    if not ObjectId.is_valid(project_id):
        raise HTTPException(status_code=400, detail="Invalid project ID format")

    project = await db.projects.find_one({
        "_id": ObjectId(project_id),
    })
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    cursor = db.assets.find({"project_id": project_id, "type": "subdomain"})
    assets = await cursor.to_list(length=2000)
    return serialize_doc(assets)


@router.get("/project/{project_id}/dashboard-stats")
async def get_dashboard_stats(project_id: str):
    db = get_database()
    if not ObjectId.is_valid(project_id):
        raise HTTPException(status_code=400, detail="Invalid project ID format")

    project = await db.projects.find_one({
        "_id": ObjectId(project_id),
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


@router.get("/project/{project_id}/asset/{asset_id}/response-body")
async def get_asset_response_body(
    project_id: str,
    asset_id: str,
):
    """
    Retrieval of stored HTTP response bodies (single-user local mode).
    Guaranteed:
      - Verifies project exists
      - Strict path-traversal prevention via response_storage service
    """
    db = get_database()
    if db is None:
        raise HTTPException(status_code=500, detail="Database connection is not available")
    if not ObjectId.is_valid(project_id) or not ObjectId.is_valid(asset_id):
        raise HTTPException(status_code=400, detail="Invalid ID format")

    project = await db.projects.find_one({
        "_id": ObjectId(project_id),
    })
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    asset = await db.assets.find_one({"_id": ObjectId(asset_id), "project_id": project_id})
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")

    meta = asset.get("metadata") or {}
    rel_path = meta.get("response_body_path") or asset.get("response_body_path")
    if not rel_path:
        raise HTTPException(status_code=404, detail="No response body stored for this asset")

    from app.services.response_storage import read_response_body
    filename = rel_path.split("/")[-1]
    content = read_response_body(project_id, filename)
    if content is None:
        raise HTTPException(status_code=404, detail="Response body file not found on disk")

    return {
        "asset_id": asset_id,
        "domain": asset.get("domain"),
        "status_code": meta.get("status_code"),
        "content_length": meta.get("response_body_size") or len(content),
        "content": content,
    }


@router.get("/project/{project_id}/content-paths")
async def get_project_content_paths(
    project_id: str,
    page: int = 1,
    limit: int = 50,
    host: Optional[str] = None,
    status_code: Optional[int] = None,
    first_seen_after: Optional[str] = None,
    current_user: Optional[Any] = None,
    **kwargs: Any,
):
    """
    Paginated retrieval of discovered content paths.
    Filters: host, status_code, first_seen_after.
    Returns: value, host, status_code, content_length, words, lines, redirect_location,
             calibration_used, first_seen, last_seen.
    """
    db = get_database()
    if db is None:
        raise HTTPException(status_code=500, detail="Database connection is not available")
    if not ObjectId.is_valid(project_id):
        raise HTTPException(status_code=400, detail="Invalid project ID format")

    project = await db.projects.find_one({
        "_id": ObjectId(project_id),
    })
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    query: Dict[str, Any] = {
        "project_id": project_id,
        "type": "content_path",
    }

    and_conditions: List[Dict[str, Any]] = []

    if host:
        host_clean = host.strip()
        and_conditions.append({
            "$or": [
                {"domain": host_clean},
                {"metadata.host": host_clean},
            ]
        })

    if status_code is not None:
        and_conditions.append({
            "$or": [
                {"status_code": status_code},
                {"metadata.status_code": status_code},
            ]
        })

    if first_seen_after:
        try:
            dt = datetime.fromisoformat(first_seen_after.replace("Z", "+00:00"))
            if dt.tzinfo is not None:
                dt_naive = dt.replace(tzinfo=None)
            else:
                dt_naive = dt
            and_conditions.append({"first_seen": {"$gte": dt_naive}})
        except Exception as pe:
            logger.debug("[content_paths] Failed to parse first_seen_after date '%s': %s", first_seen_after, pe)

    if and_conditions:
        query["$and"] = and_conditions

    total = await db.assets.count_documents(query)
    safe_page = max(1, page)
    safe_limit = max(1, min(limit, 500))
    skip = (safe_page - 1) * safe_limit

    cursor = db.assets.find(query).sort([("first_seen", -1), ("_id", -1)]).skip(skip).limit(safe_limit)
    docs = await cursor.to_list(length=safe_limit)

    items = []
    for d in docs:
        meta = d.get("metadata") or {}
        first_s = d.get("first_seen")
        last_s = d.get("last_seen")
        items.append({
            "value": d.get("value") or meta.get("url") or d.get("domain"),
            "host": d.get("domain") or meta.get("host") or "",
            "status_code": d.get("status_code") or meta.get("status_code"),
            "content_length": meta.get("content_length", 0),
            "words": meta.get("words", 0),
            "lines": meta.get("lines", 0),
            "redirect_location": meta.get("redirect_location", ""),
            "calibration_used": meta.get("calibration_used", True),
            "first_seen": first_s.isoformat() if isinstance(first_s, datetime) else (str(first_s) if first_s else None),
            "last_seen": last_s.isoformat() if isinstance(last_s, datetime) else (str(last_s) if last_s else None),
        })

    return {
        "items": items,
        "total": total,
        "page": safe_page,
        "limit": safe_limit,
    }

