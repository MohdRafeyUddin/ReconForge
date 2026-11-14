"""
Run History API Router
======================
Endpoints to list, inspect, retrieve assets, and compare historical scan runs.
"""

from typing import Any, Dict, List, Optional
from fastapi import APIRouter, HTTPException, Query
from bson import ObjectId

from app.database import get_database
from app.models import serialize_doc
from app.services.run_history import compare_runs, read_raw_tool_output

router = APIRouter(prefix="/projects", tags=["Run History"])


@router.get("/{project_id}/runs")
async def get_project_runs(
    project_id: str,
    page: int = Query(1, ge=1),
    limit: int = Query(20, ge=1, le=100),
):
    """Returns paginated list of historical scan runs for a project."""
    db = get_database()
    if db is None:
        raise HTTPException(status_code=500, detail="Database unavailable")

    query = {"project_id": str(project_id)}
    total = await db.scan_runs.count_documents(query)

    skip = (page - 1) * limit
    cursor = db.scan_runs.find(query).sort("started_at", -1).skip(skip).limit(limit)
    runs = await cursor.to_list(length=limit)

    return {
        "items": [serialize_doc(r) for r in runs],
        "total": total,
        "page": page,
        "limit": limit,
    }


@router.get("/{project_id}/runs/compare")
async def compare_project_runs(
    project_id: str,
    a: str = Query(..., description="Job ID of first run"),
    b: str = Query(..., description="Job ID of second run"),
):
    """Compares two historical scan runs and returns added/removed assets per type."""
    db = get_database()
    if db is None:
        raise HTTPException(status_code=500, detail="Database unavailable")

    try:
        comparison = await compare_runs(db, project_id, a, b)
        return serialize_doc(comparison)
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.get("/{project_id}/runs/{job_id}")
async def get_run_details(
    project_id: str,
    job_id: str,
):
    """Returns details, phase counts, and configuration snapshot for a specific run."""
    db = get_database()
    if db is None:
        raise HTTPException(status_code=500, detail="Database unavailable")

    run_doc = await db.scan_runs.find_one({
        "job_id": str(job_id),
        "project_id": str(project_id),
    })
    if not run_doc:
        # Fallback to jobs collection if run history has not been written yet
        job_doc = await db.jobs.find_one({"_id": ObjectId(job_id) if ObjectId.is_valid(job_id) else job_id})
        if not job_doc:
            raise HTTPException(status_code=404, detail="Run not found")
        return serialize_doc(job_doc)

    return serialize_doc(run_doc)


@router.get("/{project_id}/runs/{job_id}/assets")
async def get_run_assets(
    project_id: str,
    job_id: str,
    type: Optional[str] = Query(None, description="Filter by asset type"),
    page: int = Query(1, ge=1),
    limit: int = Query(50, ge=1, le=500),
):
    """Returns paginated assets observed during a specific scan run."""
    db = get_database()
    if db is None:
        raise HTTPException(status_code=500, detail="Database unavailable")

    query: Dict[str, Any] = {
        "project_id": str(project_id),
        "job_id": str(job_id),
    }
    if type:
        query["type"] = type

    total = await db.run_assets.count_documents(query)
    skip = (page - 1) * limit

    cursor = db.run_assets.find(query).sort("recorded_at", 1).skip(skip).limit(limit)
    items = await cursor.to_list(length=limit)

    return {
        "items": [serialize_doc(i) for i in items],
        "total": total,
        "page": page,
        "limit": limit,
    }


@router.get("/{project_id}/runs/{job_id}/raw/{tool_name}")
async def get_raw_tool_output_endpoint(
    project_id: str,
    job_id: str,
    tool_name: str,
):
    """Returns decompressed raw stdout/stderr for a tool in plain text with traversal protection."""
    try:
        content = read_raw_tool_output(project_id, job_id, tool_name)
        if content is None:
            raise HTTPException(status_code=404, detail=f"No raw output found for tool {tool_name}")
        return {
            "project_id": project_id,
            "job_id": job_id,
            "tool": tool_name,
            "output": content,
        }
    except ValueError as ve:
        raise HTTPException(status_code=400, detail=str(ve))

