"""
Diffs Router
============
API endpoints to retrieve scan diffs and continuous monitoring history.
"""

from typing import List, Optional
from fastapi import APIRouter, HTTPException
from bson import ObjectId

from app.database import get_database
from app.models import serialize_doc

router = APIRouter(prefix="/projects", tags=["Diffs"])


@router.get("/{project_id}/diffs/latest")
async def get_latest_diff(
    project_id: str,
):
    """Returns the most recent scan diff for a project."""
    db = get_database()
    if db is None:
        raise HTTPException(status_code=500, detail="Database offline")

    diff = await db.scan_diffs.find_one(
        {"project_id": project_id},
        sort=[("created_at", -1)]
    )
    if not diff:
        return {"diff": None, "message": "No scan diffs found for this project."}

    return serialize_doc(diff)


@router.get("/{project_id}/diffs")
async def get_project_diffs(
    project_id: str,
    limit: int = 20,
):
    """Returns historical scan diffs for a project."""
    db = get_database()
    if db is None:
        raise HTTPException(status_code=500, detail="Database offline")

    cursor = db.scan_diffs.find(
        {"project_id": project_id}
    ).sort("created_at", -1)

    diffs = await cursor.to_list(limit)
    return [serialize_doc(d) for d in diffs]


@router.get("/{project_id}/diffs/{diff_id}")
async def get_diff_by_id(
    project_id: str,
    diff_id: str,
):
    """Returns a specific diff document."""
    db = get_database()
    if db is None:
        raise HTTPException(status_code=500, detail="Database offline")

    try:
        diff = await db.scan_diffs.find_one({
            "_id": ObjectId(diff_id),
            "project_id": project_id
        })
    except Exception:
        diff = await db.scan_diffs.find_one({
            "_id": diff_id,
            "project_id": project_id
        })

    if not diff:
        raise HTTPException(status_code=404, detail="Scan diff not found")

    return serialize_doc(diff)
