from datetime import datetime
from fastapi import APIRouter, HTTPException, Depends, status
from bson import ObjectId
from typing import List
from app.database import get_database
from app.auth import get_current_user
from app.models import ProjectCreate, ProjectResponse, serialize_doc

router = APIRouter(prefix="/projects", tags=["Projects"])

@router.post("", response_model=ProjectResponse)
async def create_project(project_in: ProjectCreate, current_user: dict = Depends(get_current_user)):
    db = get_database()
    project_dict = {
        "name": project_in.name,
        "description": project_in.description,
        "seed_domains": project_in.seed_domains,
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
