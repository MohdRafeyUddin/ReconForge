import asyncio
import logging
from datetime import datetime
from typing import Dict, List, Set, Any
from fastapi import APIRouter, HTTPException, Depends, BackgroundTasks, WebSocket, WebSocketDisconnect
from bson import ObjectId
from app.database import get_database
from app.auth import get_current_user
from app.models import JobResponse, serialize_doc
from app.providers import PROVIDERS

logger = logging.getLogger("reconforge.jobs")
router = APIRouter(prefix="/jobs", tags=["Jobs"])

# In-memory subscription manager for WebSocket log streaming
class ConnectionManager:
    def __init__(self):
        # job_id -> set of active WebSockets
        self.active_connections: Dict[str, Set[WebSocket]] = {}

    async def connect(self, job_id: str, websocket: WebSocket):
        await websocket.accept()
        if job_id not in self.active_connections:
            self.active_connections[job_id] = set()
        self.active_connections[job_id].add(websocket)
        logger.info(f"WS client connected to job {job_id}")

    def disconnect(self, job_id: str, websocket: WebSocket):
        if job_id in self.active_connections:
            self.active_connections[job_id].discard(websocket)
            if not self.active_connections[job_id]:
                del self.active_connections[job_id]
        logger.info(f"WS client disconnected from job {job_id}")

    async def broadcast(self, job_id: str, message: Dict[str, Any]):
        if job_id in self.active_connections:
            websockets = self.active_connections[job_id]
            if websockets:
                # Run parallel sends
                await asyncio.gather(
                    *[ws.send_json(message) for ws in websockets],
                    return_exceptions=True
                )

manager = ConnectionManager()


@router.get("/providers")
async def get_registered_providers(current_user: dict = Depends(get_current_user)):
    return [
        {
            "name": name,
            "description": provider.description
        }
        for name, provider in PROVIDERS.items()
    ]


async def run_discovery_job(job_id: str, project_id: str, provider_name: str, seed_domains: List[str]):
    db = get_database()
    if db is None:
        logger.error("Database is not initialized. Cannot run job.")
        return

    provider = PROVIDERS.get(provider_name)
    if not provider:
        err_msg = f"[-] Provider {provider_name} not found."
        await db.jobs.update_one(
            {"_id": ObjectId(job_id)},
            {"$set": {"status": "failed", "finished_at": datetime.utcnow()}, "$push": {"logs": err_msg}}
        )
        await manager.broadcast(job_id, {"type": "log", "message": err_msg})
        return

    # Update job state to running
    await db.jobs.update_one(
        {"_id": ObjectId(job_id)},
        {"$set": {"status": "running", "started_at": datetime.utcnow()}}
    )
    
    start_msg = f"[+] Starting job {job_id} using {provider_name} for seed domains: {', '.join(seed_domains)}..."
    logger.info(start_msg)
    await db.jobs.update_one({"_id": ObjectId(job_id)}, {"$push": {"logs": start_msg}})
    await manager.broadcast(job_id, {"type": "log", "message": start_msg})

    try:
        # Run plugin generator
        async for event in provider.discover(seed_domains):
            event_type = event.get("type")

            if event_type == "log":
                log_message = event.get("message")
                logger.info(f"[{provider_name}] {log_message}")
                await db.jobs.update_one(
                    {"_id": ObjectId(job_id)},
                    {"$push": {"logs": log_message}}
                )
                await manager.broadcast(job_id, {"type": "log", "message": log_message})
                # Forward provider_stat sub-key for live progress panel
                if event.get("provider_stat"):
                    await manager.broadcast(job_id, {
                        "type": "provider_stat",
                        "provider": event["provider_stat"]["provider"],
                        "count": event["provider_stat"]["count"],
                    })

            elif event_type == "asset":
                asset_data = event.get("data")
                asset_data["project_id"] = project_id
                # Honour provider-level discovered_by; default to provider_name
                if "discovered_by" not in asset_data or not asset_data["discovered_by"]:
                    asset_data["discovered_by"] = provider_name
                asset_data["updated_at"] = datetime.utcnow()
                # Incoming sources list from UnifiedDiscoveryProvider (may be absent)
                incoming_sources: List[str] = asset_data.pop("sources", [])

                existing = await db.assets.find_one({
                    "project_id": project_id,
                    "domain": asset_data["domain"]
                })

                if existing:
                    # Merge ports, metadata, and sources
                    merged_ports = list(set(existing.get("open_ports", []) + asset_data.get("open_ports", [])))
                    merged_metadata = {**existing.get("metadata", {}), **asset_data.get("metadata", {})}
                    merged_sources = list(set(existing.get("sources", []) + incoming_sources))

                    await db.assets.update_one(
                        {"_id": existing["_id"]},
                        {"$set": {
                            "status": asset_data["status"] if asset_data["status"] != "unknown" else existing["status"],
                            "open_ports": merged_ports,
                            "metadata": merged_metadata,
                            "sources": merged_sources,
                            "last_seen": datetime.utcnow(),
                            "updated_at": datetime.utcnow(),
                        }}
                    )
                    alert_msg = f"[!] Updated existing asset: {asset_data['domain']} (sources: {merged_sources})"
                else:
                    asset_data["sources"] = incoming_sources
                    asset_data["first_seen"] = datetime.utcnow()
                    asset_data["last_seen"] = datetime.utcnow()
                    asset_data["created_at"] = datetime.utcnow()
                    await db.assets.insert_one(asset_data)
                    alert_msg = f"[+] New asset stored: {asset_data['domain']} (sources: {incoming_sources})"

                logger.info(alert_msg)
                await db.jobs.update_one({"_id": ObjectId(job_id)}, {"$push": {"logs": alert_msg}})
                await manager.broadcast(job_id, {"type": "log", "message": alert_msg})
                await manager.broadcast(job_id, {"type": "asset_discovered", "asset": serialize_doc(asset_data)})

            elif event_type == "scan_summary":
                # Forward the full summary to the frontend for the progress panel
                await manager.broadcast(job_id, {
                    "type": "scan_summary",
                    "provider_counts": event.get("provider_counts", {}),
                    "total_unique": event.get("total_unique", 0),
                })

        # Complete job
        complete_msg = f"[√] Job {job_id} completed successfully."
        logger.info(complete_msg)
        await db.jobs.update_one(
            {"_id": ObjectId(job_id)},
            {"$set": {"status": "completed", "finished_at": datetime.utcnow()}, "$push": {"logs": complete_msg}}
        )
        await manager.broadcast(job_id, {"type": "log", "message": complete_msg})
        await manager.broadcast(job_id, {"type": "status", "status": "completed"})

    except Exception as e:
        logger.error(f"Error running job {job_id}: {e}", exc_info=True)
        fail_msg = f"[-] Job failed due to unexpected error: {str(e)}"
        logger.error(fail_msg)
        await db.jobs.update_one(
            {"_id": ObjectId(job_id)},
            {"$set": {"status": "failed", "finished_at": datetime.utcnow()}, "$push": {"logs": fail_msg}}
        )
        await manager.broadcast(job_id, {"type": "log", "message": fail_msg})
        await manager.broadcast(job_id, {"type": "status", "status": "failed"})


@router.post("/project/{project_id}/provider/{provider_name}", response_model=JobResponse)
async def launch_job(
    project_id: str, 
    provider_name: str, 
    background_tasks: BackgroundTasks,
    current_user: dict = Depends(get_current_user)
):
    db = get_database()
    if not ObjectId.is_valid(project_id):
        raise HTTPException(status_code=400, detail="Invalid project ID format")
        
    project = await db.projects.find_one({
        "_id": ObjectId(project_id),
        "owner_id": str(current_user["_id"])
    })
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    if provider_name not in PROVIDERS:
        raise HTTPException(status_code=400, detail=f"Provider '{provider_name}' is not registered")

    job_dict = {
        "project_id": project_id,
        "provider_name": provider_name,
        "status": "pending",
        "logs": [],
        "started_at": datetime.utcnow(),
        "finished_at": None
    }
    
    result = await db.jobs.insert_one(job_dict)
    job_id = str(result.inserted_id)
    job_dict["_id"] = result.inserted_id

    # Queue background task to execute mock scanning provider
    background_tasks.add_task(
        run_discovery_job,
        job_id,
        project_id,
        provider_name,
        project["seed_domains"]
    )

    return serialize_doc(job_dict)


@router.get("/project/{project_id}", response_model=List[JobResponse])
async def get_project_jobs(project_id: str, current_user: dict = Depends(get_current_user)):
    db = get_database()
    if not ObjectId.is_valid(project_id):
        raise HTTPException(status_code=400, detail="Invalid project ID format")
        
    cursor = db.jobs.find({"project_id": project_id}).sort("started_at", -1)
    jobs = await cursor.to_list(length=100)
    return serialize_doc(jobs)


@router.get("/{job_id}", response_model=JobResponse)
async def get_job(job_id: str, current_user: dict = Depends(get_current_user)):
    db = get_database()
    if not ObjectId.is_valid(job_id):
        raise HTTPException(status_code=400, detail="Invalid job ID format")
        
    job = await db.jobs.find_one({"_id": ObjectId(job_id)})
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    return serialize_doc(job)


@router.websocket("/ws/{job_id}")
async def websocket_endpoint(websocket: WebSocket, job_id: str):
    await manager.connect(job_id, websocket)
    db = get_database()
    
    try:
        # Send historical logs first
        if db is not None and ObjectId.is_valid(job_id):
            job = await db.jobs.find_one({"_id": ObjectId(job_id)})
            if job:
                # Send current status
                await websocket.send_json({"type": "status", "status": job["status"]})
                # Send existing logs
                for log in job.get("logs", []):
                    await websocket.send_json({"type": "log", "message": log})
        
        # Keep connection open for real-time broadcasts
        while True:
            # We don't expect messages from client, but we must listen to keep connection alive
            data = await websocket.receive_text()
            # If client sends a ping, reply pong
            if data == "ping":
                await websocket.send_text("pong")
                
    except WebSocketDisconnect:
        manager.disconnect(job_id, websocket)
    except Exception as e:
        logger.error(f"WS Exception on job {job_id}: {e}")
        manager.disconnect(job_id, websocket)
