from fastapi import APIRouter, Query, Body
from typing import Dict, Any
from app.core.tools import get_all_tools_status_with_metadata
from app.core.provider_keys import get_masked_keys_status, save_provider_keys

router = APIRouter(prefix="/system", tags=["System"])


@router.get("/tools")
async def get_system_tools(
    refresh: bool = Query(False, description="Force re-check of tool binaries"),
):
    """
    Returns installation status and paths for all registered bug bounty
    recon tools inside WSL/system.
    Returns cached results immediately; ?refresh=true re-runs single resolution
    call with 10s timeout and returns partial/cached data with warning on timeout.
    """
    return get_all_tools_status_with_metadata(force_refresh=refresh, timeout_seconds=10)


@router.get("/provider-keys")
async def get_provider_keys():
    """Returns safe masked configuration status for passive API keys."""
    return get_masked_keys_status()


@router.post("/provider-keys")
async def update_provider_keys(keys_data: Dict[str, Any] = Body(...)):
    """Saves provider keys to local config and synchronizes Subfinder config in WSL."""
    success = save_provider_keys(keys_data)
    return {"success": success, "status": get_masked_keys_status()}


@router.get("/status")
async def get_system_status():
    """
    Returns platform health, database connectivity, and in-memory fallback status.
    Exposes `in_memory_db` boolean and `warning` message for UI banner alerts.
    """
    from app.database import db_helper
    is_mock = getattr(db_helper, "is_mock", False)
    return {
        "status": "online",
        "in_memory_db": is_mock,
        "db_type": "in_memory" if is_mock else "mongodb",
        "warning": "Running on in-memory DB, data will be lost" if is_mock else None,
        "database": {
            "is_mock": is_mock,
            "connected": True,
            "type": "in_memory" if is_mock else "mongodb",
        },
    }
