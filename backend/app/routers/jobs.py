import asyncio
import logging
from datetime import datetime
from typing import Dict, List, Set, Any
from fastapi import APIRouter, HTTPException, Depends, BackgroundTasks, WebSocket, WebSocketDisconnect
from bson import ObjectId
from app.database import get_database
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

# In-memory registry of active executing jobs in current process
live_running_jobs: Set[str] = set()

def is_job_alive(job_id: str) -> bool:
    """Returns True if a job is actively running in this process."""
    return str(job_id) in live_running_jobs


def merge_asset_metadata(existing_metadata: Dict[str, Any], incoming_metadata: Dict[str, Any]) -> Dict[str, Any]:
    """Merge metadata without overwriting existing values with empty objects."""
    merged = dict(existing_metadata or {})
    incoming = incoming_metadata or {}

    if not incoming:
        return merged

    for key, value in incoming.items():
        if value is None:
            continue
        if isinstance(value, dict) and isinstance(merged.get(key), dict) and value:
            if key == "nuclei" and "findings" in value:
                existing_nuclei = merged.get("nuclei") or {}
                existing_findings = existing_nuclei.get("findings") or []
                incoming_findings = value.get("findings") or []
                
                # Deduplicate by: template_id + matched_url
                finding_map = {}
                for f in existing_findings:
                    k = (f.get("template_id"), f.get("matched_url"))
                    finding_map[k] = f
                for f in incoming_findings:
                    k = (f.get("template_id"), f.get("matched_url"))
                    finding_map[k] = f
                
                merged["nuclei"] = {
                    **existing_nuclei,
                    **value,
                    "findings": list(finding_map.values())
                }
            else:
                merged[key] = {**merged[key], **value}
        elif value == {}:
            continue
        else:
            merged[key] = value

    return merged


@router.get("/providers")
async def get_registered_providers():
    return [
        {
            "name": name,
            "description": provider.description
        }
        for name, provider in PROVIDERS.items()
    ]


async def run_discovery_job(job_id: str, project_id: str, provider_name: str, seed_domains: List[str]):
    import time
    from app.core.scope import normalize_seed_domain
    from app.job_control import current_job_id
    current_job_id.set(job_id)
    live_running_jobs.add(str(job_id))

    # Normalize seeds before passing to any tool (e.g. *.example.com -> example.com)
    normalized_seeds = []
    for s in (seed_domains or []):
        norm_s = normalize_seed_domain(s)
        if norm_s and norm_s not in normalized_seeds:
            normalized_seeds.append(norm_s)
    if not normalized_seeds and seed_domains:
        normalized_seeds = [s.strip().lstrip("*.").strip() for s in seed_domains if s.strip()]
    seed_domains = normalized_seeds

    db = get_database()
    if db is None:
        logger.error("Database is not initialized. Cannot run job.")
        live_running_jobs.discard(str(job_id))
        return

    provider = PROVIDERS.get(provider_name)
    if not provider:
        err_msg = f"[-] Provider {provider_name} not found."
        await db.jobs.update_one(
            {"_id": ObjectId(job_id)},
            {"$set": {"status": "failed", "finished_at": datetime.utcnow()}, "$push": {"logs": err_msg}}
        )
        await manager.broadcast(job_id, {"type": "log", "message": err_msg})
        live_running_jobs.discard(str(job_id))
        return

    # Initialize tool resolution cache if not loaded
    from app.core.tools import _ensure_cache_loaded, invalidate_tool_cache
    _ensure_cache_loaded()

    # Update job state to running with initial heartbeat
    now_init = datetime.utcnow()
    await db.jobs.update_one(
        {"_id": ObjectId(job_id)},
        {"$set": {
            "status": "running",
            "started_at": now_init,
            "heartbeat": now_init,
            "executed_phases": [],
            "liveness_version": 2,
        }}
    )
    
    start_msg = f"[+] Starting job {job_id} using {provider_name} for seed domains: {', '.join(seed_domains)}..."
    logger.info(start_msg)
    await db.jobs.update_one({"_id": ObjectId(job_id)}, {"$push": {"logs": start_msg}})
    await manager.broadcast(job_id, {"type": "log", "message": start_msg})

    # Pre-initialize variables used across discovery, diff, and completion
    executed_phases: Set[str] = set()
    stage_markers_list: List[Dict[str, Any]] = []
    collected_raw_outputs: Dict[str, str] = {}
    passive_executed: bool = False
    passive_killed_or_failed: bool = False
    rejected_urls_count: int = 0
    last_hb_time = time.time()
    scan_diff = None
    summary = {}
    project_doc = None
    project_name = "Project"
    diff_err = None
    complete_msg = f"[√] Job {job_id} completed successfully."

    try:
        # Fetch project configuration (scope, rate_limits, custom_headers, clustering, port_range)
        project = await db.projects.find_one({"_id": ObjectId(project_id)})
        project_config = {
            "project_id": str(project_id),
            "scope": project.get("scope") if project else None,
            "rate_limits": project.get("rate_limits") if project else None,
            "custom_headers": project.get("custom_headers") if project else None,
            "clustering": project.get("clustering") if project else None,
            "port_range": project.get("port_range") if project else None,
            "response_body_max_kb": project.get("response_body_max_kb", 500) if project else 500,
            "scan_profile": project.get("scan_profile", "recon") if project else "recon",
            "assume_tools_installed": project.get("assume_tools_installed") if project else None,
            "wordlists": project.get("wordlists") if project else None,
            "per_host_url_cap": project.get("per_host_url_cap") if project else None,
        }

        # Run plugin generator with scan_mode and project_config if supported
        import inspect
        job = await db.jobs.find_one({"_id": ObjectId(job_id)})
        scan_mode = job.get("scan_mode", "fast") if job else "fast"
        sig = inspect.signature(provider.discover)
        discover_kwargs = {}
        if "scan_mode" in sig.parameters:
            discover_kwargs["scan_mode"] = scan_mode
        if "project_config" in sig.parameters:
            discover_kwargs["project_config"] = project_config
        generator = provider.discover(seed_domains, **discover_kwargs)
        async for event in generator:
            # Heartbeat update (every 5 seconds)
            if time.time() - last_hb_time > 5:
                await db.jobs.update_one({"_id": ObjectId(job_id)}, {"$set": {"heartbeat": datetime.utcnow()}})
                last_hb_time = time.time()

            event_type = event.get("type")

            if "raw_output" in event or event_type == "raw_output":
                t_name = event.get("tool") or event.get("stage") or event.get("provider")
                raw_val = event.get("raw_output") or event.get("output")
                if t_name and raw_val:
                    collected_raw_outputs[str(t_name)] = str(raw_val)

            if event_type == "log":
                log_message = event.get("message")
                logger.info(f"[{provider_name}] {log_message}")

                # Detect passive source failures
                msg_l = str(log_message).lower()
                if "encountered an error:" in msg_l or "failed:" in msg_l:
                    for p_lbl in ("subfinder", "assetfinder", "chaos", "amass"):
                        if p_lbl in msg_l:
                            await db.jobs.update_one({"_id": ObjectId(job_id)}, {"$set": {"passive_source_errored": True}})
                            break

                # Detect executed phases from logs
                if "naabu" in msg_l or "port scan" in msg_l:
                    executed_phases.add("port_scanning")
                if "httpx" in msg_l or "web probing" in msg_l:
                    executed_phases.add("web_probing")
                if "katana" in msg_l or "crawling" in msg_l:
                    executed_phases.add("crawling")
                if "nuclei" in msg_l:
                    executed_phases.add("vulnerability_scan")
                if ("ffuf" in msg_l or "feroxbuster" in msg_l or "content discovery" in msg_l) and "tool_missing: ffuf" not in msg_l and "tool_missing: feroxbuster" not in msg_l and "skipping content discovery" not in msg_l:
                    executed_phases.add("content_discovery")
                if ("api surface" in msg_l or "api spec" in msg_l or "graphql" in msg_l) and "skipping api" not in msg_l:
                    executed_phases.add("api_surface")
                if ("arjun" in msg_l or "x8" in msg_l or "parameter discovery" in msg_l) and "tool_missing: arjun" not in msg_l and "skipping parameter discovery" not in msg_l:
                    executed_phases.add("param_discovery")
                if ("puredns" in msg_l or "shuffledns" in msg_l or "dns brute force" in msg_l or "alterx" in msg_l) and "tool_missing: puredns" not in msg_l and "stage_skipped" not in msg_l and "deep mode only" not in msg_l:
                    executed_phases.add("dns_bruteforce")
                if "root expansion" in msg_l or "asnmap" in msg_l:
                    executed_phases.add("root_expansion")
                if "takeover" in msg_l or "subzy" in msg_l:
                    executed_phases.add("takeover_crosscheck")

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
                if not asset_data or not isinstance(asset_data, dict):
                    continue
                asset_data["project_id"] = project_id
                asset_type = asset_data.get("type", "subdomain")
                domain_val = (asset_data.get("domain") or "").strip()
                asset_val = (asset_data.get("value") or domain_val).strip()

                # Requirement 5: Validate every URL/host before it is stored
                from app.core.scope import is_valid_url, sanitize_url, validate_hostname
                if asset_type in (
                    "content_path", "historical_url", "historical_dead",
                    "uro_url", "gf_url", "js_file", "screenshot", "finding",
                    "api_spec", "graphql_endpoint", "param"
                ):
                    check_url = asset_val or (asset_data.get("metadata") or {}).get("url") or ""
                    sanitized_check_url = sanitize_url(check_url)
                    valid_u, u_reason = is_valid_url(sanitized_check_url)
                    if not valid_u:
                        rejected_urls_count += 1
                        logger.warning(f"[-] Dropping invalid URL asset ({u_reason}): {check_url}")
                        continue
                    asset_val = sanitized_check_url
                    asset_data["value"] = sanitized_check_url
                    if asset_data.get("metadata") and "url" in asset_data["metadata"]:
                        asset_data["metadata"]["url"] = sanitized_check_url
                elif asset_val.startswith("http://") or asset_val.startswith("https://"):
                    sanitized_val = sanitize_url(asset_val)
                    valid_u, u_reason = is_valid_url(sanitized_val)
                    if not valid_u:
                        rejected_urls_count += 1
                        logger.warning(f"[-] Dropping invalid URL asset ({u_reason}): {asset_val}")
                        continue
                    asset_val = sanitized_val
                    asset_data["value"] = sanitized_val
                elif asset_type in ("domain", "subdomain"):
                    target_host = domain_val or asset_val
                    valid_h, h_reason = validate_hostname(target_host)
                    if not valid_h:
                        logger.warning(f"[-] Dropping invalid hostname asset ({h_reason}): {target_host}")
                        continue
                    passive_executed = True

                if asset_type == "content_path":
                    executed_phases.add("content_discovery")
                elif asset_type in ("api_spec", "graphql_endpoint"):
                    executed_phases.add("api_surface")
                elif asset_type == "param":
                    executed_phases.add("param_discovery")
                elif asset_type == "suggested_root":
                    executed_phases.add("root_expansion")
                elif asset_type == "takeover":
                    executed_phases.add("takeover_crosscheck")
                asset_data["value"] = asset_val
                asset_data["scan_id"] = job_id
                now_dt = datetime.utcnow()
                asset_data["updated_at"] = now_dt

                # Honour provider-level discovered_by; default to provider_name
                if "discovered_by" not in asset_data or not asset_data["discovered_by"]:
                    asset_data["discovered_by"] = provider_name
                # Incoming sources list from UnifiedDiscoveryProvider (may be absent)
                incoming_sources: List[str] = asset_data.pop("sources", [])

                # Response fingerprinting for live hosts
                meta = asset_data.get("metadata") or {}
                if meta.get("status_code") or meta.get("url") or asset_data.get("status") == "live":
                    from app.services.diff_engine import generate_host_fingerprint
                    fp = generate_host_fingerprint(
                        status_code=meta.get("status_code"),
                        title=meta.get("title"),
                        content_length=meta.get("content_length"),
                        technologies=meta.get("technologies"),
                    )
                    asset_data["fingerprint"] = fp

                # Upsert keyed on (project_id, type, value)
                existing = await db.assets.find_one({
                    "project_id": project_id,
                    "type": asset_type,
                    "$or": [
                        {"value": asset_val},
                        {"domain": asset_val}
                    ]
                })

                if existing:
                    # Merge ports, metadata, and sources while preserving existing metadata.
                    merged_ports = list(set(existing.get("open_ports", []) + asset_data.get("open_ports", [])))
                    merged_metadata = merge_asset_metadata(existing.get("metadata", {}), asset_data.get("metadata", {}))
                    merged_sources = list(set(existing.get("sources", []) + incoming_sources))
                    incoming_status = asset_data.get("status")
                    if incoming_status and incoming_status != "unknown":
                        new_status = incoming_status
                    else:
                        new_status = existing.get("status", "live")
                    if new_status == "stale" and incoming_status == "live":
                        new_status = "live"

                    # Store previous fingerprint for diffing if updated
                    previous_fp = existing.get("fingerprint") or existing.get("previous_fingerprint")

                    update_fields = {
                        "status": new_status,
                        "open_ports": merged_ports,
                        "metadata": merged_metadata,
                        "sources": merged_sources,
                        "value": asset_val,
                        "scan_id": job_id,
                        "last_seen": now_dt,
                        "updated_at": now_dt,
                    }
                    if previous_fp:
                        update_fields["previous_fingerprint"] = previous_fp
                    if "status_class" in asset_data:
                        update_fields["status_class"] = asset_data["status_class"]
                    if "is_interesting" in asset_data:
                        update_fields["is_interesting"] = asset_data["is_interesting"]
                        update_fields["interesting_reason"] = asset_data.get("interesting_reason")
                    if "liveness_version" in asset_data:
                        update_fields["liveness_version"] = asset_data["liveness_version"]
                    if "cdn_waf" in asset_data and asset_data["cdn_waf"]:
                        update_fields["cdn_waf"] = asset_data["cdn_waf"]
                    if "cluster_id" in asset_data and asset_data["cluster_id"]:
                        update_fields["cluster_id"] = asset_data["cluster_id"]
                        update_fields["cluster_role"] = asset_data.get("cluster_role")
                        update_fields["is_cluster_representative"] = asset_data.get("is_cluster_representative")
                        update_fields["cluster_size"] = asset_data.get("cluster_size")
                        update_fields["cluster_representative_host"] = asset_data.get("cluster_representative_host")
                        update_fields["cluster_skip_reason"] = asset_data.get("cluster_skip_reason")
                    if "services" in asset_data and asset_data["services"]:
                        update_fields["services"] = asset_data["services"]
                    if "fingerprint" in asset_data:
                        update_fields["fingerprint"] = asset_data["fingerprint"]

                    await db.assets.update_one(
                        {"_id": existing["_id"]},
                        {"$set": update_fields}
                    )
                    alert_msg = f"[!] Updated existing asset: {asset_val} (type: {asset_type}, sources: {merged_sources})"
                    
                    # Prepare fully merged asset for real-time WebSocket broadcast
                    broadcast_asset = {
                        **existing,
                        **update_fields
                    }
                else:
                    asset_data["sources"] = incoming_sources
                    asset_data["first_seen"] = now_dt
                    asset_data["last_seen"] = now_dt
                    asset_data["created_at"] = now_dt
                    await db.assets.insert_one(asset_data)
                    alert_msg = f"[+] New asset stored: {asset_val} (type: {asset_type}, sources: {incoming_sources})"
                    broadcast_asset = asset_data

                try:
                    from app.services.run_history import record_run_asset
                    await record_run_asset(
                        db=db,
                        project_id=str(project_id),
                        job_id=str(job_id),
                        asset_type=asset_type,
                        value=asset_val,
                        domain=domain_val,
                        status=broadcast_asset.get("status", "unknown"),
                        metadata=broadcast_asset.get("metadata"),
                    )
                except Exception:
                    pass

                logger.info(alert_msg)
                await db.jobs.update_one({"_id": ObjectId(job_id)}, {"$push": {"logs": alert_msg}})
                await manager.broadcast(job_id, {"type": "log", "message": alert_msg})
                await manager.broadcast(job_id, {"type": "asset_discovered", "asset": serialize_doc(broadcast_asset)})

            elif event_type in ("url_event", "gf_event", "js_event", "screenshot_event", "finding_event"):
                import time
                url_data = event.get("data") or {}
                url_val = (url_data.get("url") or url_data.get("matched_url") or "").strip()
                if url_val:
                    from app.core.scope import is_valid_url, sanitize_url
                    url_val = sanitize_url(url_val)
                    if "url" in url_data:
                        url_data["url"] = url_val
                    if "matched_url" in url_data:
                        url_data["matched_url"] = url_val
                    valid_u, u_reason = is_valid_url(url_val)
                    if not valid_u:
                        rejected_urls_count += 1
                        logger.warning(f"[-] Discarding invalid URL from {event_type} ({u_reason}): {url_val}")
                        continue
                    now_dt = datetime.utcnow()
                    if event_type == "url_event":
                        source = url_data.get("source", "uro")
                        if source in ("gau", "linkfinder", "merged", "katana", "waymore", "api_spec", "param_discovery"):
                            existing = await db.assets.find_one({
                                "project_id": project_id,
                                "type": "historical_url",
                                "$or": [{"value": url_val}, {"domain": url_val}]
                            })
                            if existing:
                                current_sources = existing.get("sources", [])
                                new_sources = list(set(current_sources + url_data.get("sources", [source])))
                                await db.assets.update_one(
                                    {"_id": existing["_id"]},
                                    {"$set": {
                                        "value": url_val,
                                        "scan_id": job_id,
                                        "sources": new_sources,
                                        "metadata.sources": new_sources,
                                        "last_seen": now_dt,
                                        "updated_at": now_dt
                                    }}
                                )
                            else:
                                await db.assets.insert_one({
                                    "project_id": project_id,
                                    "domain": url_val,
                                    "value": url_val,
                                    "type": "historical_url",
                                    "status": "live",
                                    "scan_id": job_id,
                                    "first_seen": now_dt,
                                    "last_seen": now_dt,
                                    "metadata": {
                                        "url": url_val,
                                        "source": source,
                                        "sources": url_data.get("sources", [source]),
                                        "has_params": url_data.get("has_params", False),
                                        "extension": url_data.get("extension", ""),
                                        "discovered_at": url_data.get("discovered_at", int(time.time()))
                                    },
                                    "discovered_by": source,
                                    "sources": url_data.get("sources", [source]),
                                    "created_at": now_dt,
                                    "updated_at": now_dt
                                })
                            try:
                                from app.services.run_history import record_run_asset
                                await record_run_asset(
                                    db=db,
                                    project_id=str(project_id),
                                    job_id=str(job_id),
                                    asset_type="historical_url",
                                    value=url_val,
                                    domain=url_val,
                                    status="live",
                                    metadata=url_data,
                                )
                            except Exception:
                                pass
                        else:
                            existing = await db.assets.find_one({
                                "project_id": project_id,
                                "type": "uro_url",
                                "$or": [{"value": url_val}, {"domain": url_val}]
                            })
                            if existing:
                                await db.assets.update_one(
                                    {"_id": existing["_id"]},
                                    {"$set": {
                                        "value": url_val,
                                        "scan_id": job_id,
                                        "last_seen": now_dt,
                                        "updated_at": now_dt
                                    }}
                                )
                            else:
                                await db.assets.insert_one({
                                    "project_id": project_id,
                                    "domain": url_val,
                                    "value": url_val,
                                    "type": "uro_url",
                                    "status": "live",
                                    "scan_id": job_id,
                                    "first_seen": now_dt,
                                    "last_seen": now_dt,
                                    "metadata": {
                                        "source": "uro",
                                        "uro": {
                                            "original_url": url_data.get("original_url", url_val),
                                            "normalized_url": url_val,
                                            "duplicate_removed": url_data.get("duplicate_removed", False),
                                        }
                                    },
                                    "discovered_by": "uro",
                                    "sources": ["uro"],
                                    "created_at": now_dt,
                                    "updated_at": now_dt
                                })
                            try:
                                from app.services.run_history import record_run_asset
                                await record_run_asset(
                                    db=db,
                                    project_id=str(project_id),
                                    job_id=str(job_id),
                                    asset_type="uro_url",
                                    value=url_val,
                                    domain=url_val,
                                    status="live",
                                    metadata=url_data,
                                )
                            except Exception:
                                pass
                    elif event_type == "gf_event":
                        existing = await db.assets.find_one({
                            "project_id": project_id,
                            "type": "gf_url",
                            "$or": [{"value": url_val}, {"domain": url_val}]
                        })
                        if existing:
                            metadata = existing.get("metadata") or {}
                            gf_meta = metadata.get("gf") or {}
                            existing_cats = gf_meta.get("categories") or []
                            new_cats = list(set(existing_cats + url_data.get("categories", [])))
                            updated_metadata = {
                                **metadata,
                                "gf": {
                                    **gf_meta,
                                    "categories": new_cats
                                }
                            }
                            await db.assets.update_one(
                                {"_id": existing["_id"]},
                                {"$set": {
                                    "value": url_val,
                                    "scan_id": job_id,
                                    "metadata": updated_metadata,
                                    "last_seen": now_dt,
                                    "updated_at": now_dt
                                }}
                            )
                        else:
                            await db.assets.insert_one({
                                "project_id": project_id,
                                "domain": url_val,
                                "value": url_val,
                                "type": "gf_url",
                                "status": "live",
                                "scan_id": job_id,
                                "first_seen": now_dt,
                                "last_seen": now_dt,
                                "metadata": {
                                    "source": "gf",
                                    "gf": {
                                        "url": url_val,
                                        "categories": url_data.get("categories", []),
                                        "classified_at": url_data.get("classified_at", int(time.time()))
                                    }
                                },
                                "discovered_by": "gf",
                                "sources": ["gf"],
                                "created_at": now_dt,
                                "updated_at": now_dt
                            })
                            try:
                                from app.services.run_history import record_run_asset
                                await record_run_asset(
                                    db=db,
                                    project_id=str(project_id),
                                    job_id=str(job_id),
                                    asset_type="gf_url",
                                    value=url_val,
                                    domain=url_val,
                                    status="live",
                                    metadata=url_data,
                                )
                            except Exception:
                                pass
                    elif event_type == "js_event":
                        existing = await db.assets.find_one({
                            "project_id": project_id,
                            "type": "js_file",
                            "$or": [{"value": url_val}, {"domain": url_val}]
                        })
                        if existing:
                            await db.assets.update_one(
                                {"_id": existing["_id"]},
                                {"$set": {
                                    "value": url_val,
                                    "scan_id": job_id,
                                    "last_seen": now_dt,
                                    "updated_at": now_dt
                                }}
                            )
                        else:
                            await db.assets.insert_one({
                                "project_id": project_id,
                                "domain": url_val,
                                "value": url_val,
                                "type": "js_file",
                                "status": "live",
                                "scan_id": job_id,
                                "first_seen": now_dt,
                                "last_seen": now_dt,
                                "metadata": {
                                    "url": url_val,
                                    "host": url_data.get("host", ""),
                                    "size": url_data.get("size", "unknown"),
                                    "source": "subjs"
                                },
                                "discovered_by": "subjs",
                                "sources": ["subjs"],
                                "created_at": now_dt,
                                "updated_at": now_dt
                            })
                        try:
                            from app.services.run_history import record_run_asset
                            await record_run_asset(
                                db=db,
                                project_id=str(project_id),
                                job_id=str(job_id),
                                asset_type="js_file",
                                value=url_val,
                                domain=url_val,
                                status="live",
                                metadata=url_data,
                            )
                        except Exception:
                            pass
                    elif event_type == "screenshot_event":
                        existing = await db.assets.find_one({
                            "project_id": project_id,
                            "type": "screenshot",
                            "$or": [{"value": url_val}, {"domain": url_val}]
                        })
                        if existing:
                            await db.assets.update_one(
                                {"_id": existing["_id"]},
                                {"$set": {
                                    "value": url_val,
                                    "scan_id": job_id,
                                    "last_seen": now_dt,
                                    "updated_at": now_dt
                                }}
                            )
                        else:
                            await db.assets.insert_one({
                                "project_id": project_id,
                                "domain": url_val,
                                "value": url_val,
                                "type": "screenshot",
                                "status": "live",
                                "scan_id": job_id,
                                "first_seen": now_dt,
                                "last_seen": now_dt,
                                "metadata": {
                                    "url": url_val,
                                    "title": url_data.get("title", ""),
                                    "screenshot_path": url_data.get("screenshot_path", ""),
                                    "timestamp": url_data.get("timestamp", datetime.utcnow().isoformat()),
                                    "source": "gowitness",
                                    "host": url_data.get("host", "")
                                },
                                "discovered_by": "gowitness",
                                "sources": ["gowitness"],
                                "created_at": now_dt,
                                "updated_at": now_dt
                            })
                    elif event_type == "finding_event":
                        executed_phases.add("vulnerability_scan")
                        template_id = (
                            url_data.get("template_id")
                            or url_data.get("templateID")
                            or url_data.get("source")
                            or "finding"
                        ).strip()
                        matched_at = (url_data.get("matched_url") or url_data.get("url") or url_val or "").strip()
                        host = (url_data.get("host") or "").strip()
                        if not host and matched_at:
                            try:
                                from urllib.parse import urlparse
                                host = urlparse(matched_at).netloc or ""
                            except Exception:
                                host = ""

                        # Stable finding identity key: template-id + matched-at + host (NO scan_id, NO timestamp)
                        finding_key = f"{template_id}:{matched_at}:{host}"

                        existing = await db.assets.find_one({
                            "project_id": project_id,
                            "type": "finding",
                            "$or": [
                                {"value": finding_key},
                                {"domain": url_val}
                            ]
                        })
                        if existing:
                            await db.assets.update_one(
                                {"_id": existing["_id"]},
                                {"$set": {
                                    "value": finding_key,
                                    "scan_id": job_id,
                                    "last_seen": now_dt,
                                    "updated_at": now_dt,
                                    "metadata.payload": url_data.get("payload", ""),
                                    "metadata.parameter": url_data.get("parameter", ""),
                                    "metadata.evidence": url_data.get("evidence", ""),
                                }}
                            )
                        else:
                            await db.assets.insert_one({
                                "project_id": project_id,
                                "domain": url_val,
                                "value": finding_key,
                                "type": "finding",
                                "status": "live",
                                "scan_id": job_id,
                                "first_seen": now_dt,
                                "last_seen": now_dt,
                                "metadata": {
                                    "template_id": template_id,
                                    "source": url_data.get("source"),
                                    "severity": url_data.get("severity"),
                                    "matched_url": matched_at,
                                    "host": host,
                                    "payload": url_data.get("payload", ""),
                                    "parameter": url_data.get("parameter", ""),
                                    "evidence": url_data.get("evidence", ""),
                                    "timestamp": url_data.get("timestamp", datetime.utcnow().isoformat())
                                },
                                "discovered_by": url_data.get("source"),
                                "sources": [url_data.get("source")],
                                "created_at": now_dt,
                                "updated_at": now_dt
                            })
                        try:
                            from app.services.run_history import record_run_asset
                            await record_run_asset(
                                db=db,
                                project_id=str(project_id),
                                job_id=str(job_id),
                                asset_type="finding",
                                value=finding_key,
                                domain=host or url_val,
                                status="live",
                                metadata=url_data,
                            )
                        except Exception:
                            pass
                await manager.broadcast(job_id, event)

            elif event_type == "scan_summary":
                # Forward available summary fields without inventing zero values
                # for internal stages such as HTTPX or Naabu.
                summary_payload = {"type": "scan_summary"}
                summary_payload.update({
                    key: value
                    for key, value in event.items()
                    if key != "type" and value is not None
                })
                await manager.broadcast(job_id, summary_payload)

            elif event_type in (
                "scope_filtered", "stage_skipped", "stage_timeout", "stage_error", "scope_warning", "warning_event",
                "content_path_event", "api_spec_event", "graphql_event", "param_event", "historical_probe_event"
            ):
                if event_type == "content_path_event":
                    executed_phases.add("content_discovery")
                elif event_type in ("api_spec_event", "graphql_event"):
                    executed_phases.add("api_surface")
                elif event_type == "param_event":
                    executed_phases.add("param_discovery")
                elif event_type in ("stage_skipped", "stage_timeout", "stage_error"):
                    stage_markers_list.append({
                        "type": event_type.replace("stage_", ""),
                        "stage": event.get("stage") or event.get("tool") or "unknown",
                        "tool": event.get("tool") or "",
                        "reason": event.get("reason") or event.get("error") or event.get("message") or "unknown",
                    })
                    tool = str(event.get("tool") or event.get("stage") or "").lower()
                    if tool in ("ffuf", "feroxbuster", "content_discovery"):
                        executed_phases.discard("content_discovery")
                    elif tool in ("api_surface", "api_surface_detection"):
                        executed_phases.discard("api_surface")
                    elif tool in ("arjun", "x8", "param_discovery"):
                        executed_phases.discard("param_discovery")
                    elif tool in ("katana", "gau", "waymore", "subjs", "url_discovery"):
                        executed_phases.discard("url_discovery")
                    elif tool in ("naabu", "nmap", "port_scanning"):
                        executed_phases.discard("port_scanning")
                    elif tool in ("nuclei", "nuclei_host", "nuclei_endpoint", "dalfox", "openredirex", "vulnerability_scan"):
                        executed_phases.discard("vulnerability_scan")
                    elif any(p in tool for p in ("subfinder", "assetfinder", "chaos", "amass", "subdomain")):
                        executed_phases.discard("subdomain_discovery")
                    elif any(p in tool for p in ("puredns", "shuffledns", "alterx", "dns_bruteforce")):
                        executed_phases.discard("dns_bruteforce")
                    elif any(p in tool for p in ("asnmap", "root_expansion")):
                        executed_phases.discard("root_expansion")
                    elif any(p in tool for p in ("subzy", "dnsreaper", "takeover", "takeover_crosscheck")):
                        executed_phases.discard("takeover_crosscheck")
                await manager.broadcast(job_id, event)
                if event_type == "stage_error":
                    err_msg = event.get("message") or f"[-] Stage error in {event.get('tool') or event.get('stage')}: {event.get('reason') or event.get('error')}"
                    await db.jobs.update_one({"_id": ObjectId(job_id)}, {"$push": {"logs": err_msg}})
                    # Invalidate tool cache if error was "not found"
                    tool_err = str(event.get("reason") or event.get("error") or "").lower()
                    if "not found" in tool_err or "not_found" in tool_err or event.get("returncode") == 127:
                        invalidate_tool_cache(event.get("tool"))
                elif event_type == "scope_filtered":
                    drop_cnt = event.get("dropped_count", 0)
                    stage_lbl = event.get("stage", "Scope Filter")
                    samples_list = event.get("samples", [])
                    samples_str = f" Samples: {samples_list[:3]}" if samples_list else ""
                    filter_msg = f"[*] {stage_lbl}: Filtered out {drop_cnt} out-of-scope targets.{samples_str}"
                    await db.jobs.update_one({"_id": ObjectId(job_id)}, {"$push": {"logs": filter_msg}})
                elif event_type == "stage_skipped":
                    stage_lbl = event.get("stage", "Stage")
                    reason = event.get("reason", "unknown")
                    skip_msg = f"[!] {stage_lbl} skipped ({reason})"
                    await db.jobs.update_one({"_id": ObjectId(job_id)}, {"$push": {"logs": skip_msg}})
                elif event_type == "scope_warning":
                    warn_msg = event.get("message", "Scope is unconfigured")
                    await db.jobs.update_one({"_id": ObjectId(job_id)}, {"$push": {"logs": f"[!] {warn_msg}"}})
                elif event_type == "warning_event":
                    warn_msg = event.get("message", "Warning")
                    await db.jobs.update_one({"_id": ObjectId(job_id)}, {"$push": {"logs": f"[!] {warn_msg}"}})

        # Run Risk Scoring Engine automatically on Unified Discovery completion
        if provider_name == "Unified Discovery":
            try:
                start_log = "[*] Calculating risk scores..."
                logger.info(start_log)
                await db.jobs.update_one({"_id": ObjectId(job_id)}, {"$push": {"logs": start_log}})
                await manager.broadcast(job_id, {"type": "log", "message": start_log})
                
                from app.services.risk_scoring import recalculate_all_scores
                scores = await recalculate_all_scores(project_id)
                
                start_log_count = f"[*] Calculating risk scores for {len(scores)} assets..."
                logger.info(start_log_count)
                await db.jobs.update_one({"_id": ObjectId(job_id)}, {"$push": {"logs": start_log_count}})
                await manager.broadcast(job_id, {"type": "log", "message": start_log_count})
                
                for s in scores:
                    asset_log = f"[✓] {s['asset']} scored {s['score']} ({s['level']})"
                    await db.jobs.update_one({"_id": ObjectId(job_id)}, {"$push": {"logs": asset_log}})
                    await manager.broadcast(job_id, {"type": "log", "message": asset_log})
                    
                    ws_payload = {
                        "type": "risk_score_event",
                        "asset": s["asset"],
                        "score": s["score"],
                        "level": s["level"],
                        "reasons": s["reasons"],
                        "exposure_factors": s["exposure_factors"],
                        "recommended_priority": s["recommended_priority"],
                        "importance_score": s.get("importance_score", 0),
                        "exposure_score": s.get("exposure_score", 0),
                        "updated_at": s["updated_at"].isoformat() if isinstance(s["updated_at"], datetime) else s["updated_at"]
                    }
                    await manager.broadcast(job_id, ws_payload)

                    if "hunt_priority" in s and s["hunt_priority"] is not None:
                        hunt_ws_payload = {
                            "type": "hunt_score_event",
                            "asset": s["asset"],
                            "hunt_priority": s["hunt_priority"],
                            "hunt_reasons": s.get("hunt_reasons", []),
                        }
                        await manager.broadcast(job_id, hunt_ws_payload)
                    
                complete_log = "[*] Risk scoring complete."
                logger.info(complete_log)
                await db.jobs.update_one({"_id": ObjectId(job_id)}, {"$push": {"logs": complete_log}})
                await manager.broadcast(job_id, {"type": "log", "message": complete_log})
            except Exception as rse:
                logger.error(f"Error running risk scoring: {rse}", exc_info=True)
                err_log = f"[-] Risk scoring calculation failed: {str(rse)}"
                await db.jobs.update_one({"_id": ObjectId(job_id)}, {"$push": {"logs": err_log}})
                await manager.broadcast(job_id, {"type": "log", "message": err_log})

        # Phase 2: Compute diff vs previous scan and dispatch webhook alerts
        if provider_name == "Unified Discovery":
            try:
                from app.services.diff_engine import compute_and_save_diff
                from app.services.notifier import dispatch_scan_diff_alerts

                diff_start_log = "[*] Computing scan diff vs previous run..."
                logger.info(diff_start_log)
                await db.jobs.update_one({"_id": ObjectId(job_id)}, {"$push": {"logs": diff_start_log}})
                await manager.broadcast(job_id, {"type": "log", "message": diff_start_log})

                scan_diff = await compute_and_save_diff(project_id, job_id, db)
                if scan_diff:
                    summary = scan_diff.get("summary", {})
                    diff_summary_log = (
                        f"[✓] Diff calculated: +{summary.get('new_subdomains_count', 0)} subdomains, "
                        f"+{summary.get('new_live_hosts_count', 0)} live hosts, "
                        f"-{summary.get('stale_subdomains_count', 0)} stale, "
                        f"+{summary.get('new_content_paths_count', 0)} content paths, "
                        f"+{summary.get('new_findings_count', 0)} findings."
                    )
                    logger.info(diff_summary_log)
                    await db.jobs.update_one({"_id": ObjectId(job_id)}, {"$push": {"logs": diff_summary_log}})
                    await manager.broadcast(job_id, {"type": "log", "message": diff_summary_log})

                    # Broadcast scan_diff event over WebSocket
                    await manager.broadcast(job_id, {
                        "type": "scan_diff",
                        "diff": serialize_doc(scan_diff)
                    })

                    # Fetch project document for alerts configuration
                    project_doc = await db.projects.find_one({"_id": ObjectId(project_id)})
                    project_name = project_doc.get("name", "Project") if project_doc else "Project"

                    # Dispatch Webhook Alerts (Discord & Telegram) with secrets redaction
                    await dispatch_scan_diff_alerts(project_name, scan_diff, project_doc)
            except (Exception, BaseException) as de:
                logger.error(f"Error computing scan diff or dispatching alerts: {de}", exc_info=True)
                diff_err = f"[-] Scan diff calculation or alert dispatch failed: {str(de)}"
                await db.jobs.update_one({"_id": ObjectId(job_id)}, {"$push": {"logs": diff_err}})
                await manager.broadcast(job_id, {"type": "log", "message": diff_err})
                await manager.broadcast(job_id, {
                    "type": "stage_error",
                    "stage": "diff_and_alerts",
                    "error": str(de),
                    "message": diff_err,
                })

        # Save executed phases and rejected urls to MongoDB job document
        if passive_executed and not passive_killed_or_failed:
            executed_phases.add("subdomain_discovery")
        else:
            executed_phases.discard("subdomain_discovery")

        await db.jobs.update_one(
            {"_id": ObjectId(job_id)},
            {"$set": {
                "executed_phases": sorted(list(executed_phases)),
                "rejected_urls_count": rejected_urls_count,
            }}
        )

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
    finally:
        live_running_jobs.discard(str(job_id))
        try:
            from app.services.run_history import record_run_history
            await record_run_history(
                db=db,
                job_id=str(job_id),
                project_id=str(project_id),
                stage_markers=stage_markers_list,
                raw_outputs=collected_raw_outputs,
            )
        except Exception as rh_err:
            logger.warning(f"Non-fatal: Failed to record run history for {job_id}: {rh_err}")


@router.post("/project/{project_id}/provider/{provider_name}", response_model=JobResponse)
async def launch_job(
    project_id: str, 
    provider_name: str, 
    background_tasks: BackgroundTasks,
    scan_mode: str = "fast",
):
    db = get_database()
    if not ObjectId.is_valid(project_id):
        raise HTTPException(status_code=400, detail="Invalid project ID format")
        
    project = await db.projects.find_one({
        "_id": ObjectId(project_id)
    })
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    if provider_name not in PROVIDERS:
        raise HTTPException(status_code=400, detail=f"Provider '{provider_name}' is not registered")

    job_dict = {
        "project_id": project_id,
        "provider_name": provider_name,
        "scan_mode": scan_mode,
        "status": "pending",
        "logs": [],
        "liveness_version": 2,
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
async def get_project_jobs(project_id: str):
    db = get_database()
    if not ObjectId.is_valid(project_id):
        raise HTTPException(status_code=400, detail="Invalid project ID format")
        
    cursor = db.jobs.find({"project_id": project_id}).sort("started_at", -1)
    jobs = await cursor.to_list(length=100)
    return serialize_doc(jobs)


@router.get("/{job_id}", response_model=JobResponse)
async def get_job(job_id: str):
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


@router.post("/{job_id}/pause")
async def pause_job(job_id: str):
    db = get_database()
    if not ObjectId.is_valid(job_id):
        raise HTTPException(status_code=400, detail="Invalid job ID format")
    job = await db.jobs.find_one({"_id": ObjectId(job_id)})
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    
    await db.jobs.update_one(
        {"_id": ObjectId(job_id)},
        {"$set": {"status": "paused"}}
    )
    await manager.broadcast(job_id, {"type": "status", "status": "paused"})
    await manager.broadcast(job_id, {"type": "log", "message": "[*] Scan paused by user."})
    return {"status": "paused"}


@router.post("/{job_id}/resume")
async def resume_job(job_id: str):
    db = get_database()
    if not ObjectId.is_valid(job_id):
        raise HTTPException(status_code=400, detail="Invalid job ID format")
    job = await db.jobs.find_one({"_id": ObjectId(job_id)})
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    
    await db.jobs.update_one(
        {"_id": ObjectId(job_id)},
        {"$set": {"status": "running"}}
    )
    await manager.broadcast(job_id, {"type": "status", "status": "running"})
    await manager.broadcast(job_id, {"type": "log", "message": "[*] Scan resumed by user."})
    return {"status": "running"}


@router.post("/{job_id}/stop")
async def stop_job(job_id: str):
    db = get_database()
    if not ObjectId.is_valid(job_id):
        raise HTTPException(status_code=400, detail="Invalid job ID format")
    job = await db.jobs.find_one({"_id": ObjectId(job_id)})
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    
    await db.jobs.update_one(
        {"_id": ObjectId(job_id)},
        {"$set": {"status": "stopped", "finished_at": datetime.utcnow()}}
    )
    
    from app.job_control import active_processes
    procs = list(active_processes.get(job_id, []))
    for p in procs:
        try:
            logger.info(f"Terminating process {p.pid} for stopped job {job_id}")
            p.terminate()
        except Exception as e:
            logger.error(f"Error terminating process: {e}")
            
    await manager.broadcast(job_id, {"type": "status", "status": "stopped"})
    await manager.broadcast(job_id, {"type": "log", "message": "[-] Scan stopped by user."})
    return {"status": "stopped"}


@router.post("/{job_id}/reset")
async def reset_job(job_id: str):
    db = get_database()
    if not ObjectId.is_valid(job_id):
        raise HTTPException(status_code=400, detail="Invalid job ID format")
    job = await db.jobs.find_one({"_id": ObjectId(job_id)})
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    
    project_id = job.get("project_id")
    
    from app.job_control import active_processes
    procs = list(active_processes.get(job_id, []))
    for p in procs:
        try:
            p.terminate()
        except Exception:
            pass
            
    if project_id:
        await db.assets.delete_many({"project_id": project_id})
        await db.jobs.delete_many({"project_id": project_id})
        
    await manager.broadcast(job_id, {"type": "status", "status": "idle"})
    return {"status": "reset"}
