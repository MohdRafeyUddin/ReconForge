import asyncio
import logging
import re
import time
from datetime import datetime
from typing import Dict, List, Optional, Set, Any
from fastapi import APIRouter, HTTPException, Depends, BackgroundTasks, WebSocket, WebSocketDisconnect
from bson import ObjectId
from pydantic import BaseModel, Field
from app.core.scan_options import normalize_scan_mode
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
            from app.core.redaction import redact_payload

            websockets = self.active_connections[job_id]
            if websockets:
                safe_message = redact_payload(message)
                # Run parallel sends
                await asyncio.gather(
                    *[ws.send_json(safe_message) for ws in websockets],
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


# Phase-name bookkeeping for per-phase durations and skipped phases.
PHASE_TIMING_TO_EXECUTED: Dict[str, str] = {
    "passive_discovery": "subdomain_discovery",
    "dns_bruteforce": "dns_bruteforce",
    "dns_resolution": "dns_resolution",
    "takeover_crosscheck": "takeover_crosscheck",
    "port_scanning": "port_scanning",
    "http_probing": "web_probing",
    "content_discovery": "content_discovery",
    "crawlers": "crawling",
    "js_analysis": "js_analysis",
    "url_merge": "url_merge",
    "param_discovery": "param_discovery",
    "gf": "gf",
    "vulnerability_scan": "vulnerability_scan",
    "tech_routing": "tech_routing",
}

# Scanner output from these tools may contain raw secret values and must never
# be persisted as a raw run artifact.
SECRET_SCANNER_TOOLS = {
    "secrets", "secret", "secret_scan", "secret_finding",
    "trufflehog", "gitleaks",
}

COMPLETED_SUMMARY_PHASES: Dict[str, str] = {
    "secrets": "secret_scan",
    "secret": "secret_scan",
    "cloud_enum": "cloud_enum",
    "bucket": "cloud_enum",
    "js_analysis": "js_analysis",
    "linkfinder": "js_analysis",
    "nuclei_tech": "tech_routing",
    "wpscan": "tech_routing",
    "gowitness": "screenshots",
}

SKIPPED_PHASE_MAP: Dict[str, str] = {
    "ffuf": "content_discovery", "feroxbuster": "content_discovery", "content_discovery": "content_discovery",
    "arjun": "param_discovery", "x8": "param_discovery", "param_discovery": "param_discovery",
    "puredns": "dns_bruteforce", "shuffledns": "dns_bruteforce", "alterx": "dns_bruteforce", "dns_bruteforce": "dns_bruteforce",
    "naabu": "port_scanning", "port_scanning": "port_scanning",
    "nuclei_host": "vulnerability_scan", "nuclei_endpoint": "vulnerability_scan",
    "dalfox": "vulnerability_scan", "openredirex": "vulnerability_scan", "vulnerability_scan": "vulnerability_scan",
    "nuclei_tech": "tech_routing", "wpscan": "tech_routing", "tech_routing": "tech_routing",
    "katana": "crawling", "gau": "crawling", "waymore": "crawling", "subjs": "crawling", "crawling": "crawling",
    "js_analysis": "js_analysis", "jsluice": "js_analysis", "xnlinkfinder": "js_analysis", "linkfinder": "js_analysis",
    "uro": "url_merge", "url_merge": "url_merge",
    "gf": "gf",
    "dnsx": "dns_resolution", "dns_resolution": "dns_resolution",
    "httpx": "web_probing", "web_probing": "web_probing",
    "api_surface": "api_surface", "api_surface_detection": "api_surface",
    "subzy": "takeover_crosscheck", "takeover_crosscheck": "takeover_crosscheck",
    "asnmap": "root_expansion", "root_expansion": "root_expansion",
    "gowitness": "screenshots", "screenshots": "screenshots",
    "trufflehog": "secret_scan", "gitleaks": "secret_scan", "secrets": "secret_scan", "secret_scan": "secret_scan",
    "cloud_enum": "cloud_enum", "s3scanner": "cloud_enum",
    "interactsh": "oast", "oast": "oast",
    "subfinder": "subdomain_discovery", "assetfinder": "subdomain_discovery",
    "chaos": "subdomain_discovery", "amass": "subdomain_discovery", "subdomain_discovery": "subdomain_discovery",
}


def _executed_name(value: Any) -> Optional[str]:
    key = str(value or "").strip().lower()
    return PHASE_TIMING_TO_EXECUTED.get(key) or SKIPPED_PHASE_MAP.get(key)


def _record_skipped_phase(
    skipped_phases: List[Dict[str, Any]],
    executed_phases: Set[str],
    phase: str,
    tool: str,
    reason: Any,
) -> None:
    phase_key = str(phase or tool or "unknown").strip()
    tool_key = str(tool or "").strip()
    reason_key = str(reason or "no_eligible_work").strip()
    entry = {"phase": phase_key, "tool": tool_key, "reason": reason_key}
    if entry not in skipped_phases:
        skipped_phases.append(entry)
    exec_name = _executed_name(tool_key) or _executed_name(phase_key)
    if exec_name:
        executed_phases.discard(exec_name)


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
    phase_timings: List[Dict[str, Any]] = []
    skipped_phases: List[Dict[str, Any]] = []
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
            # Phase 8 configuration (per-project with global defaults in app/config)
            "js_analysis": project.get("js_analysis") if project else None,
            "secrets_scan": project.get("secrets_scan") if project else None,
            "cloud_enum": project.get("cloud_enum") if project else None,
            "oast": project.get("oast") if project else None,
            "nuclei_options": project.get("nuclei_options") if project else None,
            "tech_routing": project.get("tech_routing") if project else None,
            "nmap_options": project.get("nmap_options") if project else None,
            "ffuf_options": (project.get("ffuf_options") if project else None) or {"enabled": True, "concurrency": 3, "rate_strategy": "split"},
            "screenshot_options": project.get("screenshot_options") if project else None,
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

            if not event or not isinstance(event, dict):
                continue

            event_type = event.get("type")

            if event_type == "phase_timing":
                phase_name = str(event.get("phase") or "unknown")
                phase_timings.append({
                    "phase": phase_name,
                    "duration_seconds": event.get("duration_seconds", 0),
                })
                exec_name = _executed_name(phase_name)
                if exec_name:
                    executed_phases.add(exec_name)
                skipped_phases[:] = [
                    s for s in skipped_phases
                    if str(s.get("phase") or "").lower() != phase_name.lower()
                    and str(s.get("tool") or "").lower() != phase_name.lower()
                ]
                await manager.broadcast(job_id, event)
                continue

            if "raw_output" in event or event_type == "raw_output":
                t_name = event.get("tool") or event.get("stage") or event.get("provider")
                raw_val = event.get("raw_output") or event.get("output")
                t_name_l = str(t_name or "").strip().lower()
                is_secret_scanner = (
                    t_name_l in SECRET_SCANNER_TOOLS
                    or "trufflehog" in t_name_l
                    or "gitleaks" in t_name_l
                    or "secret" in t_name_l
                )
                if t_name and raw_val and not is_secret_scanner:
                    collected_raw_outputs[str(t_name)] = str(raw_val)
                elif t_name and raw_val:
                    logger.info("Secret-scanner raw output dropped for tool %s", t_name)

            if event_type == "log":
                from app.core.redaction import redact_text as _redact_text
                log_message = _redact_text(str(event.get("message") or ""))
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
                if ("jsluice" in msg_l or "js analysis" in msg_l or "xnlinkfinder" in msg_l) and "tool_missing" not in msg_l and "skipped" not in msg_l:
                    executed_phases.add("js_analysis")
                if ("trufflehog" in msg_l or "gitleaks" in msg_l or "secret scan" in msg_l) and "tool_missing" not in msg_l and "skipped" not in msg_l:
                    executed_phases.add("secret_scan")
                if ("cloud enumeration" in msg_l or "cloud_enum" in msg_l) and "skipped" not in msg_l and "tool_missing" not in msg_l and "opt_in_disabled" not in msg_l:
                    executed_phases.add("cloud_enum")
                if ("oast" in msg_l or "interactsh" in msg_l) and "skipped" not in msg_l and "disabled" not in msg_l:
                    executed_phases.add("oast")
                if ("tech-aware" in msg_l or "wpscan" in msg_l) and "skipped" not in msg_l and "tool_missing" not in msg_l:
                    executed_phases.add("tech_routing")

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
                    "api_spec", "graphql_endpoint", "param", "cloud_bucket", "bucket"
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
                elif asset_type in ("secret", "secret_finding"):
                    executed_phases.add("secret_scan")
                elif asset_type in ("cloud_bucket", "bucket"):
                    executed_phases.add("cloud_enum")
                elif asset_type == "screenshot":
                    executed_phases.add("screenshots")
                elif asset_type == "recon_info":
                    executed_phases.add("vulnerability_scan")
                asset_data["value"] = asset_val
                asset_data["scan_id"] = job_id
                now_dt = datetime.utcnow()
                asset_data["updated_at"] = now_dt

                # Honour provider-level discovered_by; default to provider_name
                if "discovered_by" not in asset_data or not asset_data["discovered_by"]:
                    asset_data["discovered_by"] = provider_name
                # Incoming sources list from UnifiedDiscoveryProvider (may be absent)
                incoming_sources: List[str] = asset_data.pop("sources", [])

                # Passive names are candidates until DNS resolution proves them.
                if asset_type in ("subdomain", "host"):
                    metadata = asset_data.setdefault("metadata", {})
                    status_l = str(asset_data.get("status") or "").strip().lower()
                    has_dns_evidence = bool(
                        status_l in ("live", "resolved")
                        or asset_data.get("resolved_ip")
                        or metadata.get("dnsx")
                        or metadata.get("status_code") is not None
                        or asset_data.get("status_code") is not None
                    )
                    if has_dns_evidence:
                        metadata["passive_candidate"] = False
                    elif status_l in ("", "unknown", "candidate", "passive_candidate"):
                        asset_data["status"] = "candidate"
                        metadata["passive_candidate"] = True
                        metadata["passive_candidate_sources"] = incoming_sources

                # Phase 8 — defence-in-depth: secrets are stored masked only.
                if asset_type in ("secret", "secret_finding"):
                    from app.core.redaction import scrub_secret_metadata
                    asset_data["metadata"] = scrub_secret_metadata(asset_data.get("metadata") or {})
                    for forbidden_key in ("raw", "secret", "match", "secret_value"):
                        asset_data.pop(forbidden_key, None)

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
                    if incoming_status == "candidate" and str(existing.get("status") or "").lower() in ("live", "resolved"):
                        new_status = existing.get("status")
                    elif incoming_status and incoming_status != "unknown":
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
                    run_metadata = dict(broadcast_asset.get("metadata") or {})
                    if broadcast_asset.get("open_ports"):
                        run_metadata["open_ports"] = broadcast_asset["open_ports"]
                    await record_run_asset(
                        db=db,
                        project_id=str(project_id),
                        job_id=str(job_id),
                        asset_type=asset_type,
                        value=asset_val,
                        domain=domain_val,
                        status=broadcast_asset.get("status", "unknown"),
                        metadata=run_metadata,
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
                        if source in (
                            "gau", "linkfinder", "merged", "katana", "waymore",
                            "api_spec", "param_discovery", "js_analysis", "jsluice", "xnlinkfinder",
                        ):
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
                        # Phase 8.1 — preserve hashes, body paths, source maps and
                        # previous hashes for the run-to-run JS diff.
                        incoming_meta = dict(url_data.get("metadata") or {}) if isinstance(url_data.get("metadata"), dict) else {}
                        js_source = str(url_data.get("source") or incoming_meta.get("source") or "subjs")
                        for key in ("hash", "sha256", "content_length", "size", "kind", "body_path", "parent_js", "host"):
                            if url_data.get(key) is not None and key not in incoming_meta:
                                incoming_meta[key] = url_data.get(key)
                        incoming_meta.setdefault("url", url_val)
                        incoming_meta.setdefault("host", url_data.get("host", ""))
                        incoming_meta.setdefault("size", incoming_meta.get("content_length", url_data.get("size", "unknown")))
                        incoming_meta.setdefault("source", js_source)
                        new_hash = incoming_meta.get("hash") or incoming_meta.get("sha256")

                        existing = await db.assets.find_one({
                            "project_id": project_id,
                            "type": "js_file",
                            "$or": [{"value": url_val}, {"domain": url_val}]
                        })
                        if existing:
                            existing_meta = dict(existing.get("metadata") or {})
                            old_hash = existing_meta.get("hash") or existing_meta.get("sha256")
                            if new_hash and old_hash and new_hash != old_hash:
                                existing_meta["previous_hash"] = old_hash
                                existing_meta["previous_sha256"] = old_hash
                            merged_meta = {**existing_meta, **incoming_meta}
                            if new_hash and existing_meta.get("previous_hash"):
                                merged_meta["previous_hash"] = existing_meta["previous_hash"]
                                merged_meta["previous_sha256"] = existing_meta.get("previous_sha256", existing_meta["previous_hash"])
                            await db.assets.update_one(
                                {"_id": existing["_id"]},
                                {"$set": {
                                    "value": url_val,
                                    "scan_id": job_id,
                                    "metadata": merged_meta,
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
                                "metadata": incoming_meta,
                                "discovered_by": js_source,
                                "sources": [js_source],
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
                                metadata=incoming_meta,
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
                if str(event.get("status") or "").upper() == "SKIPPED":
                    provider_label = str(event.get("provider") or "unknown")
                    _record_skipped_phase(
                        skipped_phases,
                        executed_phases,
                        phase=provider_label,
                        tool=provider_label,
                        reason=event.get("reason") or "no_eligible_work",
                    )
                else:
                    provider_label = str(event.get("provider") or "").lower()
                    completed_phase = COMPLETED_SUMMARY_PHASES.get(provider_label)
                    if completed_phase:
                        executed_phases.add(completed_phase)
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
                    if event_type == "stage_skipped":
                        _record_skipped_phase(
                            skipped_phases,
                            executed_phases,
                            phase=str(event.get("stage") or event.get("tool") or "unknown"),
                            tool=str(event.get("tool") or ""),
                            reason=event.get("reason") or "unknown",
                        )
                    tool = str(event.get("tool") or event.get("stage") or "").lower()
                    if tool in ("ffuf", "feroxbuster", "content_discovery"):
                        executed_phases.discard("content_discovery")
                    elif tool in ("api_surface", "api_surface_detection"):
                        executed_phases.discard("api_surface")
                    elif tool in ("arjun", "x8", "param_discovery"):
                        executed_phases.discard("param_discovery")
                    elif tool in ("katana", "gau", "waymore", "subjs", "url_discovery"):
                        executed_phases.discard("url_discovery")
                    elif tool in ("naabu", "port_scanning"):
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
                    elif any(p in tool for p in ("jsluice", "xnlinkfinder", "sourcemapper", "js_analysis")):
                        executed_phases.discard("js_analysis")
                    elif any(p in tool for p in ("trufflehog", "gitleaks", "secrets")):
                        executed_phases.discard("secret_scan")
                    elif any(p in tool for p in ("cloud_enum", "s3scanner")):
                        executed_phases.discard("cloud_enum")
                    elif any(p in tool for p in ("interactsh", "oast")):
                        executed_phases.discard("oast")
                    elif any(p in tool for p in ("wpscan", "tech_routing", "nuclei_tech")):
                        executed_phases.discard("tech_routing")
                await manager.broadcast(job_id, event)
                if event_type == "stage_error":
                    from app.core.redaction import redact_text as _redact_text
                    err_msg = _redact_text(str(
                        event.get("message")
                        or f"[-] Stage error in {event.get('tool') or event.get('stage')}: {event.get('reason') or event.get('error')}"
                    ))
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

        # Save executed/skipped phases and rejected urls to MongoDB job document
        if passive_executed and not passive_killed_or_failed:
            executed_phases.add("subdomain_discovery")
        else:
            executed_phases.discard("subdomain_discovery")

        skipped_keys = {
            str(s.get("phase") or "").strip().lower()
            for s in skipped_phases
        }
        phase_timings = [
            t for t in phase_timings
            if str(t.get("phase") or "").strip().lower() not in skipped_keys
        ]

        await db.jobs.update_one(
            {"_id": ObjectId(job_id)},
            {"$set": {
                "executed_phases": sorted(list(executed_phases)),
                "skipped_phases": skipped_phases,
                "phase_durations": phase_timings,
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
            await db.jobs.update_one(
                {"_id": ObjectId(job_id)},
                {"$set": {
                    "phase_durations": phase_timings,
                    "executed_phases": sorted(list(executed_phases)),
                    "skipped_phases": skipped_phases,
                }},
            )
        except Exception:
            pass
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
    scan_mode: Optional[str] = None,
):
    """Launches one full scan. The legacy ``scan_mode`` query value is accepted
    for backward compatibility but new runs always use the single full pipeline."""
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
        "scan_mode": normalize_scan_mode(scan_mode),
        "job_kind": "full",
        "status": "pending",
        "logs": [],
        "phase_durations": [],
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


# =============================================================================
# Stage 1 — targeted runs on selected hosts
# =============================================================================

class TargetedRunRequest(BaseModel):
    tool: str = Field(
        ...,
        description="ffuf, arjun, naabu, screenshots, js_files or ffuf_arjun",
    )
    hosts: List[str] = Field(default_factory=list)
    port_range: Optional[str] = None
    time_cap_seconds: Optional[int] = None


TARGETED_TOOLS = {"ffuf", "arjun", "naabu", "screenshots", "js_files", "ffuf_arjun"}
TARGETED_URL_ASSET_TYPES = {"content_path", "historical_url", "param"}


def _targeted_rate(project: Dict[str, Any], tool: str) -> int:
    rate_limits = (project or {}).get("rate_limits") or {}
    per_tool = rate_limits.get("per_tool") or {}
    overrides = rate_limits.get("tool_overrides") or {}
    value = overrides.get(tool)
    if value is None:
        value = per_tool.get(tool)
    if value is None:
        value = rate_limits.get("global_rps", 10)
    try:
        return max(1, int(value))
    except (TypeError, ValueError):
        return 10


async def _append_targeted_log(db: Any, job_id: str, message: str) -> None:
    await db.jobs.update_one(
        {"_id": ObjectId(job_id)},
        {"$set": {"heartbeat": datetime.utcnow()}, "$push": {"logs": message}},
    )
    await manager.broadcast(job_id, {"type": "log", "message": message})


async def _persist_targeted_asset(
    db: Any,
    project_id: str,
    job_id: str,
    incoming: Dict[str, Any],
    scope: Dict[str, Any],
) -> Optional[Dict[str, Any]]:
    """Validates, scope-checks and upserts a targeted-run asset."""
    from app.core.scope import is_in_scope, is_valid_url, sanitize_url, validate_hostname
    from app.services.run_history import record_run_asset

    if not isinstance(incoming, dict):
        return None
    asset = dict(incoming)
    asset_type = asset.get("type", "subdomain")
    domain_val = str(asset.get("domain") or "").strip()
    asset_val = str(asset.get("value") or domain_val).strip()
    metadata = dict(asset.get("metadata") or {})

    if asset_type in TARGETED_URL_ASSET_TYPES:
        check_url = sanitize_url(asset_val or metadata.get("url") or "")
        valid, _ = is_valid_url(check_url)
        if not valid:
            return None
        asset_val = check_url
        asset["value"] = check_url
        if "url" in metadata:
            metadata["url"] = check_url
    elif asset_type in ("subdomain", "domain"):
        target_host = domain_val or asset_val
        valid, _ = validate_hostname(target_host)
        if not valid:
            return None
    elif asset_val.startswith(("http://", "https://")):
        check_url = sanitize_url(asset_val)
        valid, _ = is_valid_url(check_url)
        if not valid:
            return None
        asset_val = check_url
        # SubJS (and similar providers) emit the URL only as `domain` +
        # metadata.url. Persist it as `value` too: the unique index is on
        # (project_id, type, value), so a missing value becomes null and the
        # second JS file collides with "null".
        asset["value"] = check_url

    if scope and asset_val and not is_in_scope(asset_val, scope):
        logger.info("[targeted] Dropping out-of-scope asset: %s", asset_val)
        return None

    now_dt = datetime.utcnow()
    asset["project_id"] = project_id
    asset["scan_id"] = job_id
    asset["updated_at"] = now_dt
    sources = list(asset.pop("sources", []) or [])
    asset["metadata"] = metadata

    existing = await db.assets.find_one({
        "project_id": project_id,
        "type": asset_type,
        "$or": [{"value": asset_val}, {"domain": asset_val}],
    })
    if existing:
        merged_metadata = merge_asset_metadata(existing.get("metadata") or {}, metadata)
        merged_sources = sorted(set((existing.get("sources") or []) + sources))
        merged_ports = sorted(set((existing.get("open_ports") or []) + (asset.get("open_ports") or [])))
        update_fields = {
            "value": asset_val,
            "status": asset.get("status") or existing.get("status") or "live",
            "metadata": merged_metadata,
            "sources": merged_sources,
            "open_ports": merged_ports,
            "scan_id": job_id,
            "last_seen": now_dt,
            "updated_at": now_dt,
        }
        if asset.get("services"):
            update_fields["services"] = asset["services"]
        if asset.get("is_interesting") is not None:
            update_fields["is_interesting"] = asset["is_interesting"]
            update_fields["interesting_reason"] = asset.get("interesting_reason")
        if asset.get("status_class"):
            update_fields["status_class"] = asset["status_class"]
        await db.assets.update_one({"_id": existing["_id"]}, {"$set": update_fields})
        stored = {**existing, **update_fields}
    else:
        asset["sources"] = sources
        asset["first_seen"] = now_dt
        asset["last_seen"] = now_dt
        asset["created_at"] = now_dt
        await db.assets.insert_one(asset)
        stored = asset

    run_metadata = dict(stored.get("metadata") or {})
    if stored.get("open_ports"):
        run_metadata["open_ports"] = stored["open_ports"]
    await record_run_asset(
        db=db,
        project_id=str(project_id),
        job_id=str(job_id),
        asset_type=asset_type,
        value=asset_val,
        domain=stored.get("domain") or asset_val,
        status=stored.get("status", "unknown"),
        metadata=run_metadata,
    )
    return stored


async def run_targeted_job(
    job_id: str,
    project_id: str,
    tool: str,
    targets: List[str],
    port_range: Optional[str] = None,
    time_cap_seconds: int = 600,
) -> None:
    """Runs ffuf/arjun/naabu against only the selected hosts."""
    from app.job_control import current_job_id, current_phase, kill_phase_processes
    from app.core.scope import is_in_scope
    from app.providers.naabu_provider import NaabuProvider
    from app.providers.ffuf_provider import FfufProvider
    from app.providers.param_discovery_provider import ParamDiscoveryProvider
    from app.providers.gowitness_provider import GowitnessProvider

    current_job_id.set(job_id)
    live_running_jobs.add(str(job_id))
    db = get_database()
    if db is None:
        live_running_jobs.discard(str(job_id))
        return

    project = await db.projects.find_one({"_id": ObjectId(project_id)}) or {}
    scope = project.get("scope") or {}
    custom_headers = project.get("custom_headers") or {}
    rate_limit = _targeted_rate(project, tool)
    cap = max(1, min(int(time_cap_seconds or 600), 7200))
    phase_label = f"targeted:{tool}"

    executed_phases: Set[str] = set()
    skipped_phases: List[Dict[str, Any]] = []
    stage_markers: List[Dict[str, Any]] = []
    phase_timings: List[Dict[str, Any]] = []
    raw_messages: List[str] = []
    rejected_urls = 0
    counts: Dict[str, int] = {"assets": 0}
    failed = False
    phase_ran = False
    targeted_exec_phase = {
        "ffuf": "content_discovery",
        "arjun": "param_discovery",
        "naabu": "port_scanning",
        "screenshots": "screenshots",
        "js_files": "js_analysis",
        "ffuf_arjun": "content_discovery",
    }.get(tool, tool)

    await db.jobs.update_one(
        {"_id": ObjectId(job_id)},
        {"$set": {
            "status": "running",
            "started_at": datetime.utcnow(),
            "heartbeat": datetime.utcnow(),
            "executed_phases": [],
            "phase_durations": [],
        }},
    )
    await manager.broadcast(job_id, {"type": "status", "status": "running"})
    await _append_targeted_log(
        db, job_id,
        f"[+] Targeted {tool} run started on {len(targets)} selected host(s) (rate {rate_limit}, cap {cap}s).",
    )

    if tool == "ffuf":
        provider = FfufProvider()
        wordlists = project.get("wordlists") or {}
        ffuf_options = dict(project.get("ffuf_options") or {})
        ffuf_options["enabled"] = True
        gen_factory = lambda: provider.discover_content(
            targets,
            scan_mode="fast",
            rate_limit=rate_limit,
            custom_headers=custom_headers,
            scope=scope,
            wordlist_path=wordlists.get("content") or wordlists.get("ffuf"),
            waf_detected_hosts=set(),
            detected_tech_per_host={},
            ffuf_options=ffuf_options,
        )
    elif tool == "arjun":
        provider = ParamDiscoveryProvider()
        gen_factory = lambda: provider.discover(
            targets,
            rate_limit=rate_limit,
            custom_headers=custom_headers,
            scope=scope,
            max_endpoints_to_probe=len(targets),
            per_host_timeout=cap,
        )
    elif tool == "screenshots":
        import os as _os
        from urllib.parse import urlparse as _urlparse
        from app.providers.url_merge import (
            SCREENSHOT_SKIP_EXTENSIONS,
            get_url_priority,
        )

        # Include cloud services discovered from the selected host(s) so their
        # screenshots appear alongside the host in the Screenshots tab.
        target_hosts = sorted({
            (_urlparse(target).hostname or "").lower()
            for target in targets
            if target
        } - {""})
        cloud_targets: List[str] = []
        if target_hosts:
            try:
                from app.services.cloud_classify import classify_cloud_url

                cursor = db.assets.find({
                    "project_id": project_id,
                    "type": "cloud_service",
                    "metadata.parent_hosts": {"$in": target_hosts},
                })
                async for doc in cursor:
                    meta = doc.get("metadata") or {}
                    cloud_url = str(meta.get("url") or doc.get("value") or "").strip()
                    if not cloud_url:
                        continue
                    if scope and not is_in_scope(cloud_url, scope):
                        continue
                    cloud_targets.append(cloud_url)

                # Older scans may not have cloud_service assets yet; inspect
                # the selected hosts' Katana metadata directly as a fallback.
                host_cursor = db.assets.find({
                    "project_id": project_id,
                    "type": {"$in": ["subdomain", "host"]},
                    "domain": {"$in": target_hosts},
                })
                async for host_doc in host_cursor:
                    katana_meta = (host_doc.get("metadata") or {}).get("katana") or {}
                    for key in ("urls", "endpoints", "js_files"):
                        for candidate in katana_meta.get(key) or []:
                            candidate_url = str(candidate or "").strip()
                            if not candidate_url or not classify_cloud_url(candidate_url):
                                continue
                            if scope and not is_in_scope(candidate_url, scope):
                                continue
                            cloud_targets.append(candidate_url)
            except Exception as cloud_exc:
                logger.warning("Cloud screenshot target lookup failed: %s", cloud_exc)
        cloud_targets = list(dict.fromkeys(cloud_targets))
        if cloud_targets:
            targets = list(dict.fromkeys([*targets, *cloud_targets]))

        # Capture parameterised/API endpoints first if the time cap truncates
        # the run. Raw JS/text/media files make useless screenshots and can
        # hang the browser, so they are skipped.
        ordered_targets = sorted(
            targets, key=lambda u: (get_url_priority(u), len(u), u)
        )
        screenshot_targets = [
            url
            for url in ordered_targets
            if _os.path.splitext(_urlparse(url).path.lower())[1]
            not in SCREENSHOT_SKIP_EXTENSIONS
        ]
        static_skipped = len(ordered_targets) - len(screenshot_targets)
        provider = GowitnessProvider()
        shot_cfg = project.get("screenshot_options") or {}

        async def _screenshot_events():
            if cloud_targets:
                yield {
                    "type": "log",
                    "message": (
                        f"[*] Including {len(cloud_targets)} cloud service URL(s) "
                        "related to the selected host(s)."
                    ),
                }
            if static_skipped:
                yield {
                    "type": "log",
                    "message": (
                        f"[*] Skipping {static_skipped} static asset URL(s) "
                        "that would not produce useful screenshots."
                    ),
                }
            async for ev in provider.discover(
                screenshot_targets,
                project_id=project_id,
                job_id=job_id,
                rate_limit=rate_limit,
                per_url_timeout=min(int(shot_cfg.get("per_url_timeout_seconds", 60) or 60), cap),
                concurrency=int(shot_cfg.get("concurrency", 3) or 3),
            ):
                yield ev

        gen_factory = _screenshot_events
    elif tool == "js_files":
        from app.providers.subjs_provider import SubjsProvider

        provider = SubjsProvider()
        gen_factory = lambda: provider.discover(targets)
    elif tool == "ffuf_arjun":
        from urllib.parse import urlparse as _urlparse
        from app.providers.url_merge import get_url_priority

        prioritized_targets = sorted(
            targets, key=lambda u: (get_url_priority(u), len(u), u)
        )
        origins: List[str] = []
        for target in prioritized_targets:
            parsed_target = _urlparse(target)
            if parsed_target.scheme and parsed_target.netloc:
                origin = f"{parsed_target.scheme}://{parsed_target.netloc}"
                if origin not in origins:
                    origins.append(origin)

        async def _ffuf_arjun_combined():
            discovered_body_urls: List[str] = []

            def collect_body_url(event: Dict[str, Any]) -> None:
                if not isinstance(event, dict):
                    return
                if event.get("type") == "content_path_event":
                    url = (event.get("data") or {}).get("url")
                    if url:
                        discovered_body_urls.append(str(url))
                    return
                if event.get("type") != "asset":
                    return
                data = event.get("data") or {}
                if str(data.get("type") or "") not in (
                    "content_path", "api_spec", "graphql_endpoint",
                ):
                    return
                url = data.get("value") or (data.get("metadata") or {}).get("url")
                if url:
                    discovered_body_urls.append(str(url))

            ffuf_provider = FfufProvider()
            ffuf_options = dict(project.get("ffuf_options") or {})
            ffuf_options["enabled"] = True
            wordlists = project.get("wordlists") or {}
            async for ev in ffuf_provider.discover_content(
                origins,
                scan_mode="fast",
                rate_limit=rate_limit,
                custom_headers=custom_headers,
                scope=scope,
                wordlist_path=wordlists.get("content") or wordlists.get("ffuf"),
                waf_detected_hosts=set(),
                detected_tech_per_host={},
                ffuf_options=ffuf_options,
            ):
                collect_body_url(ev)
                yield ev
            arjun_provider = ParamDiscoveryProvider()
            # Probe every extracted URL in priority order; the targeted-run
            # time cap bounds the work for very large hosts.
            arjun_targets = prioritized_targets
            async for ev in arjun_provider.discover(
                arjun_targets,
                rate_limit=rate_limit,
                custom_headers=custom_headers,
                scope=scope,
                max_endpoints_to_probe=len(arjun_targets),
                per_host_timeout=min(cap, 60),
            ):
                yield ev

            if discovered_body_urls:
                auto_limit = max(
                    1, min(int(project.get("body_storage_auto_limit") or 30), 100)
                )
                yield {
                    "type": "log",
                    "message": (
                        f"[*] Fetching response bodies for up to {auto_limit} "
                        "discovered content/API URL(s)..."
                    ),
                }
                try:
                    from app.services.body_fetch import auto_store_bodies

                    store_res = await auto_store_bodies(
                        project_id,
                        list(dict.fromkeys(discovered_body_urls)),
                        scope=scope,
                        max_kb=int(project.get("response_body_max_kb") or 500),
                        limit=auto_limit,
                        concurrency=3,
                        timeout=12,
                    )
                    yield {
                        "type": "log",
                        "message": (
                            f"[+] Body storage: {store_res.get('stored', 0)} stored, "
                            f"{store_res.get('skipped', 0)} skipped, "
                            f"{store_res.get('failed', 0)} failed "
                            f"(of {store_res.get('requested', 0)})."
                        ),
                    }
                except Exception as body_exc:
                    yield {
                        "type": "log",
                        "message": f"[!] Automatic body storage failed: {body_exc} (non-fatal)",
                    }

        gen_factory = _ffuf_arjun_combined
    else:
        provider = NaabuProvider()
        gen_factory = lambda: provider.discover(
            targets,
            rate_limit=rate_limit,
            scan_mode="deep",
            port_range=port_range or project.get("port_range"),
            timeout=cap,
        )

    queue: asyncio.Queue = asyncio.Queue()
    start_mono = time.monotonic()

    async def produce() -> None:
        token = current_phase.set(phase_label)
        try:
            async for ev in gen_factory():
                if isinstance(ev, dict):
                    await queue.put(ev)
        except Exception as exc:
            await queue.put({
                "type": "stage_error",
                "stage": phase_label,
                "tool": tool,
                "error": str(exc),
                "reason": str(exc),
            })
        finally:
            current_phase.reset(token)
            await queue.put(None)

    task = asyncio.create_task(produce())
    deadline = start_mono + cap
    try:
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                killed = kill_phase_processes(phase_label)
                reason = f"time cap ({cap}s) exceeded; killed {killed} process(es)"
                stage_markers.append({"type": "timeout", "stage": phase_label, "tool": tool, "reason": reason})
                await _append_targeted_log(db, job_id, f"[-] Targeted {tool} {reason}. Partial results kept.")
                break
            try:
                event = await asyncio.wait_for(queue.get(), timeout=remaining)
            except asyncio.TimeoutError:
                continue
            if event is None:
                break

            event_type = event.get("type")
            if event_type == "log":
                message = str(event.get("message") or "")
                if message:
                    raw_messages.append(message)
                    await _append_targeted_log(db, job_id, message)
            elif event_type == "asset":
                phase_ran = True
                stored = await _persist_targeted_asset(
                    db, project_id, job_id, event.get("data") or {}, scope
                )
                if stored:
                    counts["assets"] += 1
                    asset_phase_map = {
                        "content_path": "content_discovery",
                        "param": "param_discovery",
                        "screenshot": "screenshots",
                        "js_file": "js_analysis",
                    }
                    executed_phases.add(
                        asset_phase_map.get(str(stored.get("type") or ""), targeted_exec_phase)
                    )
                    await manager.broadcast(job_id, {"type": "asset", "data": serialize_doc(stored)})
            elif event_type == "content_path_event":
                phase_ran = True
                executed_phases.add("content_discovery")
                await manager.broadcast(job_id, event)
            elif event_type == "param_event":
                phase_ran = True
                executed_phases.add("param_discovery")
                await manager.broadcast(job_id, event)
            elif event_type == "url_event":
                url_data = event.get("data") or {}
                url_val = url_data.get("url")
                if url_val and url_data.get("source") == "param_discovery" and is_in_scope(url_val, scope):
                    from urllib.parse import urlparse as _urlparse
                    parsed_u = _urlparse(url_val)
                    stored = await _persist_targeted_asset(
                        db, project_id, job_id,
                        {
                            "domain": parsed_u.hostname or parsed_u.netloc,
                            "type": "historical_url",
                            "value": url_val,
                            "status": "live",
                            "metadata": {"url": url_val, "source": "param_discovery"},
                            "discovered_by": "arjun",
                            "sources": ["param_discovery"],
                        },
                        scope,
                    )
                    if stored:
                        counts["assets"] += 1
                        await manager.broadcast(job_id, {"type": "asset", "data": serialize_doc(stored)})
                await manager.broadcast(job_id, event)
            elif event_type in ("stage_error", "stage_timeout", "stage_skipped", "warning_event"):
                reason = event.get("reason") or event.get("error") or event.get("message") or "unknown"
                stage_markers.append({
                    "type": str(event_type).replace("stage_", ""),
                    "stage": event.get("stage") or event.get("tool") or phase_label,
                    "tool": event.get("tool") or "",
                    "reason": str(reason),
                })
                if event_type == "stage_skipped":
                    _record_skipped_phase(
                        skipped_phases,
                        executed_phases,
                        phase=str(event.get("stage") or event.get("tool") or phase_label),
                        tool=str(event.get("tool") or ""),
                        reason=reason,
                    )
                if event_type in ("stage_error", "stage_timeout"):
                    raw_messages.append(f"{event_type}: {reason}")
                    await _append_targeted_log(db, job_id, f"[-] {phase_label}: {reason}")
                await manager.broadcast(job_id, event)
            elif event_type == "phase_timing":
                phase_timings.append({
                    "phase": event.get("phase") or phase_label,
                    "duration_seconds": event.get("duration_seconds", 0),
                })
                await manager.broadcast(job_id, event)
            elif event_type == "scan_summary":
                if str(event.get("status") or "").upper() == "SKIPPED":
                    _record_skipped_phase(
                        skipped_phases,
                        executed_phases,
                        phase=str(event.get("provider") or tool),
                        tool=str(event.get("provider") or tool),
                        reason=event.get("reason") or "no_eligible_work",
                    )
                else:
                    phase_ran = True
                    provider_phase_map = {
                        "ffuf": "content_discovery",
                        "arjun": "param_discovery",
                        "x8": "param_discovery",
                        "subjs": "js_analysis",
                        "gowitness": "screenshots",
                    }
                    executed_phases.add(
                        provider_phase_map.get(
                            str(event.get("provider") or "").lower(),
                            targeted_exec_phase,
                        )
                    )
                for key in ("count", "findings_found", "confirmed_xss", "confirmed_redirects"):
                    if event.get(key) is not None:
                        try:
                            counts[key] = max(counts.get(key, 0), int(event.get(key)))
                        except (TypeError, ValueError):
                            pass
                await manager.broadcast(job_id, event)
            else:
                await manager.broadcast(job_id, event)
    except Exception as exc:
        failed = True
        logger.error("Targeted %s run failed: %s", tool, exc, exc_info=True)
        stage_markers.append({"type": "error", "stage": phase_label, "tool": tool, "reason": str(exc)})
        await _append_targeted_log(db, job_id, f"[-] Targeted {tool} run failed: {exc}")
    finally:
        if not task.done():
            kill_phase_processes(phase_label)
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)
        duration = round(time.monotonic() - start_mono, 2)
        if phase_ran and not phase_timings:
            phase_timings.append({"phase": targeted_exec_phase, "duration_seconds": duration})
        if phase_ran:
            executed_phases.add(targeted_exec_phase)
        status = "failed" if failed else "completed"
        await db.jobs.update_one(
            {"_id": ObjectId(job_id)},
            {"$set": {
                "status": status,
                "finished_at": datetime.utcnow(),
                "executed_phases": sorted(executed_phases),
                "skipped_phases": skipped_phases,
                "phase_durations": phase_timings,
                "targeted_counts": counts,
                "rejected_urls_count": rejected_urls,
            }},
        )
        await manager.broadcast(job_id, {"type": "status", "status": status})
        await manager.broadcast(job_id, {
            "type": "log",
            "message": f"[{'√' if status == 'completed' else '!'}] Targeted {tool} run {status} in {duration}s.",
        })
        live_running_jobs.discard(str(job_id))
        try:
            from app.services.run_history import record_run_history
            await record_run_history(
                db=db,
                job_id=str(job_id),
                project_id=str(project_id),
                stage_markers=stage_markers,
                raw_outputs={tool: "\n".join(raw_messages)} if raw_messages else None,
            )
        except Exception as rh_err:
            logger.warning("Non-fatal: Failed to record targeted run history for %s: %s", job_id, rh_err)


@router.post("/project/{project_id}/targeted", response_model=JobResponse)
async def launch_targeted_run(
    project_id: str,
    payload: TargetedRunRequest,
    background_tasks: BackgroundTasks,
):
    from app.core.scope import is_in_scope, is_valid_url, sanitize_url, validate_hostname
    from urllib.parse import urlparse as _urlparse

    db = get_database()
    if not ObjectId.is_valid(project_id):
        raise HTTPException(status_code=400, detail="Invalid project ID format")
    project = await db.projects.find_one({"_id": ObjectId(project_id)})
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    tool = str(payload.tool or "").strip().lower()
    if tool not in TARGETED_TOOLS:
        raise HTTPException(
            status_code=400,
            detail=(
                "tool must be one of: "
                + ", ".join(sorted(TARGETED_TOOLS))
            ),
        )

    raw_hosts = list(dict.fromkeys(h.strip() for h in (payload.hosts or []) if isinstance(h, str) and h.strip()))
    if not raw_hosts:
        raise HTTPException(status_code=400, detail="At least one host is required")

    scope = project.get("scope") or {}
    targets: List[str] = []
    for raw_host in raw_hosts:
        if tool == "naabu":
            parsed = _urlparse(raw_host if "://" in raw_host else f"//{raw_host}")
            host = (parsed.hostname or raw_host.split("/")[0].split(":")[0]).strip().lower()
            valid, _ = validate_hostname(host)
            if not valid:
                continue
            if scope and not is_in_scope(host, scope):
                continue
            targets.append(host)
        else:
            url = raw_host if raw_host.startswith(("http://", "https://")) else f"https://{raw_host}"
            url = sanitize_url(url).rstrip("/")
            valid, _ = is_valid_url(url)
            if not valid:
                continue
            if scope and not is_in_scope(url, scope):
                continue
            targets.append(url)

    targets = list(dict.fromkeys(targets))
    if not targets:
        raise HTTPException(status_code=400, detail="No valid in-scope hosts were provided")

    port_range = str(payload.port_range or "").strip() or None
    if port_range and not re.fullmatch(r"[0-9,\-]+", port_range):
        raise HTTPException(status_code=400, detail="port_range may contain only digits, commas and hyphens")
    cap = max(1, min(int(payload.time_cap_seconds or 600), 7200))

    job_dict = {
        "project_id": project_id,
        "provider_name": f"Targeted {tool}",
        "scan_mode": "targeted",
        "job_kind": "targeted",
        "targeted": {
            "tool": tool,
            "hosts": targets,
            "port_range": port_range,
            "time_cap_seconds": cap,
        },
        "status": "pending",
        "logs": [f"[+] Targeted {tool} run queued for {len(targets)} selected host(s)."],
        "executed_phases": [],
        "phase_durations": [],
        "liveness_version": 2,
        "started_at": datetime.utcnow(),
        "finished_at": None,
    }
    result = await db.jobs.insert_one(job_dict)
    job_id = str(result.inserted_id)
    job_dict["_id"] = result.inserted_id

    background_tasks.add_task(
        run_targeted_job,
        job_id,
        project_id,
        tool,
        targets,
        port_range,
        cap,
    )
    return serialize_doc(job_dict)
