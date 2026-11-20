from fastapi import APIRouter, Body, HTTPException, Query
from fastapi.responses import FileResponse
from bson import ObjectId
from datetime import datetime
from typing import List, Dict, Any, Optional
from urllib.parse import urlparse
import logging
import os

from app.database import get_database
from app.models import AssetResponse, serialize_doc
from app.providers.url_merge import get_url_priority
from app.services.asset_counts import collect_counts
from app.services.screenshot_storage import resolve_screenshot_file

logger = logging.getLogger("reconforge.assets")
router = APIRouter(prefix="/assets", tags=["Assets"])

UNIFIED_PROVIDERS = ["subfinder", "assetfinder", "amass", "chaos"]


@router.get("/project/{project_id}", response_model=List[AssetResponse])
async def get_project_assets(
    project_id: str,
    type: Optional[str] = Query(None),
    limit: Optional[int] = Query(None),
):
    db = get_database()
    if not ObjectId.is_valid(project_id):
        raise HTTPException(status_code=400, detail="Invalid project ID format")

    project = await db.projects.find_one({
        "_id": ObjectId(project_id),
    })
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    query: Dict[str, Any] = {"project_id": project_id}
    if type:
        query["type"] = type

    cursor = db.assets.find(query)
    if not type:
        # Prioritize core assets (subdomain, domain, live hosts) over raw historical URLs
        cursor = cursor.sort([("type", -1), ("status", -1), ("hunt_priority", -1)])

    max_len = limit if (limit and limit > 0) else 10000
    assets = await cursor.to_list(length=max_len)
    return serialize_doc(assets)


HOST_URL_ASSET_TYPES = {
    "content_path", "historical_url", "gf_url", "uro_url",
    "api_spec", "graphql_endpoint", "param", "js_file",
}


def _normalise_host(value: str) -> str:
    """Extracts a lowercase hostname from a bare host or a full URL."""
    raw = str(value or "").strip()
    if not raw:
        return ""
    parsed = urlparse(raw if "://" in raw else f"//{raw}")
    return (parsed.hostname or "").lower()


@router.get("/project/{project_id}/live-hosts")
async def get_project_live_hosts(project_id: str):
    """Lists HTTP-live hosts independently of the paginated asset feed.

    DNS can contain resolved-only records that cannot be screenshotted, so
    this endpoint returns only hosts HTTPX marked live plus the DNS record
    count for context.
    """
    db = get_database()
    if not ObjectId.is_valid(project_id):
        raise HTTPException(status_code=400, detail="Invalid project ID format")
    project = await db.projects.find_one({"_id": ObjectId(project_id)})
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    cursor = db.assets.find({
        "project_id": project_id,
        "type": {"$in": ["subdomain", "host"]},
        "status": "live",
    }).sort([("hunt_priority", -1), ("domain", 1)])
    assets = await cursor.to_list(length=5000)

    hosts: List[Dict[str, Any]] = []
    seen = set()
    for asset in assets:
        host = str(asset.get("domain") or "").strip().lower()
        if not host or host in seen:
            continue
        meta = asset.get("metadata") or {}
        url = str(meta.get("url") or "")
        if not url.startswith(("http://", "https://")):
            url = f"https://{host}"
        seen.add(host)
        hosts.append({
            "host": host,
            "url": url,
            "title": str(meta.get("title") or ""),
            "status_code": meta.get("status_code"),
        })

    dns_record_count = await db.assets.count_documents({
        "project_id": project_id,
        "metadata.dnsx": {"$exists": True},
    })
    return {
        "hosts": hosts,
        "dns_record_count": dns_record_count,
    }


@router.get("/project/{project_id}/api-endpoints")
async def get_project_api_endpoints(
    project_id: str,
    limit: int = Query(5000, ge=1, le=20000),
):
    """Lists API links/paths, including dynamically classified URL assets.

    Explicit API discovery assets (api_spec/graphql_endpoint/api_endpoint) are
    merged with API-looking URLs from the URL inventory so newly discovered
    FFUF/historical URLs show up without waiting for another full scan.
    """
    db = get_database()
    if db is None:
        raise HTTPException(status_code=500, detail="Database unavailable")
    if not ObjectId.is_valid(project_id):
        raise HTTPException(status_code=400, detail="Invalid project ID format")
    project = await db.projects.find_one({"_id": ObjectId(project_id)})
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    from app.services.api_classify import classify_api_url

    explicit_types = {"api_endpoint", "api_spec", "graphql_endpoint"}
    dynamic_types = {"content_path", "historical_url", "gf_url", "uro_url", "param"}
    cursor = db.assets.find({
        "project_id": project_id,
        "type": {"$in": sorted(explicit_types | dynamic_types)},
    })
    docs = await cursor.to_list(length=limit)

    items_by_url: Dict[str, Dict[str, Any]] = {}
    explicit_urls = set()
    for doc in docs:
        asset_type = str(doc.get("type") or "").lower()
        meta = doc.get("metadata") or {}

        if asset_type == "param":
            # Arjun/x8 parameter assets store the endpoint in metadata.endpoint
            # and the parameter name in metadata.param_name.
            endpoint_url = str(
                meta.get("endpoint") or meta.get("url") or doc.get("value") or ""
            ).split("?", 1)[0].strip()
            parsed_param = classify_api_url(endpoint_url)
            if not parsed_param:
                continue
            param_name = str(meta.get("param_name") or meta.get("param") or "").strip()
            existing = items_by_url.get(endpoint_url)
            if not existing:
                parsed_param.update({
                    "parent_host": str(meta.get("host") or ""),
                    "source": str(meta.get("source") or "param_discovery"),
                    "asset_id": str(doc.get("_id")),
                    "asset_type": asset_type,
                })
                items_by_url[endpoint_url] = parsed_param
                existing = parsed_param
            if param_name:
                params = set(existing.get("params") or [])
                params.add(param_name)
                existing["params"] = sorted(params)
                existing["has_params"] = True
            continue

        url = str(meta.get("url") or doc.get("value") or doc.get("domain") or "").strip()
        if not url.startswith(("http://", "https://")):
            continue

        if asset_type in explicit_types:
            if asset_type == "graphql_endpoint":
                api_type = "graphql"
            elif asset_type == "api_spec":
                fmt = str(meta.get("format") or "").lower()
                api_type = "openapi" if "openapi" in fmt else ("swagger" if "swagger" in fmt else "api-spec")
            else:
                api_type = str(meta.get("api_type") or "api")
            info = {
                "url": url,
                "host": str(meta.get("host") or urlparse(url).hostname or "").lower(),
                "path": str(meta.get("path") or urlparse(url).path or "/"),
                "api_type": api_type,
                "has_params": bool(meta.get("has_params") or urlparse(url).query),
                "params": list(meta.get("params") or []),
                "parent_host": str(meta.get("parent_host") or ""),
                "source": str(meta.get("source") or asset_type),
                "asset_id": str(doc.get("_id")),
                "asset_type": asset_type,
            }
            previous = items_by_url.get(url)
            if previous:
                merged_params = sorted(
                    set(info.get("params") or []) | set(previous.get("params") or [])
                )
                info["params"] = merged_params
                info["has_params"] = bool(
                    info.get("has_params")
                    or previous.get("has_params")
                    or merged_params
                )
            items_by_url[url] = info
            explicit_urls.add(url)
            continue

        parsed = classify_api_url(url)
        if not parsed:
            continue

        if url in items_by_url:
            continue
        parsed.update({
            "parent_host": str(meta.get("parent_host") or ""),
            "source": str(meta.get("source") or doc.get("discovered_by") or asset_type),
            "asset_id": str(doc.get("_id")),
            "asset_type": asset_type,
        })
        items_by_url[url] = parsed

    items = sorted(items_by_url.values(), key=lambda item: (item["host"], item["path"], item["url"]))
    by_type: Dict[str, int] = {}
    for item in items:
        api_type = str(item.get("api_type") or "api")
        by_type[api_type] = by_type.get(api_type, 0) + 1

    return {
        "items": items,
        "total": len(items),
        "by_type": by_type,
    }


@router.get("/project/{project_id}/cloud-services")
async def get_project_cloud_services(
    project_id: str,
    limit: int = Query(5000, ge=1, le=20000),
):
    """Lists detected cloud service URLs and bucket candidates."""
    db = get_database()
    if db is None:
        raise HTTPException(status_code=500, detail="Database unavailable")
    if not ObjectId.is_valid(project_id):
        raise HTTPException(status_code=400, detail="Invalid project ID format")
    project = await db.projects.find_one({"_id": ObjectId(project_id)})
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    cursor = db.assets.find({
        "project_id": project_id,
        "type": {"$in": ["cloud_service", "bucket", "cloud_bucket"]},
    }).sort([("metadata.provider", 1), ("value", 1)])
    docs = await cursor.to_list(length=limit)

    providers: Dict[str, int] = {}
    for doc in docs:
        provider = str((doc.get("metadata") or {}).get("provider") or "unknown").lower()
        providers[provider] = providers.get(provider, 0) + 1

    return {
        "items": serialize_doc(docs),
        "total": len(docs),
        "providers": providers,
    }


@router.get("/project/{project_id}/host-urls")
async def get_project_host_urls(project_id: str, host: str = Query(...)):
    """Returns every URL extracted for one host, highest-priority first.

    Used by the inventory's extracted-URL action panel so targeted
    screenshots / JS discovery / FFUF+Arjun cover the complete URL set that
    belongs to the selected host, not just what the current page has loaded.
    """
    db = get_database()
    if not ObjectId.is_valid(project_id):
        raise HTTPException(status_code=400, detail="Invalid project ID format")

    project = await db.projects.find_one({"_id": ObjectId(project_id)})
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    hostname = _normalise_host(host)
    if not hostname:
        raise HTTPException(status_code=400, detail="A valid host is required")

    cursor = db.assets.find({"project_id": project_id})
    assets = await cursor.to_list(length=10000)
    urls: set = set()

    def add_url(value: Any) -> None:
        url = str(value or "").strip()
        if not url.startswith(("http://", "https://")):
            return
        try:
            parsed = urlparse(url)
        except Exception:
            return
        if (parsed.hostname or "").lower() != hostname:
            return
        urls.add(url)

    for asset in assets:
        asset_type = str(asset.get("type") or "").lower()
        meta = asset.get("metadata") or {}

        if asset_type in ("subdomain", "host"):
            if str(asset.get("domain") or "").lower() == hostname:
                add_url(meta.get("url"))
                katana = meta.get("katana") or {}
                for key in ("urls", "endpoints", "js_files"):
                    for url in katana.get(key) or []:
                        add_url(url)
            continue

        if asset_type not in HOST_URL_ASSET_TYPES:
            continue
        add_url(meta.get("url") or asset.get("value") or asset.get("domain"))

    ordered_urls = sorted(
        urls, key=lambda url: (get_url_priority(url), len(url), url)
    )
    return {"host": hostname, "count": len(ordered_urls), "urls": ordered_urls}


@router.post("/project/{project_id}/fetch-body")
async def fetch_project_body(
    project_id: str,
    payload: Dict[str, Any] = Body(...),
):
    """Fetches one URL and stores its capped response body + metadata.

    On-demand only: any status is stored (subject to the project's
    response_body_max_kb cap). Reuses the cached body unless ``force`` is set.
    """
    db = get_database()
    if db is None:
        raise HTTPException(status_code=500, detail="Database unavailable")
    if not ObjectId.is_valid(project_id):
        raise HTTPException(status_code=400, detail="Invalid project ID format")
    project = await db.projects.find_one({"_id": ObjectId(project_id)})
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    url = str(payload.get("url") or "").strip()
    if not url:
        raise HTTPException(status_code=400, detail="url is required")

    from app.services.body_fetch import fetch_and_store

    result = await fetch_and_store(
        project_id,
        url,
        scope=project.get("scope") or None,
        max_kb=int(project.get("response_body_max_kb") or 500),
        force=bool(payload.get("force")),
    )
    if not result.get("ok"):
        raise HTTPException(status_code=400, detail=result.get("error") or "body fetch failed")
    return result


@router.get("/project/{project_id}/subdomains")
async def get_project_subdomains(
    project_id: str,
    limit: Optional[int] = Query(None),
):
    """Returns all subdomain assets with source attribution and timestamps."""
    db = get_database()
    if not ObjectId.is_valid(project_id):
        raise HTTPException(status_code=400, detail="Invalid project ID format")

    project = await db.projects.find_one({
        "_id": ObjectId(project_id),
    })
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    cursor = db.assets.find({"project_id": project_id, "type": "subdomain"}).sort(
        [("status", -1), ("hunt_priority", -1)]
    )
    max_len = limit if (limit and limit > 0) else 10000
    assets = await cursor.to_list(length=max_len)
    return serialize_doc(assets)


@router.get("/project/{project_id}/dns")
async def get_project_dns(project_id: str):
    """Returns all resolved DNS records for the project's assets."""
    db = get_database()
    if not ObjectId.is_valid(project_id):
        raise HTTPException(status_code=400, detail="Invalid project ID format")

    project = await db.projects.find_one({"_id": ObjectId(project_id)})
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    cursor = db.assets.find(
        {"project_id": project_id, "metadata.dnsx": {"$exists": True}},
        {"domain": 1, "status": 1, "metadata.dnsx": 1}
    )
    docs = await cursor.to_list(length=10000)
    records = []
    for d in docs:
        dnsx = (d.get("metadata") or {}).get("dnsx") or {}
        records.append({
            "subdomain": d.get("domain", ""),
            "status": d.get("status", "resolved"),
            "ipv4": dnsx.get("a", []),
            "ipv6": dnsx.get("aaaa", []),
            "cname": dnsx.get("cname", []),
            "resolved_at": dnsx.get("resolved_at"),
        })
    return records


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
    canonical_counts = await collect_counts(db.assets, project_id)
    subdomains_count = canonical_counts["resolved_hosts"]
    live_hosts = canonical_counts["live_hosts"]

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
        "resolved_hosts": canonical_counts["resolved_hosts"],
        "passive_candidates": canonical_counts["passive_candidates"],
        "live_hosts": live_hosts,
        "urls_total": canonical_counts["urls_total"],
        "urls": canonical_counts["urls"],
        "open_ports_count": total_open_ports,
        "last_scan_time": last_scan_time,
        "ports_distribution": [{"port": item["_id"], "count": item["count"]} for item in ports_distribution],
        "sources_distribution": sources_data,
        "provider_counts": provider_counts,
    }


@router.get("/project/{project_id}/screenshots")
async def get_project_screenshots(
    project_id: str,
    job_id: Optional[str] = Query(None),
    limit: int = Query(500, ge=1, le=2000),
):
    """Lists per-run screenshot assets and available runs for the selector."""
    db = get_database()
    if db is None:
        raise HTTPException(status_code=500, detail="Database unavailable")
    if not ObjectId.is_valid(project_id):
        raise HTTPException(status_code=400, detail="Invalid project ID format")
    project = await db.projects.find_one({"_id": ObjectId(project_id)})
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    pipeline = [
        {"$match": {"project_id": project_id, "type": "screenshot"}},
        {"$group": {
            "_id": "$job_id",
            "count": {"$sum": 1},
            "last_recorded": {"$max": "$recorded_at"},
        }},
    ]
    run_groups = await db.run_assets.aggregate(pipeline).to_list(500)
    run_ids = [g["_id"] for g in run_groups if g.get("_id")]
    job_map: Dict[str, Any] = {}
    object_ids = [ObjectId(j) for j in run_ids if ObjectId.is_valid(j)]
    if object_ids:
        async for job in db.jobs.find({"_id": {"$in": object_ids}}):
            job_map[str(job["_id"])] = job

    runs = []
    for group in run_groups:
        rid = str(group.get("_id") or "")
        if not rid:
            continue
        job = job_map.get(rid) or {}
        started = job.get("started_at") or group.get("last_recorded") or job.get("finished_at")
        runs.append({
            "job_id": rid,
            "started_at": started.isoformat() if isinstance(started, datetime) else (str(started) if started else None),
            "status": job.get("status") or "unknown",
            "count": int(group.get("count") or 0),
        })
    runs.sort(key=lambda r: r.get("started_at") or "", reverse=True)

    selected = job_id if job_id and any(r["job_id"] == job_id for r in runs) else (runs[0]["job_id"] if runs else None)
    previous_hashes: Dict[str, str] = {}
    if selected:
        selected_index = next((i for i, r in enumerate(runs) if r["job_id"] == selected), -1)
        if selected_index >= 0 and selected_index + 1 < len(runs):
            prev_job = runs[selected_index + 1]["job_id"]
            prev_cursor = db.run_assets.find({
                "project_id": project_id,
                "job_id": prev_job,
                "type": "screenshot",
            })
            async for prev_doc in prev_cursor:
                pmeta = prev_doc.get("metadata") or {}
                purl = pmeta.get("url") or prev_doc.get("value") or ""
                if purl:
                    previous_hashes[purl] = pmeta.get("page_hash") or pmeta.get("screenshot_hash") or ""

    items: List[Dict[str, Any]] = []
    if selected:
        cursor = db.run_assets.find({
            "project_id": project_id,
            "job_id": selected,
            "type": "screenshot",
        }).sort("recorded_at", 1).limit(limit)
        docs = await cursor.to_list(length=limit)
        for doc in docs:
            meta = doc.get("metadata") or {}
            path = str(meta.get("screenshot_path") or "")
            filename = str(meta.get("filename") or os.path.basename(path))
            first_seen = meta.get("first_seen") or doc.get("recorded_at")
            last_seen = meta.get("last_seen") or doc.get("recorded_at")
            shot_url = meta.get("url") or doc.get("value") or ""
            page_hash = meta.get("page_hash") or meta.get("screenshot_hash") or ""
            previous_hash = previous_hashes.get(shot_url, "")
            items.append({
                "job_id": selected,
                "url": shot_url,
                "host": meta.get("host") or doc.get("domain") or "",
                "title": meta.get("title") or "",
                "filename": filename,
                "path": path,
                "size": meta.get("size", 0),
                "page_hash": page_hash,
                "previous_page_hash": previous_hash,
                "changed": bool(previous_hash and page_hash and previous_hash != page_hash),
                "first_seen": first_seen.isoformat() if isinstance(first_seen, datetime) else first_seen,
                "last_seen": last_seen.isoformat() if isinstance(last_seen, datetime) else last_seen,
                "image_url": (
                    f"/api/v1/assets/project/{project_id}/screenshots/{selected}/{filename}"
                    if filename else ""
                ),
            })

    return {
        "runs": runs,
        "selected_job_id": selected,
        "items": items,
        "total": len(items),
    }


@router.get("/project/{project_id}/screenshots/{job_id}/{filename}")
async def serve_screenshot(project_id: str, job_id: str, filename: str):
    """Serves a PNG only if it resolves inside the project/job screenshot dir."""
    db = get_database()
    if db is None:
        raise HTTPException(status_code=500, detail="Database unavailable")
    if not ObjectId.is_valid(project_id):
        raise HTTPException(status_code=400, detail="Invalid project ID format")
    project = await db.projects.find_one({"_id": ObjectId(project_id)})
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    safe_path = resolve_screenshot_file(project_id, job_id, filename)
    if not safe_path:
        raise HTTPException(status_code=404, detail="Screenshot not found")
    return FileResponse(safe_path, media_type="image/png")


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

