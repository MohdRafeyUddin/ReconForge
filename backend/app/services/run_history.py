"""
Run History Service
===================
Manages historical scan run records, per-run asset memberships, raw tool output
gzip storage with path traversal protection, and run comparison.
"""

import gzip
import logging
import os
import re
from datetime import datetime
from typing import Any, Dict, List, Optional, Set, Tuple
from bson import ObjectId

logger = logging.getLogger("reconforge.run_history")

RUNS_BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "storage", "runs"))
MAX_RAW_FILE_KB = 5120  # 5 MB size cap per raw output file


def _sanitize_path_component(comp: str) -> str:
    """Sanitizes path components to prevent path traversal."""
    if not comp:
        raise ValueError("Path component cannot be empty")
    # Reject directory traversal attempts
    if ".." in comp or "/" in comp or "\\" in comp:
        raise ValueError(f"Path traversal detected in component: {comp}")
    clean = re.sub(r"[^a-zA-Z0-9_\-\.]", "_", comp)
    return clean


def get_run_storage_dir(project_id: str, job_id: str) -> str:
    """Returns absolute directory path for a run, strictly validated against RUNS_BASE_DIR."""
    safe_proj = _sanitize_path_component(str(project_id))
    safe_job = _sanitize_path_component(str(job_id))
    target_dir = os.path.abspath(os.path.join(RUNS_BASE_DIR, safe_proj, safe_job))
    if not target_dir.startswith(RUNS_BASE_DIR):
        raise ValueError(f"Directory path traversal detected: {target_dir}")
    os.makedirs(target_dir, exist_ok=True)
    return target_dir


def save_raw_tool_output(
    project_id: str,
    job_id: str,
    tool_name: str,
    raw_content: str,
    max_kb: int = MAX_RAW_FILE_KB,
) -> Optional[str]:
    """
    Saves a tool's raw output compressed with gzip under:
    backend/storage/runs/{project_id}/{job_id}/{tool}.txt.gz
    Applies size cap and path traversal protection.
    Never stores credentials or headers.
    """
    try:
        if not raw_content:
            return None
        safe_tool = _sanitize_path_component(tool_name.lower())
        run_dir = get_run_storage_dir(project_id, job_id)
        file_path = os.path.join(run_dir, f"{safe_tool}.txt.gz")

        # Redact any authorization tokens or secret patterns from raw content before storing
        redacted = re.sub(r"(?i)bearer\s+[a-zA-Z0-9_\-\.]{15,}", "Bearer [REDACTED]", raw_content)
        redacted = re.sub(r"(?i)(token|api_key|secret)=([a-zA-Z0-9_\-]{8,})", r"\1=[REDACTED]", redacted)

        data_bytes = redacted.encode("utf-8")
        max_bytes = max_kb * 1024
        if len(data_bytes) > max_bytes:
            data_bytes = data_bytes[:max_bytes]

        compressed = gzip.compress(data_bytes)
        with open(file_path, "wb") as f:
            f.write(compressed)

        logger.info(f"Saved raw output for {tool_name} ({len(compressed)} bytes gzipped) -> {file_path}")
        return file_path
    except Exception as e:
        logger.error(f"Failed to save raw output for {tool_name}: {e}")
        return None


def read_raw_tool_output(project_id: str, job_id: str, tool_name: str) -> Optional[str]:
    """Reads and decompresses stored raw tool output with strict traversal guard."""
    try:
        safe_tool = _sanitize_path_component(tool_name.lower())
        run_dir = get_run_storage_dir(project_id, job_id)
        file_path = os.path.join(run_dir, f"{safe_tool}.txt.gz")
        if not os.path.exists(file_path):
            return None
        with open(file_path, "rb") as f:
            compressed = f.read()
        return gzip.decompress(compressed).decode("utf-8", errors="replace")
    except Exception as e:
        logger.error(f"Failed to read raw output for {tool_name}: {e}")
        return None


async def record_run_asset(
    db: Any,
    project_id: str,
    job_id: str,
    asset_type: str,
    value: str,
    domain: str = "",
    status: str = "unknown",
    metadata: Optional[Dict[str, Any]] = None,
) -> None:
    """Records an asset seen during a specific run in the run_assets collection."""
    try:
        if db is None or not project_id or not job_id or not value:
            return
        doc = {
            "project_id": str(project_id),
            "job_id": str(job_id),
            "type": str(asset_type),
            "value": str(value),
            "domain": str(domain or value),
            "status": str(status),
            "metadata": metadata or {},
            "recorded_at": datetime.utcnow(),
        }
        await db.run_assets.update_one(
            {
                "project_id": str(project_id),
                "job_id": str(job_id),
                "type": str(asset_type),
                "value": str(value),
            },
            {"$set": doc},
            upsert=True,
        )
    except Exception as e:
        logger.warning(f"Non-fatal: Failed to record run asset ({asset_type}:{value}): {e}")


async def record_run_history(
    db: Any,
    job_id: str,
    project_id: str,
    tool_versions: Optional[Dict[str, str]] = None,
    stage_markers: Optional[List[Dict[str, Any]]] = None,
    raw_outputs: Optional[Dict[str, str]] = None,
) -> Optional[Dict[str, Any]]:
    """
    Saves or updates a completed/interrupted/failed run document in `scan_runs`.
    A failure while writing history must never fail the scan.
    """
    try:
        if db is None:
            return None

        # 1. Fetch job document
        job = await db.jobs.find_one({"_id": ObjectId(job_id) if ObjectId.is_valid(job_id) else job_id})
        if not job:
            logger.warning(f"Cannot record run history: job {job_id} not found")
            return None

        # 2. Fetch project document for config snapshot
        project = await db.projects.find_one({"_id": ObjectId(project_id) if ObjectId.is_valid(project_id) else project_id}) or {}

        # 3. Calculate timing & duration
        started_at = job.get("started_at")
        finished_at = job.get("finished_at") or datetime.utcnow()
        duration_sec = 0.0
        if started_at and finished_at:
            duration_sec = max(0.0, (finished_at - started_at).total_seconds())

        status = job.get("status", "completed")
        scan_mode = job.get("scan_mode", "fast")
        scan_profile = project.get("scan_profile", "recon")

        # 4. Config Snapshot: Header NAMES only, never secret values
        custom_headers = project.get("custom_headers") or {}
        custom_header_names = list(custom_headers.keys())

        config_snapshot = {
            "scope": project.get("scope") or {"in_scope": [], "out_of_scope": []},
            "rate_limits": project.get("rate_limits") or {},
            "custom_header_names": custom_header_names,
            "scan_profile": scan_profile,
            "port_range": project.get("port_range") or "1-10000",
            "assume_tools_installed": project.get("assume_tools_installed", True),
        }

        # 5. Extract counts from assets and job logs
        # Count per-type from run_assets if populated, else fallback to db.assets
        run_asset_counts: Dict[str, int] = {}
        try:
            pipeline = [
                {"$match": {"project_id": str(project_id), "job_id": str(job_id)}},
                {"$group": {"_id": "$type", "count": {"$sum": 1}}},
            ]
            async for doc in db.run_assets.aggregate(pipeline):
                run_asset_counts[doc["_id"]] = doc["count"]
        except Exception:
            pass

        # Calculate counts
        subdomains_count = run_asset_counts.get("subdomain", 0)
        live_count = await db.run_assets.count_documents({
            "project_id": str(project_id),
            "job_id": str(job_id),
            "status": "live",
        }) if run_asset_counts else 0

        # Ports count
        open_ports_count = 0
        try:
            live_cursor = db.run_assets.find({
                "project_id": str(project_id),
                "job_id": str(job_id),
                "status": "live",
            })
            async for l_doc in live_cursor:
                meta = l_doc.get("metadata") or {}
                ports = meta.get("open_ports") or l_doc.get("open_ports") or []
                open_ports_count += len(ports)
        except Exception:
            pass

        # Stage markers extraction from logs if not passed
        markers = list(stage_markers or [])
        if not markers:
            for log in job.get("logs", []):
                log_s = str(log)
                if "skipped" in log_s.lower():
                    markers.append({"type": "skipped", "message": log_s})
                elif "timed out" in log_s.lower():
                    markers.append({"type": "timeout", "message": log_s})
                elif "error" in log_s.lower() or "failed" in log_s.lower():
                    markers.append({"type": "error", "message": log_s})

        # Save raw outputs if provided
        raw_output_paths: Dict[str, str] = {}
        if raw_outputs:
            for tool, out_content in raw_outputs.items():
                p = save_raw_tool_output(str(project_id), str(job_id), tool, out_content)
                if p:
                    raw_output_paths[tool] = p

        counts_summary = {
            "subdomains": subdomains_count,
            "resolved": run_asset_counts.get("subdomain", 0),
            "live": live_count,
            "ports": open_ports_count,
            "content_paths": run_asset_counts.get("content_path", 0),
            "params": run_asset_counts.get("param", 0),
            "findings": run_asset_counts.get("finding", 0),
            "api_specs": run_asset_counts.get("api_spec", 0),
            "graphql_endpoints": run_asset_counts.get("graphql_endpoint", 0),
            "js_files": run_asset_counts.get("js_file", 0),
            "rejected_urls": job.get("rejected_urls_count", 0),
            "urls_by_source": {
                "katana": run_asset_counts.get("katana_url", 0),
                "gau": run_asset_counts.get("historical_url", 0),
                "uro": run_asset_counts.get("uro_url", 0),
                "gf": run_asset_counts.get("gf_url", 0),
            },
        }

        # Build scan_runs document
        run_doc = {
            "job_id": str(job_id),
            "project_id": str(project_id),
            "started_at": started_at,
            "finished_at": finished_at,
            "duration_sec": round(duration_sec, 2),
            "status": status,
            "scan_mode": scan_mode,
            "scan_profile": scan_profile,
            "executed_phases": job.get("executed_phases", []),
            "stage_markers": markers,
            "counts": counts_summary,
            "tool_versions": tool_versions or {},
            "config_snapshot": config_snapshot,
            "raw_output_paths": raw_output_paths,
            "created_at": datetime.utcnow(),
        }

        await db.scan_runs.update_one(
            {"job_id": str(job_id)},
            {"$set": run_doc},
            upsert=True,
        )
        logger.info(f"Recorded scan run history for job {job_id} (status: {status}, duration: {duration_sec:.1f}s)")
        return run_doc

    except Exception as e:
        logger.error(f"Non-fatal: Failed to record run history for job {job_id}: {e}", exc_info=True)
        return None


async def compare_runs(
    db: Any,
    project_id: str,
    job_a_id: str,
    job_b_id: str,
) -> Dict[str, Any]:
    """
    Compares two historical scan runs using `run_assets`.
    Returns added and removed items per asset type, plus summary counts.
    """
    if db is None:
        raise ValueError("Database unavailable")

    run_a = await db.scan_runs.find_one({"job_id": str(job_a_id), "project_id": str(project_id)})
    run_b = await db.scan_runs.find_one({"job_id": str(job_b_id), "project_id": str(project_id)})

    cursor_a = db.run_assets.find({"project_id": str(project_id), "job_id": str(job_a_id)})
    assets_a = await cursor_a.to_list(length=50000)

    cursor_b = db.run_assets.find({"project_id": str(project_id), "job_id": str(job_b_id)})
    assets_b = await cursor_b.to_list(length=50000)

    # Group by type -> set of values
    grouped_a: Dict[str, Dict[str, Dict[str, Any]]] = {}
    for a in assets_a:
        t = a.get("type", "unknown")
        val = a.get("value", "")
        if t not in grouped_a:
            grouped_a[t] = {}
        grouped_a[t][val] = a

    grouped_b: Dict[str, Dict[str, Dict[str, Any]]] = {}
    for b in assets_b:
        t = b.get("type", "unknown")
        val = b.get("value", "")
        if t not in grouped_b:
            grouped_b[t] = {}
        grouped_b[t][val] = b

    all_types = sorted(list(set(grouped_a.keys()) | set(grouped_b.keys())))

    comparison: Dict[str, Any] = {}
    total_added = 0
    total_removed = 0
    total_retained = 0

    for t in all_types:
        vals_a = set(grouped_a.get(t, {}).keys())
        vals_b = set(grouped_b.get(t, {}).keys())

        added_vals = sorted(list(vals_b - vals_a))
        removed_vals = sorted(list(vals_a - vals_b))
        retained_vals = sorted(list(vals_a & vals_b))

        total_added += len(added_vals)
        total_removed += len(removed_vals)
        total_retained += len(retained_vals)

        comparison[t] = {
            "added_count": len(added_vals),
            "removed_count": len(removed_vals),
            "retained_count": len(retained_vals),
            "added": added_vals,
            "removed": removed_vals,
        }

    return {
        "project_id": str(project_id),
        "job_a": str(job_a_id),
        "job_b": str(job_b_id),
        "run_a_meta": {
            "started_at": run_a.get("started_at") if run_a else None,
            "scan_mode": run_a.get("scan_mode") if run_a else None,
            "status": run_a.get("status") if run_a else None,
        },
        "run_b_meta": {
            "started_at": run_b.get("started_at") if run_b else None,
            "scan_mode": run_b.get("scan_mode") if run_b else None,
            "status": run_b.get("status") if run_b else None,
        },
        "summary": {
            "total_added": total_added,
            "total_removed": total_removed,
            "total_retained": total_retained,
            **{t: {"added_count": comp["added_count"], "removed_count": comp["removed_count"], "retained_count": comp["retained_count"]} for t, comp in comparison.items()}
        },
        "comparison": comparison,
        "added": {t: comp["added"] for t, comp in comparison.items()},
        "removed": {t: comp["removed"] for t, comp in comparison.items()},
    }

