"""
Continuous Monitoring & Diff Engine
===================================
Computes differences between the current scan and the previous completed scan
for a project with the same scan_mode. Detects:
  - New subdomains
  - Disappeared subdomains (marked as 'stale' only after N consecutive completed scans, default 2)
  - New live hosts
  - New open ports and closed ports per host (only if both scans executed port scanning)
  - HTTP response fingerprint changes:
      * status_code, title, technologies (high-priority, triggers alerts)
      * body_hash, content_length (low-priority only, UI badge)
  - New JavaScript files
  - New vulnerability findings (keyed stably on template-id:matched-at:host)

Saves result into `scan_diffs` collection and returns diff summary.
"""

import hashlib
import logging
from datetime import datetime
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse
from bson import ObjectId

from app.core.scope import is_in_scope

logger = logging.getLogger("reconforge.diff_engine")


def generate_host_fingerprint(
    status_code: Optional[int],
    title: Optional[str],
    content_length: Optional[int],
    technologies: Optional[List[str]] = None,
    body_hash: Optional[str] = None,
    favicon: Optional[str] = None,
    tls: Optional[Any] = None,
    **kwargs: Any,
) -> Dict[str, Any]:
    """Generates a structured response fingerprint and deterministic hash."""
    tech_list = sorted(list(set(technologies or kwargs.get("tech") or [])))
    if not body_hash:
        raw = f"{status_code}|{title or ''}|{content_length or 0}|{','.join(tech_list)}"
        body_hash = hashlib.sha256(raw.encode("utf-8")).hexdigest()

    fav_val = favicon or kwargs.get("favicon_hash") or kwargs.get("favicon_mmh3")
    tls_val = tls or kwargs.get("tls_info")

    fp: Dict[str, Any] = {
        "status_code": status_code,
        "title": title or "",
        "content_length": content_length or 0,
        "technologies": tech_list,
        "body_hash": body_hash,
    }
    if fav_val is not None:
        fp["favicon"] = fav_val
    if tls_val is not None:
        fp["tls"] = tls_val
    return fp


def compare_fingerprints(
    old_fp: Optional[Dict[str, Any]],
    new_fp: Optional[Dict[str, Any]]
) -> List[Dict[str, Any]]:
    """
    Compares two fingerprints and returns list of detected changes.
    Tags status_code, title, technologies with priority="high" (alert-triggering)
    and body_hash, content_length, favicon, tls with priority="low" (UI only).
    """
    changes = []
    if not old_fp or not new_fp:
        return changes

    if old_fp.get("status_code") != new_fp.get("status_code"):
        changes.append({
            "field": "status_code",
            "priority": "high",
            "old": old_fp.get("status_code"),
            "new": new_fp.get("status_code"),
        })

    if old_fp.get("title") != new_fp.get("title"):
        changes.append({
            "field": "title",
            "priority": "high",
            "old": old_fp.get("title"),
            "new": new_fp.get("title"),
        })

    old_tech = set(old_fp.get("technologies") or old_fp.get("tech") or [])
    new_tech = set(new_fp.get("technologies") or new_fp.get("tech") or [])
    if old_tech != new_tech:
        added_tech = sorted(list(new_tech - old_tech))
        removed_tech = sorted(list(old_tech - new_tech))
        changes.append({
            "field": "technologies",
            "priority": "high",
            "added": added_tech,
            "removed": removed_tech,
        })

    # body_hash and content_length are low priority only (UI badges, no alerts)
    if old_fp.get("body_hash") != new_fp.get("body_hash"):
        changes.append({
            "field": "body_hash",
            "priority": "low",
            "old": old_fp.get("body_hash"),
            "new": new_fp.get("body_hash"),
        })

    old_cl = old_fp.get("content_length") or 0
    new_cl = new_fp.get("content_length") or 0
    if old_cl != new_cl:
        changes.append({
            "field": "content_length",
            "priority": "low",
            "old": old_fp.get("content_length"),
            "new": new_fp.get("content_length"),
        })

    old_fav = old_fp.get("favicon") or old_fp.get("favicon_hash")
    new_fav = new_fp.get("favicon") or new_fp.get("favicon_hash")
    if old_fav != new_fav:
        changes.append({
            "field": "favicon",
            "priority": "low",
            "old": old_fav,
            "new": new_fav,
        })

    old_tls = old_fp.get("tls") or old_fp.get("tls_info")
    new_tls = new_fp.get("tls") or new_fp.get("tls_info")
    if old_tls != new_tls:
        changes.append({
            "field": "tls",
            "priority": "low",
            "old": old_tls,
            "new": new_tls,
        })

    return changes


def get_executed_phases(job: Optional[Dict[str, Any]]) -> Set[str]:
    """Infers or reads the set of pipeline phases executed by a job."""
    if not job:
        return set()
    phases = set(job.get("executed_phases") or [])
    # New full runs record executed phases authoritatively. Legacy fast/deep
    # jobs keep the old log-inference behaviour so their diffs still work.
    is_legacy_job = str(job.get("scan_mode") or "").strip().lower() in ("fast", "deep")
    explicit_phases = (job.get("executed_phases") is not None) and not is_legacy_job
    logs_list = job.get("logs") or []
    logs = " ".join(logs_list).lower()

    # Targeted runs are not full pipeline runs; never infer phases for them.
    if str(job.get("job_kind") or "").lower() == "targeted" or job.get("scan_mode") == "targeted":
        return phases

    # Tool missing gating: if tool was missing or phase skipped, phase did NOT run
    if "tool_missing: ffuf" in logs or "tool_missing: feroxbuster" in logs or "skipping content discovery" in logs:
        phases.discard("content_discovery")
    elif "ffuf" in logs or "content discovery" in logs:
        phases.add("content_discovery")

    if "tool_missing: api_surface" in logs or "skipping api" in logs:
        phases.discard("api_surface")
    elif "api surface" in logs or "api spec" in logs or "graphql" in logs:
        phases.add("api_surface")

    if ("tool_missing: arjun" in logs and "tool_missing: x8" in logs) or "skipping parameter discovery" in logs:
        phases.discard("param_discovery")
    elif "arjun" in logs or "x8" in logs or "parameter discovery" in logs:
        phases.add("param_discovery")

    if "tool_missing: puredns" in logs or "skipping dns brute force" in logs or "dns brute force skipped" in logs:
        phases.discard("dns_bruteforce")
    elif "puredns" in logs or "dns brute force" in logs or "alterx" in logs or "dns_bruteforce" in phases:
        phases.add("dns_bruteforce")

    if "root expansion" in logs or "asnmap" in logs or "root_expansion" in phases:
        phases.add("root_expansion")

    if "takeover" in logs or "subzy" in logs or "takeover_crosscheck" in phases:
        phases.add("takeover_crosscheck")

    # If no logs provided and no explicit phases, assume standard pipeline executed subdomain_discovery and port_scanning
    if not explicit_phases and not logs_list and not phases:
        phases.add("subdomain_discovery")
        phases.add("port_scanning")
        phases.add("web_probing")
    elif not explicit_phases:
        if "skipping passive discovery" not in logs:
            phases.add("subdomain_discovery")
        if "skipping naabu" not in logs and ("naabu" in logs or "port scan" in logs or job.get("scan_mode") != "fast_no_ports"):
            phases.add("port_scanning")
        if "httpx" in logs or "web probing" in logs:
            phases.add("web_probing")
        if "katana" in logs or "gau" in logs or "uro" in logs:
            phases.add("crawling")
        if "subjs" in logs or "linkfinder" in logs or "jsluice" in logs or "js analysis" in logs:
            phases.add("js_analysis")
        if "nuclei" in logs or "dalfox" in logs or "openredirex" in logs:
            phases.add("vulnerability_scan")

    # Stage 1 switches: a skipped-by-switch phase did NOT execute, even if the
    # tool name appears in the skip line.
    if "dns brute force & permutations disabled by project switch" in logs:
        phases.discard("dns_bruteforce")
    if "ffuf content discovery disabled by project switch" in logs:
        phases.discard("content_discovery")
    if "parameter discovery disabled by project switch" in logs:
        phases.discard("param_discovery")
    if "active scanners disabled by project switch" in logs:
        phases.discard("vulnerability_scan")
        phases.discard("tech_routing")
    if "gowitness screenshots disabled by project switch" in logs:
        phases.discard("screenshots")
    return phases


def compute_modified_js_files(
    current_js_meta: Dict[str, Dict[str, Any]],
    prev_js_meta: Dict[str, Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """Returns JS files present in both scans whose SHA-256 changed."""
    modified: List[Dict[str, Any]] = []
    for js_url in sorted(set(current_js_meta.keys()) & set(prev_js_meta.keys())):
        old_hash = prev_js_meta[js_url].get("hash")
        new_hash = current_js_meta[js_url].get("hash")
        if old_hash and new_hash and old_hash != new_hash:
            modified.append({
                "url": js_url,
                "host": current_js_meta[js_url].get("host") or prev_js_meta[js_url].get("host") or "",
                "old_hash": old_hash,
                "new_hash": new_hash,
            })
    return modified


def compute_finding_key(template_id: str, matched_at: str, host: str) -> str:
    """Computes stable finding identity key: template-id + matched-at + host."""
    t_id = (template_id or "finding").strip()
    m_at = (matched_at or "").strip()
    h = (host or "").strip()
    if not h and m_at:
        try:
            h = urlparse(m_at).netloc or ""
        except Exception:
            h = ""
    return f"{t_id}:{m_at}:{h}"


async def compute_and_save_diff(
    project_id: Any,
    current_job_id: Any,
    db: Any = None
) -> Dict[str, Any]:
    """
    Computes diff between the current scan (`current_job_id`) and the previous
    completed scan with the SAME `scan_mode` for `project_id`.
    Saves diff into `scan_diffs` collection.
    
    Rules:
      1. Only diff scans with the same scan_mode.
      2. Mark subdomains as stale only after absent in N consecutive completed scans (default 2).
      3. Skip stale / closed-port marking if scan was cancelled, partial, or a passive source errored.
      4. Report closed ports and stale items only for phases both scans executed.
      5. Do not report scope-excluded assets as disappeared.
    """
    # Parameter order normalisation: support (db, project_id, job_id) or (project_id, job_id, db)
    if hasattr(project_id, "jobs"):
        db, project_id, current_job_id = project_id, current_job_id, db
    elif db is None:
        from app.database import get_database
        db = get_database()

    if db is None:
        logger.warning("[diff_engine] Database unavailable. Skipping diff computation.")
        return {}

    # 1. Fetch current job and project
    try:
        current_job = await db.jobs.find_one({"_id": ObjectId(current_job_id)})
    except Exception:
        current_job = await db.jobs.find_one({"_id": current_job_id})

    if not current_job:
        logger.warning(f"[diff_engine] Current job {current_job_id} not found.")
        return {}

    try:
        project_doc = await db.projects.find_one({"_id": ObjectId(project_id)})
    except Exception:
        project_doc = await db.projects.find_one({"_id": project_id})

    current_scan_mode = current_job.get("scan_mode", "fast")
    scan_started_at = current_job.get("started_at") or datetime.min

    # Check scan reliability
    curr_status = current_job.get("status")
    is_scan_reliable = True
    if curr_status in ("cancelled", "stopped", "failed", "interrupted"):
        is_scan_reliable = False
    if current_job.get("is_partial"):
        is_scan_reliable = False
    if current_job.get("passive_source_errored"):
        is_scan_reliable = False

    # Check logs for passive source errors
    job_logs = current_job.get("logs") or []
    for log_line in job_logs:
        line_l = log_line.lower()
        if "encountered an error:" in line_l or "failed:" in line_l or "provider_error" in line_l:
            for p_lbl in ("subfinder", "assetfinder", "chaos", "amass"):
                if p_lbl in line_l:
                    is_scan_reliable = False
                    break

    # 2. Find previous completed job for this project with the SAME scan_mode
    prev_job = None
    try:
        scan_mode_filter = {"$in": ["fast", None]} if current_scan_mode == "fast" else current_scan_mode
        prev_cursor = db.jobs.find({
            "project_id": project_id,
            "status": "completed",
            "scan_mode": scan_mode_filter,
            "_id": {"$ne": current_job["_id"]},
        }).sort("finished_at", -1)
        prev_list = await prev_cursor.to_list(1)
        if prev_list:
            prev_job = prev_list[0]
    except Exception as exc:
        logger.warning(f"[diff_engine] Error querying previous job: {exc}")

    prev_job_id = str(prev_job["_id"]) if prev_job else None

    # Liveness version check for re-baselining
    curr_liveness_ver = int(current_job.get("liveness_version") or 2)
    prev_liveness_ver = int(prev_job.get("liveness_version") or 1) if prev_job else curr_liveness_ver
    is_liveness_rebaseline = bool(prev_job and curr_liveness_ver > prev_liveness_ver)

    if is_liveness_rebaseline:
        logger.info(
            f"[diff_engine] Liveness version upgrade detected (v{prev_liveness_ver} -> v{curr_liveness_ver}). "
            f"Re-baselining live hosts to prevent alerting previously dead-but-responding hosts."
        )

    # Check executed phases for both scans
    curr_phases = get_executed_phases(current_job)
    prev_phases = get_executed_phases(prev_job) if prev_job else set()
    both_ran_subdomains = bool("subdomain_discovery" in curr_phases and "subdomain_discovery" in prev_phases)
    both_ran_ports = bool("port_scanning" in curr_phases and "port_scanning" in prev_phases)
    both_ran_content = bool("content_discovery" in curr_phases and "content_discovery" in prev_phases)
    both_ran_api = bool("api_surface" in curr_phases and "api_surface" in prev_phases)
    both_ran_params = bool("param_discovery" in curr_phases and "param_discovery" in prev_phases)
    both_ran_js = bool("js_analysis" in curr_phases and "js_analysis" in prev_phases)
    both_ran_vuln = bool("vulnerability_scan" in curr_phases and "vulnerability_scan" in prev_phases)
    both_ran_secrets = bool("secret_scan" in curr_phases and "secret_scan" in prev_phases)
    both_ran_buckets = bool("cloud_enum" in curr_phases and "cloud_enum" in prev_phases)
    both_ran_screenshots = bool("screenshots" in curr_phases and "screenshots" in prev_phases)

    # 3. Query all assets for this project
    all_assets_cursor = db.assets.find({"project_id": project_id})
    all_assets = await all_assets_cursor.to_list(100000)

    current_subdomains: Dict[str, Dict[str, Any]] = {}
    prev_subdomains: Dict[str, Dict[str, Any]] = {}

    current_live_hosts: Set[str] = set()
    prev_live_hosts: Set[str] = set()

    current_ports: Dict[str, Set[int]] = {}
    prev_ports: Dict[str, Set[int]] = {}

    current_fingerprints: Dict[str, Dict[str, Any]] = {}
    prev_fingerprints: Dict[str, Dict[str, Any]] = {}

    current_js_files: Set[str] = set()
    prev_js_files: Set[str] = set()
    current_js_meta: Dict[str, Dict[str, Any]] = {}
    prev_js_meta: Dict[str, Dict[str, Any]] = {}

    current_findings: List[Dict[str, Any]] = []
    prev_finding_keys: Set[str] = set()

    current_content_paths: Dict[str, Dict[str, Any]] = {}
    prev_content_paths: Dict[str, Dict[str, Any]] = {}

    current_api_specs: Dict[str, Dict[str, Any]] = {}
    prev_api_specs: Dict[str, Dict[str, Any]] = {}

    current_graphql_endpoints: Dict[str, Dict[str, Any]] = {}
    prev_graphql_endpoints: Dict[str, Dict[str, Any]] = {}

    current_params: Dict[str, Dict[str, Any]] = {}
    prev_params: Dict[str, Dict[str, Any]] = {}

    current_secrets: Dict[str, Dict[str, Any]] = {}
    prev_secrets: Dict[str, Dict[str, Any]] = {}

    current_buckets: Dict[str, Dict[str, Any]] = {}
    prev_buckets: Dict[str, Dict[str, Any]] = {}

    current_recon_info: Dict[str, Dict[str, Any]] = {}
    prev_recon_info: Dict[str, Dict[str, Any]] = {}

    current_screenshots: Dict[str, Dict[str, Any]] = {}
    prev_screenshots: Dict[str, Dict[str, Any]] = {}

    for doc in all_assets:
        a_type = doc.get("type", "subdomain")
        val = doc.get("value") or doc.get("domain") or ""
        scan_id = doc.get("scan_id") or doc.get("last_seen_job_id") or doc.get("job_id")
        last_seen_job = doc.get("last_seen_job_id") or scan_id
        first_seen = doc.get("first_seen") or doc.get("created_at") or datetime.min
        last_seen = doc.get("last_seen") or doc.get("updated_at") or datetime.min

        seen_in_current = (scan_id == current_job_id) or (last_seen_job == current_job_id) or (last_seen >= scan_started_at)
        seen_in_prev = False
        if prev_job:
            prev_start = prev_job.get("started_at") or datetime.min
            prev_finish = prev_job.get("finished_at") or datetime.max
            seen_in_prev = (
                (scan_id == prev_job_id)
                or (last_seen_job == prev_job_id)
                or (first_seen <= prev_finish and last_seen >= prev_start)
                or (first_seen <= prev_finish and not seen_in_current)
            )

        # 3a. Subdomains
        if a_type == "subdomain":
            domain = doc.get("domain") or val
            if seen_in_current:
                current_subdomains[domain] = doc
                if doc.get("status") == "live":
                    current_live_hosts.add(domain)
                open_ports = set(doc.get("open_ports") or [])
                if open_ports:
                    current_ports[domain] = open_ports
                fp = doc.get("fingerprint") or (doc.get("metadata") or {}).get("fingerprint")
                if not fp and doc.get("status") == "live":
                    meta = doc.get("metadata") or {}
                    fp = generate_host_fingerprint(
                        status_code=meta.get("status_code"),
                        title=meta.get("title"),
                        content_length=meta.get("content_length"),
                        technologies=meta.get("technologies") or meta.get("tech"),
                        body_hash=meta.get("body_hash"),
                        favicon=meta.get("favicon_hash") or meta.get("favicon"),
                        tls=meta.get("tls_info") or meta.get("tls"),
                    )
                if fp:
                    current_fingerprints[domain] = fp

                # Check if previous fingerprint was stored on this asset
                prev_fp = doc.get("previous_fingerprint") or (doc.get("metadata") or {}).get("previous_fingerprint")
                if prev_fp and seen_in_prev:
                    prev_fingerprints[domain] = prev_fp

            if seen_in_prev and not (first_seen >= scan_started_at):
                prev_subdomains[domain] = doc
                if doc.get("status") == "live":
                    prev_live_hosts.add(domain)
                open_ports = set(doc.get("open_ports") or [])
                if open_ports:
                    prev_ports[domain] = open_ports
                fp = (
                    doc.get("previous_fingerprint")
                    or (doc.get("metadata") or {}).get("previous_fingerprint")
                    or doc.get("fingerprint")
                    or (doc.get("metadata") or {}).get("fingerprint")
                )
                if not fp and doc.get("status") == "live":
                    meta = doc.get("metadata") or {}
                    fp = generate_host_fingerprint(
                        status_code=meta.get("status_code"),
                        title=meta.get("title"),
                        content_length=meta.get("content_length"),
                        technologies=meta.get("technologies") or meta.get("tech"),
                        body_hash=meta.get("body_hash"),
                        favicon=meta.get("favicon_hash") or meta.get("favicon"),
                        tls=meta.get("tls_info") or meta.get("tls"),
                    )
                if fp and (domain not in prev_fingerprints or doc.get("scan_id") == prev_job_id):
                    prev_fingerprints[domain] = fp

        # 3b. JS Files (URL + content hash for modified-JS detection)
        elif a_type == "js_file":
            js_meta = doc.get("metadata") or {}
            js_url = js_meta.get("url") or val
            if not js_url:
                continue
            current_hash = js_meta.get("hash") or js_meta.get("sha256")
            previous_hash = js_meta.get("previous_hash") or js_meta.get("previous_sha256")
            js_host = js_meta.get("host") or (urlparse(js_url).hostname or "")
            if seen_in_current:
                current_js_files.add(js_url)
                current_js_meta[js_url] = {
                    "url": js_url,
                    "host": js_host,
                    "hash": current_hash,
                }
            if seen_in_prev and not (first_seen >= scan_started_at):
                prev_js_files.add(js_url)
                prev_js_meta[js_url] = {
                    "url": js_url,
                    "host": js_host,
                    "hash": previous_hash or current_hash,
                }

        # 3c. Findings
        elif a_type == "finding":
            meta = doc.get("metadata") or {}
            template_id = meta.get("template_id") or doc.get("discovered_by") or "finding"
            matched_url = meta.get("matched_url") or doc.get("domain") or ""
            host = meta.get("host") or ""
            f_key = doc.get("value") or compute_finding_key(template_id, matched_url, host)

            finding_obj = {
                "key": f_key,
                "domain": doc.get("domain"),
                "matched_url": matched_url,
                "source": doc.get("discovered_by") or meta.get("source"),
                "severity": meta.get("severity", "medium"),
                "payload": meta.get("payload", ""),
                "parameter": meta.get("parameter", ""),
            }

            if seen_in_current and (first_seen >= scan_started_at or scan_id == current_job_id):
                current_findings.append(finding_obj)
            if seen_in_prev and not (first_seen >= scan_started_at):
                prev_finding_keys.add(f_key)

        # 3d. Content Paths
        elif a_type == "content_path":
            meta = doc.get("metadata") or {}
            cp_key = doc.get("value") or meta.get("url") or val
            cp_item = {
                "value": cp_key,
                "url": meta.get("url") or cp_key,
                "domain": doc.get("domain") or meta.get("host") or "",
                "status_code": meta.get("status_code") or doc.get("status_code") or 200,
                "content_length": meta.get("content_length") or doc.get("content_length") or 0,
                "source": doc.get("discovered_by") or meta.get("source") or "ffuf",
            }
            if seen_in_current:
                current_content_paths[cp_key] = cp_item
            if seen_in_prev and not (first_seen >= scan_started_at):
                prev_content_paths[cp_key] = cp_item

        # 3e. API Specs
        elif a_type == "api_spec":
            meta = doc.get("metadata") or {}
            spec_key = doc.get("value") or meta.get("url") or val
            spec_item = {
                "value": spec_key,
                "url": meta.get("url") or spec_key,
                "domain": doc.get("domain") or meta.get("host") or "",
                "spec_type": meta.get("spec_type") or "OpenAPI",
                "title": meta.get("title") or "API Spec",
                "endpoints_count": meta.get("endpoints_count") or len(meta.get("routes") or []),
                "source": doc.get("discovered_by") or "api_surface",
            }
            if seen_in_current:
                current_api_specs[spec_key] = spec_item
            if seen_in_prev and not (first_seen >= scan_started_at):
                prev_api_specs[spec_key] = spec_item

        # 3f. GraphQL Endpoints
        elif a_type == "graphql_endpoint":
            meta = doc.get("metadata") or {}
            gql_key = doc.get("value") or meta.get("url") or val
            gql_item = {
                "value": gql_key,
                "url": meta.get("url") or gql_key,
                "domain": doc.get("domain") or meta.get("host") or "",
                "introspection_enabled": meta.get("introspection_enabled", False),
                "types_count": meta.get("types_count", 0),
                "source": doc.get("discovered_by") or "api_surface",
            }
            if seen_in_current:
                current_graphql_endpoints[gql_key] = gql_item
            if seen_in_prev and not (first_seen >= scan_started_at):
                prev_graphql_endpoints[gql_key] = gql_item

        # 3g. Parameters
        elif a_type == "param":
            meta = doc.get("metadata") or {}
            p_key = doc.get("value") or f"{meta.get('endpoint')}?{meta.get('param_name')}"
            p_item = {
                "value": p_key,
                "endpoint": meta.get("endpoint") or "",
                "param_name": meta.get("param_name") or "",
                "url": meta.get("parameterized_url") or "",
                "domain": doc.get("domain") or "",
                "source": doc.get("discovered_by") or "param_discovery",
            }
            if seen_in_current:
                current_params[p_key] = p_item
            if seen_in_prev and not (first_seen >= scan_started_at):
                prev_params[p_key] = p_item

        # 3h. Secret findings (masked values only)
        elif a_type in ("secret_finding", "secret"):
            meta = doc.get("metadata") or {}
            s_key = meta.get("identity_key") or doc.get("value") or val
            s_item = {
                "key": s_key,
                "secret_type": meta.get("secret_type") or meta.get("detector") or "secret",
                "host": meta.get("host") or doc.get("domain") or "",
                "url": meta.get("location_url") or meta.get("url") or "",
                "location": meta.get("location") or "",
                "line": meta.get("line") or 0,
                "masked_preview": meta.get("masked_preview") or meta.get("prefix") or "",
                "severity": meta.get("severity") or "medium",
            }
            if seen_in_current:
                current_secrets[s_key] = s_item
            if seen_in_prev and not (first_seen >= scan_started_at):
                prev_secrets[s_key] = s_item

        # 3i. Cloud buckets
        elif a_type in ("bucket", "cloud_bucket"):
            meta = doc.get("metadata") or {}
            b_key = doc.get("value") or meta.get("url") or val
            b_item = {
                "value": b_key,
                "url": meta.get("url") or b_key,
                "host": meta.get("host") or doc.get("domain") or "",
                "bucket_name": meta.get("bucket_name") or "",
                "provider": meta.get("provider") or "",
                "public": bool(meta.get("public")),
                "in_scope_keyword": meta.get("in_scope_keyword") or meta.get("tied_to_keyword") or "",
            }
            if seen_in_current:
                current_buckets[b_key] = b_item
            if seen_in_prev and not (first_seen >= scan_started_at):
                prev_buckets[b_key] = b_item

        # 3j. Info-level Nuclei recon notes (never vulnerabilities)
        elif a_type == "recon_info":
            meta = doc.get("metadata") or {}
            r_key = doc.get("value") or f"{meta.get('template_id')}:{meta.get('matched_url')}:{meta.get('host')}"
            r_item = {
                "key": r_key,
                "template_id": meta.get("template_id") or "",
                "template_name": meta.get("template_name") or "",
                "matched_url": meta.get("matched_url") or "",
                "host": meta.get("host") or doc.get("domain") or "",
                "tags": meta.get("tags") or [],
                "severity": "info",
            }
            if seen_in_current:
                current_recon_info[r_key] = r_item
            if seen_in_prev and not (first_seen >= scan_started_at):
                prev_recon_info[r_key] = r_item

        # 3k. Screenshots (page hash changes)
        elif a_type == "screenshot":
            meta = doc.get("metadata") or {}
            shot_url = meta.get("url") or doc.get("value") or val
            page_hash = meta.get("page_hash") or meta.get("screenshot_hash") or ""
            shot_item = {
                "url": shot_url,
                "host": meta.get("host") or doc.get("domain") or "",
                "page_hash": page_hash,
                "screenshot_path": meta.get("screenshot_path") or "",
                "filename": meta.get("filename") or "",
                "run_id": meta.get("run_id") or "",
            }
            if seen_in_current:
                current_screenshots[shot_url] = shot_item
            if seen_in_prev and not (first_seen >= scan_started_at):
                prev_screenshots[shot_url] = shot_item

    # Screenshot per-run history: run_assets keeps every run's page hash, so
    # compare current vs previous even though the assets document is upserted.
    async def _load_run_screenshots(job_id: Any) -> Dict[str, Dict[str, Any]]:
        if not job_id:
            return {}
        found: Dict[str, Dict[str, Any]] = {}
        try:
            cursor = db.run_assets.find({
                "project_id": project_id,
                "job_id": str(job_id),
                "type": "screenshot",
            })
            async for shot in cursor:
                meta = shot.get("metadata") or {}
                shot_url = meta.get("url") or shot.get("value") or ""
                if not shot_url:
                    continue
                found[shot_url] = {
                    "url": shot_url,
                    "host": meta.get("host") or shot.get("domain") or "",
                    "page_hash": meta.get("page_hash") or meta.get("screenshot_hash") or "",
                    "screenshot_path": meta.get("screenshot_path") or "",
                    "filename": meta.get("filename") or "",
                    "run_id": str(job_id),
                }
        except Exception:
            pass
        return found

    current_run_shots = await _load_run_screenshots(current_job_id)
    prev_run_shots = await _load_run_screenshots(prev_job_id)
    if current_run_shots:
        current_screenshots = current_run_shots
    if prev_run_shots:
        prev_screenshots = prev_run_shots

    # Reset consecutive_absent_count for subdomains seen in current scan
    for dom in current_subdomains:
        doc = current_subdomains[dom]
        if doc.get("consecutive_absent_count", 0) > 0:
            try:
                await db.assets.update_one(
                    {"project_id": project_id, "domain": dom, "type": "subdomain"},
                    {"$set": {"consecutive_absent_count": 0}}
                )
            except Exception:
                pass

    # 4. Calculate Diff Arrays
    if prev_job is None:
        # Initial scan: all discovered items are new
        new_subdomains = sorted(list(current_subdomains.keys()))
        stale_subdomains = []
        new_live_hosts = sorted(list(current_live_hosts))
        new_ports = [
            {"domain": dom, "port": p}
            for dom, p_set in current_ports.items()
            for p in sorted(list(p_set))
        ]
        closed_ports = []
        changed_hosts = []
        new_js_files = sorted(list(current_js_files))
        modified_js_files = []
        new_findings = current_findings
        # Initial scan: baseline new asset types — do not report as new when no earlier completed scan executed that phase
        new_content_paths = []
        new_api_specs = []
        new_graphql_endpoints = []
        new_params = []
        # Phase 8 additions are baselined on first appearance.
        new_secret_findings = []
        new_buckets = []
        new_recon_info = []
        changed_screenshots = []
    else:
        # Comparison vs previous scan
        new_subdomains = sorted(list(set(current_subdomains.keys()) - set(prev_subdomains.keys())))
        
        # Stale Logic (Item 3 & 4)
        stale_subdomains = []
        scope_cfg = (project_doc or {}).get("scope")
        sched_cfg = (project_doc or {}).get("schedule") or {}
        stale_threshold = int(sched_cfg.get("stale_threshold") or (project_doc or {}).get("stale_threshold") or 2)

        if is_scan_reliable and both_ran_subdomains:
            disappeared_candidates = sorted(list(set(prev_subdomains.keys()) - set(current_subdomains.keys())))
            for d in disappeared_candidates:
                # Do not report scope-excluded assets as disappeared!
                if scope_cfg and not is_in_scope(d, scope_cfg):
                    logger.debug(f"[diff_engine] {d} excluded by scope. Skipping stale/disappeared check.")
                    continue

                prev_doc = prev_subdomains.get(d) or {}
                absent_count = prev_doc.get("consecutive_absent_count", 0) + 1

                if absent_count >= stale_threshold:
                    stale_subdomains.append(d)
                    try:
                        await db.assets.update_one(
                            {"project_id": project_id, "domain": d, "type": "subdomain"},
                            {"$set": {
                                "status": "stale",
                                "consecutive_absent_count": absent_count,
                                "updated_at": datetime.utcnow()
                            }}
                        )
                    except Exception as upd_err:
                        logger.debug(f"[diff_engine] Failed to mark {d} as stale: {upd_err}")
                else:
                    try:
                        await db.assets.update_one(
                            {"project_id": project_id, "domain": d, "type": "subdomain"},
                            {"$set": {
                                "consecutive_absent_count": absent_count,
                                "updated_at": datetime.utcnow()
                            }}
                        )
                    except Exception as upd_err:
                        logger.debug(f"[diff_engine] Failed to increment absent count for {d}: {upd_err}")
        else:
            logger.info(
                f"[diff_engine] Skipping stale subdomains (reliable={is_scan_reliable}, both_ran_subdomains={both_ran_subdomains})"
            )

        # New live hosts (re-baselined on version transition to suppress false alerts on dead-but-responding hosts)
        if is_liveness_rebaseline:
            # Only genuinely new subdomains discovered in this scan can qualify as new live hosts
            new_live_hosts = sorted(list(set(new_subdomains) & current_live_hosts))
        else:
            new_live_hosts = sorted(list(current_live_hosts - prev_live_hosts))

        # Port changes (only report closed ports if both scans executed port scanning and scan was reliable)
        new_ports = []
        closed_ports = []
        for dom, cur_p_set in current_ports.items():
            prev_p_set = prev_ports.get(dom, set())
            for p in sorted(list(cur_p_set - prev_p_set)):
                new_ports.append({"domain": dom, "port": p})
            
            if is_scan_reliable and both_ran_ports:
                for p in sorted(list(prev_p_set - cur_p_set)):
                    closed_ports.append({"domain": dom, "port": p})

        # Fingerprint changes
        changed_hosts = []
        common_live = set(current_fingerprints.keys()) & set(prev_fingerprints.keys())
        v1_nonexistent_fields = {"body_hash", "favicon", "favicon_hash", "tech", "technologies", "tls", "tls_info"}
        for dom in sorted(list(common_live)):
            old_fp = prev_fingerprints[dom]
            new_fp = current_fingerprints[dom]
            changes = compare_fingerprints(old_fp, new_fp)
            if is_liveness_rebaseline:
                # Suppress changed_hosts alerts caused by fingerprint fields that did not exist in v1 (body_hash, favicon, tech, tls)
                changes = [
                    c for c in changes
                    if c.get("field") not in v1_nonexistent_fields
                ]
            if changes:
                changed_hosts.append({
                    "domain": dom,
                    "changes": changes,
                    "old_fingerprint": old_fp,
                    "new_fingerprint": new_fp,
                })

        # JS Files — diff only if both scans ran JS analysis
        if both_ran_js:
            new_js_files = sorted(list(current_js_files - prev_js_files))
            modified_js_files = compute_modified_js_files(current_js_meta, prev_js_meta)
        else:
            new_js_files = []
            modified_js_files = []

        # New Findings — diff only if both scans ran the vulnerability phase
        if both_ran_vuln:
            new_findings = [f for f in current_findings if f.get("key") not in prev_finding_keys]
        else:
            new_findings = []

        # Content Paths: diff only if both scans ran content_discovery
        if both_ran_content:
            new_content_paths = [
                current_content_paths[k]
                for k in sorted(set(current_content_paths.keys()) - set(prev_content_paths.keys()))
            ]
        else:
            new_content_paths = []

        # API Specs & GraphQL: diff only if both scans ran api_surface
        if both_ran_api:
            new_api_specs = [
                current_api_specs[k]
                for k in sorted(set(current_api_specs.keys()) - set(prev_api_specs.keys()))
            ]
            new_graphql_endpoints = [
                current_graphql_endpoints[k]
                for k in sorted(set(current_graphql_endpoints.keys()) - set(prev_graphql_endpoints.keys()))
            ]
        else:
            new_api_specs = []
            new_graphql_endpoints = []

        # Params: diff only if both scans ran param_discovery
        if both_ran_params:
            new_params = [
                current_params[k]
                for k in sorted(set(current_params.keys()) - set(prev_params.keys()))
            ]
        else:
            new_params = []

        # Phase 8: only diff types whose phase ran in BOTH scans.
        if both_ran_secrets:
            new_secret_findings = [
                current_secrets[k]
                for k in sorted(set(current_secrets.keys()) - set(prev_secrets.keys()))
            ]
        else:
            new_secret_findings = []

        if both_ran_buckets:
            new_buckets = [
                current_buckets[k]
                for k in sorted(set(current_buckets.keys()) - set(prev_buckets.keys()))
            ]
        else:
            new_buckets = []

        if both_ran_vuln:
            new_recon_info = [
                current_recon_info[k]
                for k in sorted(set(current_recon_info.keys()) - set(prev_recon_info.keys()))
            ]
        else:
            new_recon_info = []

        changed_screenshots = []
        if both_ran_screenshots:
            for shot_url in sorted(set(current_screenshots.keys()) & set(prev_screenshots.keys())):
                old_hash = prev_screenshots[shot_url].get("page_hash")
                new_hash = current_screenshots[shot_url].get("page_hash")
                if old_hash and new_hash and old_hash != new_hash:
                    changed_screenshots.append({
                        **current_screenshots[shot_url],
                        "old_hash": old_hash,
                        "new_hash": new_hash,
                    })

    diff_data = {
        "new_subdomains": new_subdomains,
        "stale_subdomains": stale_subdomains,
        "new_live_hosts": new_live_hosts,
        "new_ports": new_ports,
        "closed_ports": closed_ports,
        "changed_hosts": changed_hosts,
        "new_js_files": new_js_files,
        "modified_js_files": modified_js_files,
        "new_findings": new_findings,
        "new_content_paths": new_content_paths,
        "new_api_specs": new_api_specs,
        "new_graphql_endpoints": new_graphql_endpoints,
        "new_params": new_params,
        "new_secret_findings": new_secret_findings,
        "new_buckets": new_buckets,
        "new_recon_info": new_recon_info,
        "changed_screenshots": changed_screenshots,
    }

    summary = {
        "new_subdomains_count": len(new_subdomains),
        "stale_subdomains_count": len(stale_subdomains),
        "new_live_hosts_count": len(new_live_hosts),
        "new_ports_count": len(new_ports),
        "closed_ports_count": len(closed_ports),
        "changed_hosts_count": len(changed_hosts),
        "new_js_files_count": len(new_js_files),
        "modified_js_files_count": len(modified_js_files),
        "new_findings_count": len(new_findings),
        "new_content_paths_count": len(new_content_paths),
        "new_api_specs_count": len(new_api_specs),
        "new_graphql_endpoints_count": len(new_graphql_endpoints),
        "new_params_count": len(new_params),
        "new_secret_findings_count": len(new_secret_findings),
        "new_buckets_count": len(new_buckets),
        "new_recon_info_count": len(new_recon_info),
        "changed_screenshots_count": len(changed_screenshots),
        "is_initial_scan": prev_job is None,
        "scan_mode": current_scan_mode,
        "is_reliable": is_scan_reliable,
        "liveness_version": curr_liveness_ver,
        "prev_liveness_version": prev_liveness_ver,
        "is_liveness_rebaseline": is_liveness_rebaseline,
    }

    summary["total_changes"] = (
        summary["new_subdomains_count"]
        + summary["stale_subdomains_count"]
        + summary["new_live_hosts_count"]
        + summary["new_ports_count"]
        + summary["closed_ports_count"]
        + summary["changed_hosts_count"]
        + summary["new_js_files_count"]
        + summary["modified_js_files_count"]
        + summary["new_findings_count"]
        + summary["new_content_paths_count"]
        + summary["new_api_specs_count"]
        + summary["new_graphql_endpoints_count"]
        + summary["new_params_count"]
        + summary["new_secret_findings_count"]
        + summary["new_buckets_count"]
        + summary["new_recon_info_count"]
        + summary["changed_screenshots_count"]
    )

    diff_doc = {
        "project_id": project_id,
        "scan_id": current_job_id,
        "current_job_id": current_job_id,
        "prev_scan_id": prev_job_id,
        "previous_job_id": prev_job_id,
        "scan_mode": current_scan_mode,
        "liveness_version": curr_liveness_ver,
        "prev_liveness_version": prev_liveness_ver,
        "is_liveness_rebaseline": is_liveness_rebaseline,
        "created_at": datetime.utcnow(),
        "diff": diff_data,
        "summary": summary,
        # Mirror diff keys at root level for direct attribute access
        **diff_data,
    }

    # Save to MongoDB scan_diffs collection
    try:
        res = await db.scan_diffs.insert_one(diff_doc)
        diff_doc["_id"] = str(res.inserted_id)
    except Exception as e:
        logger.error(f"[diff_engine] Failed to save scan diff: {e}")

    logger.info(
        f"[diff_engine] Diff calculated for job {current_job_id} (mode: {current_scan_mode}): "
        f"+{summary['new_subdomains_count']} subdomains, "
        f"-{summary['stale_subdomains_count']} stale, "
        f"+{summary['new_live_hosts_count']} live, "
        f"{summary['changed_hosts_count']} changed hosts, "
        f"+{summary['new_content_paths_count']} content paths, "
        f"+{summary['new_findings_count']} findings."
    )

    return diff_doc
