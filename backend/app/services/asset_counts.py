"""Canonical asset-count definitions.

Live hosts are distinct host assets (type subdomain/host) with status "live"
AND an HTTP response. URL-type assets are never counted as hosts. Passive
candidates are unresolved names kept for attribution but excluded from the
attack-surface host counts.
"""

from typing import Any, Dict, Optional

HOST_ASSET_TYPES = ("subdomain", "host")
PASSIVE_STATUSES = ("candidate", "passive_candidate")

URL_TYPE_KEYS: Dict[str, str] = {
    "historical_url": "historical",
    "historical_dead": "historical_dead",
    "unprobed_url": "unprobed",
    "uro_url": "normalized",
    "gf_url": "gf",
    "content_path": "content_paths",
    "js_file": "js_files",
    "api_spec": "api_specs",
    "graphql_endpoint": "graphql_endpoints",
    "param": "params",
    "screenshot": "screenshots",
}

_CANDIDATE_CLAUSES = [
    {"status": {"$in": list(PASSIVE_STATUSES)}},
    {"metadata.passive_candidate": True},
]

_HTTP_RESPONSE_CLAUSE = {
    "$or": [
        {"metadata.status_code": {"$exists": True, "$ne": None}},
        {"status_code": {"$exists": True, "$ne": None}},
    ]
}

_RESOLVED_CLAUSE = {
    "$or": [
        {"status": {"$in": ["live", "resolved"]}},
        {"metadata.status_code": {"$exists": True, "$ne": None}},
        {"status_code": {"$exists": True, "$ne": None}},
        {"resolved_ip": {"$exists": True, "$ne": None}},
        {"metadata.dnsx": {"$exists": True}},
        {"metadata.resolved_ip": {"$exists": True, "$ne": None}},
    ]
}


def _base(project_id: str, job_id: Optional[str] = None) -> Dict[str, Any]:
    query: Dict[str, Any] = {"project_id": str(project_id)}
    if job_id is not None:
        query["job_id"] = str(job_id)
    return query


def _and(*clauses: Dict[str, Any]) -> Dict[str, Any]:
    merged: Dict[str, Any] = {}
    for clause in clauses:
        for key, value in clause.items():
            merged[key] = value
    return merged


def host_query(project_id: str, job_id: Optional[str] = None) -> Dict[str, Any]:
    return _and(_base(project_id, job_id), {"type": {"$in": list(HOST_ASSET_TYPES)}})


def passive_candidate_query(project_id: str, job_id: Optional[str] = None) -> Dict[str, Any]:
    return _and(host_query(project_id, job_id), {"$or": list(_CANDIDATE_CLAUSES)})


def non_candidate_host_query(project_id: str, job_id: Optional[str] = None) -> Dict[str, Any]:
    return _and(host_query(project_id, job_id), {"$nor": list(_CANDIDATE_CLAUSES)})


def resolved_host_query(project_id: str, job_id: Optional[str] = None) -> Dict[str, Any]:
    return _and(non_candidate_host_query(project_id, job_id), _RESOLVED_CLAUSE)


def live_http_host_query(project_id: str, job_id: Optional[str] = None) -> Dict[str, Any]:
    return _and(
        host_query(project_id, job_id),
        {"status": "live"},
        _HTTP_RESPONSE_CLAUSE,
        {"$nor": list(_CANDIDATE_CLAUSES)},
    )


def url_query(project_id: str, job_id: Optional[str] = None) -> Dict[str, Any]:
    return _and(_base(project_id, job_id), {"type": {"$in": list(URL_TYPE_KEYS)}})


def is_passive_candidate(doc: Dict[str, Any]) -> bool:
    status = str(doc.get("status") or "").strip().lower()
    metadata = doc.get("metadata") or {}
    return status in PASSIVE_STATUSES or bool(metadata.get("passive_candidate"))


def is_http_response(doc: Dict[str, Any]) -> bool:
    metadata = doc.get("metadata") or {}
    return doc.get("status_code") is not None or metadata.get("status_code") is not None


def is_live_http_host(doc: Dict[str, Any]) -> bool:
    return (
        str(doc.get("type") or "").strip().lower() in HOST_ASSET_TYPES
        and str(doc.get("status") or "").strip().lower() == "live"
        and is_http_response(doc)
        and not is_passive_candidate(doc)
    )


async def collect_counts(collection: Any, project_id: str, job_id: Optional[str] = None) -> Dict[str, Any]:
    """Counts host, passive-candidate and URL assets using the canonical rules."""
    subdomains = await collection.count_documents(non_candidate_host_query(project_id, job_id))
    resolved_hosts = await collection.count_documents(resolved_host_query(project_id, job_id))
    passive_candidates = await collection.count_documents(passive_candidate_query(project_id, job_id))
    live_hosts = await collection.count_documents(live_http_host_query(project_id, job_id))

    url_counts: Dict[str, int] = {}
    urls_total = 0
    for asset_type, key in URL_TYPE_KEYS.items():
        count = await collection.count_documents(
            _and(_base(project_id, job_id), {"type": asset_type})
        )
        url_counts[key] = count
        urls_total += count

    open_ports_count = 0
    try:
        cursor = collection.find(host_query(project_id, job_id))
        async for host_doc in cursor:
            metadata = host_doc.get("metadata") or {}
            ports = (
                metadata.get("open_ports")
                or (metadata.get("naabu") or {}).get("open_ports")
                or host_doc.get("open_ports")
                or []
            )
            open_ports_count += len(ports)
    except Exception:
        pass

    return {
        "subdomains": subdomains,
        "resolved_hosts": resolved_hosts,
        "passive_candidates": passive_candidates,
        "live": live_hosts,
        "live_hosts": live_hosts,
        "ports": open_ports_count,
        "urls_total": urls_total,
        "urls": url_counts,
        "historical_urls": url_counts.get("historical", 0),
        "normalized_urls": url_counts.get("normalized", 0),
        "gf_urls": url_counts.get("gf", 0),
        "content_paths": url_counts.get("content_paths", 0),
        "js_files": url_counts.get("js_files", 0),
        "api_specs": url_counts.get("api_specs", 0),
        "graphql_endpoints": url_counts.get("graphql_endpoints", 0),
        "params": url_counts.get("params", 0),
    }
