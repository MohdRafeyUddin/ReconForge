"""API URL classification and storage.

Detects API-looking URLs from the discovered URL set (REST, GraphQL, OpenAPI/
Swagger, SOAP/WSDL, OData, JSON-RPC, versioned endpoints) and persists them as
`api_endpoint` assets. Explicit API discovery results (`api_spec`,
`graphql_endpoint`) are surfaced alongside these in the API inventory tab.
"""

import logging
from datetime import datetime
from typing import Any, Dict, Iterable, Optional, Set
from urllib.parse import parse_qsl, urlparse

logger = logging.getLogger("reconforge.services.api_classify")

STATIC_EXTENSIONS = {
    ".js", ".mjs", ".css", ".map", ".png", ".jpg", ".jpeg", ".gif", ".svg",
    ".webp", ".ico", ".bmp", ".woff", ".woff2", ".ttf", ".eot", ".otf",
    ".mp4", ".webm", ".mp3", ".wav", ".avi", ".mov", ".zip", ".tar", ".gz",
    ".rar", ".7z", ".exe", ".dll", ".bin", ".iso", ".pdf", ".doc", ".docx",
    ".xls", ".xlsx", ".ppt", ".pptx",
}


def _extension(path: str) -> str:
    name = (path or "").lower().rsplit("/", 1)[-1]
    if "." not in name:
        return ""
    return "." + name.rsplit(".", 1)[-1]


def classify_api_url(url: str) -> Optional[Dict[str, Any]]:
    """Returns API metadata for a URL, or None when it does not look like an API."""
    try:
        parsed = urlparse(str(url or "").strip())
        host = (parsed.hostname or "").lower().strip(".")
        path = parsed.path or "/"
    except Exception:
        return None
    if not host:
        return None

    lowered = path.lower()
    if _extension(lowered) in STATIC_EXTENSIONS:
        return None

    segments = [segment for segment in lowered.split("/") if segment]
    api_type = ""
    if any(segment in ("graphql", "gql") for segment in segments) or "graphql" in lowered:
        api_type = "graphql"
    elif any(
        marker in lowered
        for marker in ("openapi", "swagger", "/api-docs", "/v3/api-docs", "/swagger-ui")
    ):
        api_type = "openapi"
    elif ".wsdl" in lowered or any(segment == "soap" for segment in segments):
        api_type = "soap"
    elif any(segment == "odata" for segment in segments):
        api_type = "odata"
    elif any(segment in ("rpc", "jsonrpc") for segment in segments):
        api_type = "rpc"
    elif any(segment == "wp-json" for segment in segments):
        api_type = "rest"
    elif any(segment == "api" for segment in segments) or lowered.startswith("/api"):
        api_type = "rest"
    elif any(segment == "rest" for segment in segments):
        api_type = "rest"
    elif any(
        segment in ("v1", "v2", "v3", "v4", "v5")
        for segment in segments
    ) and len(segments) >= 2:
        api_type = "rest"
    elif _extension(lowered) == ".json":
        api_type = "json"
    elif not segments and (host.startswith("api.") or host.startswith("api-")):
        api_type = "rest"

    if not api_type:
        return None

    params = [key for key, _value in parse_qsl(parsed.query, keep_blank_values=True)]
    return {
        "url": str(url).strip(),
        "host": host,
        "path": path,
        "api_type": api_type,
        "has_params": bool(params),
        "params": sorted(set(params)),
    }


async def classify_api_and_store(
    project_id: str,
    url_parents: Dict[str, Set[str]],
    scan_id: Optional[str] = None,
    limit: int = 2000,
) -> Dict[str, Any]:
    """Classifies URL→parent mappings and upserts api_endpoint assets."""
    if not project_id:
        return {"total": 0, "urls": [], "by_type": {}}

    classified = []
    for url, parents in (url_parents or {}).items():
        info = classify_api_url(url)
        if not info:
            continue
        parent_hosts = sorted({
            str(parent or "").strip().lower()
            for parent in (parents or set())
            if str(parent or "").strip()
        })
        info["parent_hosts"] = parent_hosts
        info["parent_host"] = parent_hosts[0] if parent_hosts else ""
        classified.append(info)
        if len(classified) >= max(1, int(limit or 2000)):
            break

    if not classified:
        return {"total": 0, "urls": [], "by_type": {}}

    by_type: Dict[str, int] = {}
    stored = 0
    try:
        from app.database import get_database

        db = get_database()
        if db is None:
            return {
                "total": len(classified),
                "urls": [item["url"] for item in classified],
                "by_type": {},
            }
        now = datetime.utcnow()
        for item in classified:
            by_type[item["api_type"]] = by_type.get(item["api_type"], 0) + 1
            existing = await db.assets.find_one({
                "project_id": project_id,
                "type": "api_endpoint",
                "$or": [{"value": item["url"]}, {"metadata.url": item["url"]}],
            })
            fields = {
                "metadata.url": item["url"],
                "metadata.host": item["host"],
                "metadata.path": item["path"],
                "metadata.api_type": item["api_type"],
                "metadata.has_params": item["has_params"],
                "metadata.params": item["params"],
                "metadata.parent_host": item["parent_host"],
                "metadata.parent_hosts": item["parent_hosts"],
                "metadata.source": "url_classifier",
                "last_seen": now,
                "updated_at": now,
            }
            if scan_id:
                fields["scan_id"] = scan_id
            if existing:
                previous = set(
                    (existing.get("metadata") or {}).get("parent_hosts") or []
                )
                merged = sorted(previous | set(item["parent_hosts"]))
                fields["metadata.parent_hosts"] = merged
                fields["metadata.parent_host"] = merged[0] if merged else ""
                await db.assets.update_one({"_id": existing["_id"]}, {"$set": fields})
            else:
                await db.assets.insert_one({
                    "project_id": project_id,
                    "type": "api_endpoint",
                    "domain": item["host"],
                    "value": item["url"],
                    "status": "live" if item["parent_hosts"] else "unknown",
                    "metadata": {
                        "url": item["url"],
                        "host": item["host"],
                        "path": item["path"],
                        "api_type": item["api_type"],
                        "has_params": item["has_params"],
                        "params": item["params"],
                        "parent_host": item["parent_host"],
                        "parent_hosts": item["parent_hosts"],
                        "source": "url_classifier",
                    },
                    "discovered_by": "url_classifier",
                    "sources": ["url_classifier"],
                    "first_seen": now,
                    "last_seen": now,
                    "created_at": now,
                    "updated_at": now,
                    **({"scan_id": scan_id} if scan_id else {}),
                })
            stored += 1
    except Exception as exc:
        logger.warning("API classification persistence failed: %s", exc)

    return {
        "total": len(classified),
        "stored": stored,
        "urls": [item["url"] for item in classified],
        "by_type": by_type,
    }
