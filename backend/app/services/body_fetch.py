"""Selective HTTP body fetching and storage.

Two entry points:

* ``fetch_and_store`` — on-demand fetch for a single URL (UI button). Any
  status code is stored; the body is capped by the existing response-storage
  service.
* ``auto_store_bodies`` — bounded background storage for newly discovered
  FFUF/API URLs. Only useful status codes and text-like content are stored.

Every fetch persists request/response metadata (method, headers, params,
status, content type, timestamps). Raw bodies go to the existing per-project
response store, which already enforces size caps and FIFO retention.
"""

import asyncio
import logging
import socket
from datetime import datetime
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple
from urllib.parse import parse_qsl, urljoin, urlparse

import httpx

from app.core.scope import is_disallowed_ip, is_in_scope, is_valid_url, sanitize_url
from app.services.response_storage import read_response_body, save_response_body

logger = logging.getLogger("reconforge.services.body_fetch")

DEFAULT_MAX_KB = 500
ABSOLUTE_MAX_KB = 2048
DEFAULT_BATCH_LIMIT = 30
DEFAULT_TIMEOUT = 12
PREVIEW_CHARS = 20000

# Automatic storage is intentionally narrower than on-demand fetching:
# 404/410 noise is skipped, while auth/forbidden/server errors are kept
# because they often expose stack traces or framework details.
AUTO_STORE_STATUS_CODES: Set[int] = (
    set(range(200, 300))
    | {301, 302, 303, 307, 308}
    | {400, 401, 402, 403, 405, 406, 409, 410, 411, 415, 418, 429}
    | set(range(500, 600))
)
TEXTUAL_CONTENT_MARKERS = (
    "text/", "json", "xml", "javascript", "x-www-form-urlencoded",
    "graphql", "yaml", "csv",
)
REQUEST_HEADERS = {
    "User-Agent": "ReconForge/1.0 (authorized recon)",
    "Accept": "*/*",
}


def _clamp_kb(value: Any, default: int = DEFAULT_MAX_KB) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        parsed = default
    return max(1, min(parsed, ABSOLUTE_MAX_KB))


def _is_textual(content_type: str) -> bool:
    lowered = (content_type or "").lower()
    return any(marker in lowered for marker in TEXTUAL_CONTENT_MARKERS)


def _preview(raw: bytes, content_type: str) -> str:
    if not raw:
        return ""
    if not _is_textual(content_type):
        return f"<binary response, {len(raw)} bytes>"
    text = raw.decode("utf-8", errors="replace")
    if len(text) > PREVIEW_CHARS:
        return text[:PREVIEW_CHARS] + "\n\n[preview truncated]"
    return text


def _status_is_live(status_code: Optional[int]) -> str:
    if status_code is None:
        return "unknown"
    if status_code in (404, 410):
        return "dead"
    return "live"


def _host_allowed(host: str) -> Tuple[bool, Optional[str]]:
    """Rejects loopback/private/metadata IPs before any request is made."""
    if not host:
        return False, "missing hostname"
    try:
        infos = socket.getaddrinfo(host, None)
    except Exception as exc:
        return False, f"DNS resolution failed: {exc}"
    if not infos:
        return False, "DNS resolution returned no addresses"
    for info in infos:
        ip = str(info[4][0])
        bad, reason = is_disallowed_ip(ip)
        if bad:
            return False, reason or f"disallowed IP {ip}"
    return True, None


async def _find_asset(db: Any, project_id: str, url: str) -> Optional[Dict[str, Any]]:
    parsed = urlparse(url)
    host = (parsed.hostname or "").lower()
    if parsed.path in ("", "/") and not parsed.query:
        host_asset = await db.assets.find_one({
            "project_id": project_id,
            "type": {"$in": ["subdomain", "host"]},
            "domain": host,
        })
        if host_asset:
            return host_asset
    return await db.assets.find_one({
        "project_id": project_id,
        "$or": [
            {"value": url},
            {"domain": url},
            {"metadata.url": url},
        ],
    })


async def _persist_metadata(
    project_id: str,
    url: str,
    metadata: Dict[str, Any],
) -> Optional[str]:
    """Upserts fetch metadata on the matching asset (or a historical_url)."""
    try:
        from app.database import get_database

        db = get_database()
        if db is None:
            return None
        now = datetime.utcnow()
        existing = await _find_asset(db, project_id, url)
        status = _status_is_live(metadata.get("status_code"))
        set_fields = {f"metadata.{key}": value for key, value in metadata.items()}
        set_fields.update({
            "status": status,
            "last_seen": now,
            "updated_at": now,
        })
        if existing:
            await db.assets.update_one({"_id": existing["_id"]}, {"$set": set_fields})
            return str(existing["_id"])

        parsed = urlparse(url)
        host = (parsed.hostname or "").lower()
        doc = {
            "project_id": project_id,
            "domain": host,
            "value": url,
            "type": "historical_url",
            "status": status,
            "metadata": {**metadata, "host": host, "source": "body_fetch"},
            "discovered_by": "body_fetch",
            "sources": ["body_fetch"],
            "first_seen": now,
            "last_seen": now,
            "created_at": now,
            "updated_at": now,
        }
        result = await db.assets.insert_one(doc)
        return str(result.inserted_id)
    except Exception as exc:
        logger.warning("Could not persist body-fetch metadata for %s: %s", url, exc)
        return None


async def _cached_result(
    project_id: str,
    url: str,
    max_kb: int,
) -> Optional[Dict[str, Any]]:
    try:
        from app.database import get_database

        db = get_database()
        if db is None:
            return None
        asset = await _find_asset(db, project_id, url)
        if not asset:
            return None
        meta = dict(asset.get("metadata") or {})
        rel_path = meta.get("response_body_path")
        if not rel_path:
            return None
        content = read_response_body(project_id, str(rel_path).split("/")[-1])
        if content is None:
            return None
        preview = content if len(content) <= PREVIEW_CHARS else content[:PREVIEW_CHARS] + "\n\n[preview truncated]"
        return {
            "ok": True,
            "url": meta.get("url") or url,
            "cached": True,
            "asset_id": str(asset.get("_id")),
            "status_code": meta.get("status_code"),
            "content_type": meta.get("content_type") or "text/plain",
            "size": meta.get("response_body_size") or len(content),
            "stored_path": rel_path,
            "truncated": bool(meta.get("response_body_truncated")),
            "request": meta.get("request") or {"method": "GET", "url": url},
            "response_headers": meta.get("response_headers") or {},
            "fetched_at": meta.get("fetched_at"),
            "body_preview": preview,
            "max_kb": max_kb,
        }
    except Exception as exc:
        logger.debug("Cached body lookup failed for %s: %s", url, exc)
        return None


async def fetch_and_store(
    project_id: str,
    url: str,
    *,
    scope: Optional[Dict[str, Any]] = None,
    max_kb: int = DEFAULT_MAX_KB,
    timeout: int = DEFAULT_TIMEOUT,
    force: bool = False,
    allowed_statuses: Optional[Set[int]] = None,
    store_binary: bool = True,
) -> Dict[str, Any]:
    """Fetches one URL and stores its response body + request metadata.

    ``allowed_statuses=None`` stores bodies for every status (on-demand).
    Auto-storage passes a narrower set and ``store_binary=False``.
    """
    sanitized = sanitize_url(url)
    valid, reason = is_valid_url(sanitized)
    if not valid:
        return {"ok": False, "error": f"invalid URL: {reason}"}
    parsed = urlparse(sanitized)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        return {"ok": False, "error": "only http/https URLs can be fetched"}
    if scope and not is_in_scope(sanitized, scope):
        return {"ok": False, "error": "URL is out of scope"}

    max_kb = _clamp_kb(max_kb)

    if not force:
        cached = await _cached_result(project_id, sanitized, max_kb)
        if cached:
            return cached

    request_meta = {
        "method": "GET",
        "url": sanitized,
        "headers": dict(REQUEST_HEADERS),
        "params": dict(parse_qsl(parsed.query, keep_blank_values=True)),
    }
    max_bytes = max_kb * 1024
    raw_chunks: List[bytes] = []
    received = 0
    truncated = False
    redirect_chain: List[str] = []

    # Follow redirects manually so every hop is scope- and SSRF-checked
    # before the request is made.
    current_url = sanitized
    final_url = sanitized
    status_code: Optional[int] = None
    content_type = ""
    response_headers: Dict[str, str] = {}
    redirect_location = ""
    loop = asyncio.get_running_loop()

    try:
        for hop in range(4):
            current_parsed = urlparse(current_url)
            if current_parsed.scheme not in ("http", "https") or not current_parsed.hostname:
                return {"ok": False, "error": "redirected to an unsupported URL"}
            if scope and not is_in_scope(current_url, scope):
                return {"ok": False, "error": "redirected out of scope"}
            allowed, deny_reason = await loop.run_in_executor(
                None, _host_allowed, current_parsed.hostname
            )
            if not allowed:
                return {"ok": False, "error": deny_reason or "host is not allowed"}

            async with httpx.AsyncClient(
                follow_redirects=False,
                verify=False,
                timeout=httpx.Timeout(timeout),
                headers=REQUEST_HEADERS,
            ) as client:
                async with client.stream("GET", current_url) as response:
                    status_code = int(response.status_code)
                    response_headers = {
                        str(k): str(v) for k, v in response.headers.items()
                    }
                    content_type = response_headers.get("content-type", "")
                    redirect_location = response_headers.get("location", "")
                    if (
                        status_code in (301, 302, 303, 307, 308)
                        and redirect_location
                        and hop < 3
                    ):
                        next_url = urljoin(current_url, redirect_location)
                        redirect_chain.append(next_url)
                        current_url = next_url
                        continue

                    final_url = current_url
                    async for chunk in response.aiter_bytes():
                        if received < max_bytes:
                            take = chunk[: max_bytes - received]
                            raw_chunks.append(take)
                            received += len(take)
                        if received >= max_bytes:
                            truncated = True
                            break
                    break
    except Exception as exc:
        logger.info("Body fetch failed for %s: %s", sanitized, exc)
        return {"ok": False, "error": f"request failed: {exc}"}

    if status_code is None:
        return {"ok": False, "error": "no response received"}

    raw = b"".join(raw_chunks)
    should_store_body = (
        bool(raw)
        and (allowed_statuses is None or status_code in allowed_statuses)
        and (store_binary or _is_textual(content_type))
    )
    stored_path = None
    stored_size = 0
    if should_store_body:
        saved = save_response_body(
            project_id,
            final_url or sanitized,
            raw,
            max_kb=max_kb,
        )
        if saved:
            stored_path, stored_size = saved

    metadata = {
        "url": final_url or sanitized,
        "request_url": sanitized,
        "host": (parsed.hostname or "").lower(),
        "status_code": status_code,
        "content_type": content_type,
        "redirect_location": redirect_location,
        "redirect_chain": redirect_chain,
        "request": request_meta,
        "request_method": "GET",
        "request_headers": request_meta["headers"],
        "params": request_meta["params"],
        "response_headers": response_headers,
        "response_body_path": stored_path,
        "response_body_size": stored_size,
        "response_body_truncated": truncated,
        "fetched_at": datetime.utcnow().isoformat(),
        "auto_stored": allowed_statuses is not None,
    }
    asset_id = await _persist_metadata(project_id, sanitized, metadata)

    return {
        "ok": True,
        "url": final_url or sanitized,
        "requested_url": sanitized,
        "cached": False,
        "asset_id": asset_id,
        "status_code": status_code,
        "content_type": content_type,
        "size": stored_size or len(raw),
        "stored": bool(stored_path),
        "stored_path": stored_path,
        "truncated": truncated,
        "request": request_meta,
        "response_headers": response_headers,
        "fetched_at": metadata["fetched_at"],
        "body_preview": _preview(raw, content_type),
        "max_kb": max_kb,
    }


async def auto_store_bodies(
    project_id: str,
    urls: Iterable[str],
    *,
    scope: Optional[Dict[str, Any]] = None,
    max_kb: int = DEFAULT_MAX_KB,
    limit: int = DEFAULT_BATCH_LIMIT,
    concurrency: int = 3,
    timeout: int = DEFAULT_TIMEOUT,
) -> Dict[str, Any]:
    """Bounded automatic body storage for discovered FFUF/API URLs."""
    unique: List[str] = []
    seen = set()
    for raw_url in urls or []:
        url = sanitize_url(raw_url)
        if not url or url in seen:
            continue
        valid, _ = is_valid_url(url)
        if not valid:
            continue
        if scope and not is_in_scope(url, scope):
            continue
        seen.add(url)
        unique.append(url)

    selected = unique[: max(0, int(limit or DEFAULT_BATCH_LIMIT))]
    if not selected:
        return {"requested": 0, "stored": 0, "failed": 0, "skipped": 0}

    semaphore = asyncio.Semaphore(max(1, int(concurrency or 1)))
    results: List[Dict[str, Any]] = []

    async def run_one(url: str) -> None:
        async with semaphore:
            try:
                results.append(await fetch_and_store(
                    project_id,
                    url,
                    scope=scope,
                    max_kb=max_kb,
                    timeout=timeout,
                    force=False,
                    allowed_statuses=AUTO_STORE_STATUS_CODES,
                    store_binary=False,
                ))
            except Exception as exc:
                results.append({"ok": False, "error": str(exc), "url": url})

    await asyncio.gather(*(run_one(url) for url in selected))
    stored = sum(1 for result in results if result.get("ok") and result.get("stored"))
    failed = sum(1 for result in results if not result.get("ok"))
    skipped = sum(
        1
        for result in results
        if result.get("ok") and not result.get("stored")
    )
    return {
        "requested": len(selected),
        "stored": stored,
        "failed": failed,
        "skipped": skipped,
        "results": results,
    }
