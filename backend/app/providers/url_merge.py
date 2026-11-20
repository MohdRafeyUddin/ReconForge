import logging
import os
import re
from typing import Dict, List, Set, Any, Optional
from urllib.parse import urlparse

logger = logging.getLogger("reconforge.providers.url_merge")

def normalize_url(url: str) -> str:
    """Normalizes URL, e.g. replacing double slashes inside path while keeping scheme intact."""
    url = url.strip()
    if not url:
        return ""
    if "://" in url:
        scheme, rest = url.split("://", 1)
        while "//" in rest:
            rest = rest.replace("//", "/")
        return f"{scheme}://{rest}"
    else:
        while "//" in url:
            url = url.replace("//", "/")
        return url

def get_url_priority(url: str) -> int:
    """
    Returns priority score: lower is higher priority.
    0: URLs with parameters
    1: API endpoints (contains api, v1, v2, etc., or no file extension)
    2: Interesting extensions (js, php, json, etc.)
    3: Other URLs
    """
    try:
        parsed = urlparse(url)
        path = parsed.path.lower()
        query = parsed.query
        
        # 1. URLs with parameters
        if query or "?" in url:
            return 0
            
        # 2. API endpoints
        if "api" in path or "/v1" in path or "/v2" in path or "/v3" in path:
            return 1
        
        # Paths without a file extension (e.g. /profile, /admin/users)
        filename = path.split("/")[-1] if "/" in path else path
        if filename and "." not in filename:
            return 1
            
        # 3. Interesting extensions
        interesting_exts = {".js", ".php", ".json", ".jsp", ".asp", ".aspx", ".html", ".htm", ".txt", ".xml", ".action"}
        for ext in interesting_exts:
            if path.endswith(ext):
                return 2
                
        # 4. Other
        return 3
    except Exception:
        return 3

# File types that render as raw assets in a browser, not as useful pages.
SCREENSHOT_SKIP_EXTENSIONS = {
    ".js", ".mjs", ".css", ".map",
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".ico", ".bmp",
    ".woff", ".woff2", ".ttf", ".eot", ".otf",
    ".mp4", ".webm", ".mp3", ".wav", ".avi", ".mov",
    ".zip", ".tar", ".gz", ".rar", ".7z", ".exe", ".dll", ".bin", ".iso",
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
    ".txt", ".xml", ".csv", ".log",
}


def _screenshot_host_key(url: str) -> str:
    """Returns a host[:port] key that ignores default ports and casing."""
    try:
        parsed = urlparse(url)
        host = (parsed.hostname or parsed.netloc or "").lower()
        scheme = (parsed.scheme or "").lower()
        port = parsed.port
        if port and not (
            (scheme == "https" and port == 443)
            or (scheme == "http" and port == 80)
        ):
            host = f"{host}:{port}"
        return host
    except Exception:
        return ""


def _screenshot_url_key(url: str) -> str:
    """Canonical key so `https://host` and `https://host/` deduplicate."""
    try:
        parsed = urlparse((url or "").strip())
        scheme = (parsed.scheme or "https").lower()
        host = _screenshot_host_key(url)
        path = parsed.path or "/"
        query = f"?{parsed.query}" if parsed.query else ""
        if path == "/" and not query:
            path = ""
        return f"{scheme}://{host}{path}{query}"
    except Exception:
        return (url or "").strip().lower()


def select_screenshot_targets(
    live_urls: Optional[List[str]] = None,
    candidate_urls: Optional[List[str]] = None,
    max_urls: int = 50,
    max_per_host_extras: int = 5,
) -> List[str]:
    """Selects GoWitness targets: live host roots first, then prioritized URLs.

    Roots come from HTTPX-confirmed live host URLs and are always kept (the
    historical behaviour) before the budget is spent on merged/normalised
    URLs. Candidates are ranked with :func:`get_url_priority` so parameterised
    and API-like endpoints are captured before generic pages. ``max_urls``
    bounds the whole list and ``max_per_host_extras`` stops a single noisy
    host from consuming every remaining slot.
    """
    try:
        max_urls = max(1, int(max_urls))
    except (TypeError, ValueError):
        max_urls = 50
    try:
        max_per_host_extras = max(0, int(max_per_host_extras))
    except (TypeError, ValueError):
        max_per_host_extras = 5

    targets: List[str] = []
    seen: Set[str] = set()
    extras_per_host: Dict[str, int] = {}

    def add(url: str) -> bool:
        url = (url or "").strip()
        if not url or len(targets) >= max_urls:
            return False
        key = _screenshot_url_key(url)
        if not key or key in seen:
            return False
        seen.add(key)
        targets.append(url)
        return True

    for url in live_urls or []:
        add(url)

    ranked = sorted(
        (u.strip() for u in (candidate_urls or []) if u and u.strip()),
        key=lambda u: (get_url_priority(u), len(u), u),
    )
    for url in ranked:
        if len(targets) >= max_urls:
            break
        try:
            ext = os.path.splitext(urlparse(url).path.lower())[1]
        except Exception:
            ext = ""
        if ext in SCREENSHOT_SKIP_EXTENSIONS:
            continue
        host = _screenshot_host_key(url)
        if host and extras_per_host.get(host, 0) >= max_per_host_extras:
            continue
        if add(url) and host:
            extras_per_host[host] = extras_per_host.get(host, 0) + 1

    return targets


def merge_urls(
    katana_urls: Optional[List[str]] = None, 
    gau_urls: Optional[List[str]] = None, 
    linkfinder_urls: Optional[List[str]] = None, 
    scan_mode: str = "fast",
    per_host_cap: Optional[int] = None,
    global_cap: Optional[int] = None,
    **extra_source_urls: Any
) -> List[Dict[str, Any]]:
    """
    Merges, normalizes, deduplicates, prioritizes, and limits URL list.
    Applies per-host URL cap (default 1,000/host fast, 5,000/host deep)
    IN ADDITION to the global cap (5,000 fast, 30,000 deep).
    Returns: List of dicts, e.g. [{"url": "...", "sources": ["gau", "katana"]}]
    """
    url_sources: Dict[str, Set[str]] = {}
    
    def add_urls(urls: Optional[List[str]], source: str):
        if not urls:
            return
        for u in urls:
            norm = normalize_url(u)
            if not norm:
                continue
            if norm not in url_sources:
                url_sources[norm] = set()
            url_sources[norm].add(source)
            
    add_urls(katana_urls or [], "katana")
    add_urls(gau_urls or [], "gau")
    add_urls(linkfinder_urls or [], "linkfinder")
    for src, urls in extra_source_urls.items():
        clean_src = src.replace("_urls", "")
        if isinstance(urls, list):
            add_urls(urls, clean_src)
    
    if not url_sources:
        return []
        
    # Determine limits
    if global_cap is not None:
        limit = global_cap
    else:
        limit = 30000 if scan_mode == "deep" else 5000

    if per_host_cap is not None:
        host_limit = per_host_cap
    else:
        host_limit = 5000 if scan_mode == "deep" else 1000
    
    # Sort by priority score, then by URL length/alpha for stability
    sorted_urls = sorted(
        url_sources.keys(),
        key=lambda u: (get_url_priority(u), len(u), u)
    )
    
    limited_urls = []
    host_counts: Dict[str, int] = {}
    for u in sorted_urls:
        if len(limited_urls) >= limit:
            break
        try:
            parsed = urlparse(u)
            host = parsed.netloc.lower() or parsed.path.split("/")[0].lower() or "unknown"
        except Exception:
            host = "unknown"

        if host_counts.get(host, 0) >= host_limit:
            continue

        host_counts[host] = host_counts.get(host, 0) + 1
        limited_urls.append(u)
    
    result = []
    for u in limited_urls:
        result.append({
            "url": u,
            "sources": sorted(list(url_sources[u]))
        })
        
    logger.info(
        f"Merged {len(url_sources)} unique URLs down to {len(result)} "
        f"(global limit: {limit}, per-host cap: {host_limit}) using scan_mode: {scan_mode}"
    )
    return result
