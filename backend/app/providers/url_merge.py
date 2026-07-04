import logging
import re
from typing import Dict, List, Set, Any
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

def merge_urls(
    katana_urls: List[str], 
    gau_urls: List[str], 
    linkfinder_urls: List[str], 
    scan_mode: str = "fast"
) -> List[Dict[str, Any]]:
    """
    Merges, normalizes, deduplicates, prioritizes, and limits URL list.
    Returns: List of dicts, e.g. [{"url": "...", "sources": ["gau", "katana"]}]
    """
    url_sources: Dict[str, Set[str]] = {}
    
    def add_urls(urls: List[str], source: str):
        for u in urls:
            norm = normalize_url(u)
            if not norm:
                continue
            if norm not in url_sources:
                url_sources[norm] = set()
            url_sources[norm].add(source)
            
    add_urls(katana_urls, "katana")
    add_urls(gau_urls, "gau")
    add_urls(linkfinder_urls, "linkfinder")
    
    if not url_sources:
        return []
        
    # Determine limit
    limit = 30000 if scan_mode == "deep" else 5000
    
    # Sort by priority score, then by URL length/alpha for stability
    sorted_urls = sorted(
        url_sources.keys(),
        key=lambda u: (get_url_priority(u), len(u), u)
    )
    
    limited_urls = sorted_urls[:limit]
    
    result = []
    for u in limited_urls:
        result.append({
            "url": u,
            "sources": sorted(list(url_sources[u]))
        })
        
    logger.info(f"Merged {len(url_sources)} unique URLs down to {len(result)} (limit: {limit}) using scan_mode: {scan_mode}")
    return result
