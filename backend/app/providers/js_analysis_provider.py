"""Phase 8.1 — JavaScript analysis, hashing and source-map extraction.

Augments/replaces LinkFinder with jsluice (preferred) or xnLinkFinder.
JavaScript bodies are hashed for run-to-run diffing and persisted through the
existing response-storage service so the secret scanner can inspect exactly the
same in-scope bodies.

All tools are optional. Missing tools emit ``stage_skipped`` with
``tool_missing: <name>`` and the phase continues with native hashing.
"""

import asyncio
import hashlib
import json
import logging
import os
import platform
import re
import subprocess
import tempfile
import time
from typing import Any, AsyncGenerator, Dict, List, Optional, Tuple
from urllib.parse import urljoin, urlparse

import httpx

from app.core.phase8_config import get_phase8_config
from app.core.scope import is_in_scope, is_valid_url, sanitize_url
from app.providers.base import BaseProvider

logger = logging.getLogger("reconforge.providers.js_analysis")

# backend/storage/js/{project_id}/{sha256}.js
# JS_STORAGE_ROOT is the storage root so metadata paths are `js/{project_id}/...`.
JS_STORAGE_ROOT = os.path.abspath(
    os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "storage")
)
JS_SUBDIR = "js"


def _safe_project_component(project_id: str) -> str:
    safe = re.sub(r"[^a-zA-Z0-9_\-]", "", str(project_id or ""))
    if not safe:
        raise ValueError("Invalid project_id for JS storage")
    return safe


def save_js_body(project_id: str, content_hash: str, body: bytes) -> Optional[str]:
    """Stores a JS body under backend/storage/js/{project_id}/{hash}.js.

    Returns the storage-relative path (`js/{project_id}/{hash}.js`) or None.
    """
    if not project_id or not content_hash or not body:
        return None
    try:
        project_dir = os.path.join(JS_STORAGE_ROOT, JS_SUBDIR, _safe_project_component(project_id))
        os.makedirs(project_dir, exist_ok=True)
        safe_hash = re.sub(r"[^a-f0-9]", "", str(content_hash).lower())
        if len(safe_hash) < 16:
            return None
        file_path = os.path.abspath(os.path.join(project_dir, f"{safe_hash}.js"))
        if os.path.commonpath([file_path, JS_STORAGE_ROOT]) != JS_STORAGE_ROOT:
            return None
        if not os.path.isfile(file_path):
            with open(file_path, "wb") as f:
                f.write(body)
        return f"js/{_safe_project_component(project_id)}/{safe_hash}.js"
    except Exception as exc:
        logger.debug("JS body persistence failed: %s", exc)
        return None


def save_sourcemap_file_list(project_id: str, recovered: Dict[str, List[str]]) -> Optional[str]:
    """Stores only the recovered source-map file list, never the recovered sources."""
    if not project_id or not recovered:
        return None
    try:
        project_dir = os.path.join(JS_STORAGE_ROOT, JS_SUBDIR, _safe_project_component(project_id))
        os.makedirs(project_dir, exist_ok=True)
        file_path = os.path.join(project_dir, "sourcemap_recovered_files.json")
        existing: Dict[str, Any] = {}
        if os.path.isfile(file_path):
            try:
                with open(file_path, "r", encoding="utf-8") as f:
                    loaded = json.load(f)
                if isinstance(loaded, dict):
                    existing = loaded
            except Exception:
                existing = {}
        existing.update(recovered)
        with open(file_path, "w", encoding="utf-8") as f:
            json.dump(existing, f, indent=2, sort_keys=True)
        return f"js/{_safe_project_component(project_id)}/sourcemap_recovered_files.json"
    except Exception as exc:
        logger.debug("Source-map file-list persistence failed: %s", exc)
        return None

SOURCE_MAP_RE = re.compile(r"[#@]\s*sourceMappingURL=([^\s'\"*]+)")
ABS_URL_RE = re.compile(r"https?://[^\s'\"<>()]+", re.IGNORECASE)
ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


class JsAnalysisProvider(BaseProvider):
    @property
    def name(self) -> str:
        return "JS Analysis"

    @property
    def description(self) -> str:
        return "Hashes JavaScript files, extracts source maps and discovers endpoints with jsluice/xnLinkFinder."

    # ------------------------------------------------------------------
    # Pure helpers (unit-testable)
    # ------------------------------------------------------------------

    @staticmethod
    def extract_sourcemap_urls(js_url: str, body: str) -> List[str]:
        """Returns absolute, deduplicated source-map URLs referenced by *body*."""
        if not js_url or not body:
            return []
        found: List[str] = []
        for raw in SOURCE_MAP_RE.findall(body):
            candidate = raw.strip().strip("'\"")
            if not candidate or candidate.startswith("data:"):
                continue
            resolved = urljoin(js_url, candidate)
            if resolved not in found:
                found.append(resolved)
        return found

    async def _sourcemap_targets_in_scope(
        self,
        js_url: str,
        body: str,
        scope_cfg: Optional[Dict[str, List[str]]],
        timeout: float,
    ) -> Tuple[bool, List[str], str]:
        """Checks every referenced .map URL and its redirect chain before sourcemapper."""
        map_urls = self.extract_sourcemap_urls(js_url, body)
        if not map_urls:
            return False, [], "no_sourcemap_reference"
        if not scope_cfg:
            return True, map_urls, "ok"
        headers = {
            "User-Agent": "ReconForge-JSAnalysis/1.0",
            "Accept": "*/*",
        }
        async with httpx.AsyncClient(
            headers=headers,
            timeout=timeout,
            follow_redirects=True,
            verify=False,
        ) as checker:
            for map_url in map_urls:
                if not is_in_scope(map_url, scope_cfg):
                    return False, [], f"out_of_scope_map: {map_url}"
                try:
                    async with checker.stream("GET", map_url) as resp:
                        chain = [str(r.url) for r in resp.history] + [str(resp.url)]
                except Exception as exc:
                    return False, [], f"map_scope_check_failed: {type(exc).__name__}"
                for chain_url in chain:
                    if not is_in_scope(chain_url, scope_cfg):
                        return False, [], f"out_of_scope_redirect: {chain_url}"
        return True, map_urls, "ok"

    @staticmethod
    def parse_jsluice_output(lines: List[str], temp_map: Dict[str, str], fallback_js_url: str = "") -> List[Tuple[str, str]]:
        """Parses jsluice URL output into (absolute_url, source_js_url) pairs."""
        results: List[Tuple[str, str]] = []
        seen = set()
        for raw_line in lines:
            line = ANSI_RE.sub("", str(raw_line or "")).strip()
            if not line:
                continue
            candidate = ""
            source_js = fallback_js_url
            try:
                obj = json.loads(line)
                if isinstance(obj, dict):
                    candidate = str(obj.get("url") or obj.get("path") or obj.get("endpoint") or "").strip()
                    fname = str(obj.get("filename") or obj.get("file") or "")
                    if fname and fname in temp_map:
                        source_js = temp_map[fname]
                    elif fname:
                        for tpath, juri in temp_map.items():
                            if os.path.basename(tpath) == os.path.basename(fname):
                                source_js = juri
                                break
                elif isinstance(obj, str):
                    candidate = obj.strip()
            except Exception:
                if line.startswith(("http://", "https://", "/", "../")):
                    candidate = line

            if not candidate:
                continue
            candidate = candidate.strip().strip("'\"")
            if candidate.startswith("//"):
                scheme = urlparse(source_js).scheme or "https"
                candidate = f"{scheme}:{candidate}"
            if not candidate.startswith(("http://", "https://")):
                if not candidate.startswith("/") or not source_js:
                    continue
                candidate = urljoin(source_js, candidate)
            if candidate.startswith(("http://", "https://")) and candidate not in seen:
                seen.add(candidate)
                results.append((candidate, source_js or ""))
        return results

    @staticmethod
    def parse_xnlinkfinder_output(lines: List[str], js_url: str) -> List[str]:
        """Extracts absolute URLs from xnLinkFinder console output."""
        results: List[str] = []
        seen = set()
        for raw_line in lines:
            line = ANSI_RE.sub("", str(raw_line or "")).strip()
            if not line:
                continue
            for match in ABS_URL_RE.findall(line):
                cleaned = match.rstrip(").,;'\"")
                if cleaned.startswith(("http://", "https://")) and cleaned not in seen:
                    seen.add(cleaned)
                    results.append(cleaned)
        return results

    # ------------------------------------------------------------------
    # Tool helpers
    # ------------------------------------------------------------------

    def _strict_tool(self, tool_name: str) -> Optional[str]:
        """Resolves a tool without consulting ASSUME_TOOLS_INSTALLED."""
        try:
            return self.detect_tool(tool_name)
        except Exception:
            return None

    @staticmethod
    def _tool_prefix(tool_path: str) -> List[str]:
        if platform.system().lower() == "windows":
            return ["wsl", "-e", tool_path]
        return [tool_path]

    async def _run_tool(self, args: List[str], timeout: int) -> Tuple[int, str, str]:
        """Runs a local tool off the event loop and registers it for job control."""
        from app.job_control import register_process, unregister_process, kill_process_tree

        def _run() -> Tuple[int, str, str]:
            proc = subprocess.Popen(
                args,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding="utf-8",
                errors="replace",
            )
            register_process(proc)
            try:
                out, err = proc.communicate(timeout=timeout)
                return proc.returncode, out or "", err or ""
            except subprocess.TimeoutExpired:
                kill_process_tree(proc, "js_analysis")
                try:
                    out, err = proc.communicate(timeout=5)
                except Exception:
                    out, err = "", ""
                return -1, out or "", err or ""
            finally:
                unregister_process(proc)

        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, _run)

    async def discover(self, seed_domains: List[str], **kwargs: Any) -> AsyncGenerator[Dict[str, Any], None]:
        async for event in self.analyze(seed_domains, **kwargs):
            yield event

    # ------------------------------------------------------------------
    # Main phase
    # ------------------------------------------------------------------

    async def analyze(
        self,
        js_urls: List[str],
        scan_mode: str = "fast",
        rate_limit: int = 10,
        custom_headers: Optional[Dict[str, str]] = None,
        project_config: Optional[Dict[str, Any]] = None,
        scope: Optional[Dict[str, List[str]]] = None,
    ) -> AsyncGenerator[Dict[str, Any], None]:
        cfg = get_phase8_config(project_config)["js_analysis"]
        scope_cfg = scope if scope is not None else (project_config or {}).get("scope")
        project_id = str((project_config or {}).get("project_id") or "")

        yield {"type": "log", "message": "\n========== JS Analysis (Phase 8) =========="}

        targets = []
        seen = set()
        for raw_url in js_urls or []:
            clean = sanitize_url(str(raw_url or "").strip())
            if not clean:
                yield {"type": "log", "message": f"[-] JS Analysis: skipping empty URL ({str(raw_url or '')[:120]})."}
                continue
            if clean in seen:
                continue
            valid, invalid_reason = is_valid_url(clean)
            if not valid:
                yield {"type": "log", "message": f"[-] JS Analysis: skipping {clean} (invalid URL: {invalid_reason})."}
                continue
            if scope_cfg and not is_in_scope(clean, scope_cfg):
                yield {"type": "log", "message": f"[-] JS Analysis: skipping {clean} (out of scope)."}
                continue
            seen.add(clean)
            targets.append(clean)

        if not cfg.get("enabled", True):
            yield {
                "type": "stage_skipped",
                "stage": "JS Analysis (jsluice)",
                "tool": "jsluice",
                "reason": "disabled",
            }
            yield {"type": "scan_summary", "provider": "js_analysis", "status": "SKIPPED", "count": 0}
            yield {"type": "scan_summary", "provider": "linkfinder", "status": "SKIPPED", "count": 0, "extracted_endpoints": 0}
            return

        if not targets:
            yield {"type": "log", "message": "JS Analysis: no in-scope JavaScript URLs to process."}
            yield {"type": "scan_summary", "provider": "js_analysis", "status": "SKIPPED", "count": 0, "reason": "no_js_urls"}
            yield {"type": "scan_summary", "provider": "linkfinder", "status": "SKIPPED", "count": 0, "extracted_endpoints": 0}
            return

        max_files = int(cfg.get("max_files_deep" if scan_mode == "deep" else "max_files_fast") or (100 if scan_mode == "deep" else 25))
        max_bytes = max(1, int(cfg.get("max_file_kb", 500) or 500)) * 1024
        timeout = float(cfg.get("timeout_seconds", 15) or 15)
        if len(targets) > max_files:
            yield {
                "type": "log",
                "message": (
                    f"[!] JS Analysis: file-count cap reached ({max_files} files); "
                    f"skipping the remaining {len(targets) - max_files} in-scope file(s)."
                ),
            }
            targets = targets[:max_files]

        jsluice_path = self._strict_tool("jsluice")
        xn_path = self._strict_tool("xnlinkfinder")
        sourcemapper_path = self._strict_tool("sourcemapper")
        linkfinder_path = self._strict_tool("linkfinder")

        if not jsluice_path:
            yield {
                "type": "stage_skipped",
                "stage": "JS Analysis (jsluice)",
                "tool": "jsluice",
                "reason": "tool_missing: jsluice",
            }
        if not xn_path:
            yield {
                "type": "stage_skipped",
                "stage": "JS Analysis (xnLinkFinder)",
                "tool": "xnlinkfinder",
                "reason": "tool_missing: xnlinkfinder",
            }
        if scan_mode == "deep" and not sourcemapper_path:
            yield {
                "type": "stage_skipped",
                "stage": "JS Source Map Extraction (sourcemapper)",
                "tool": "sourcemapper",
                "reason": "tool_missing: sourcemapper",
            }

        headers = {
            "User-Agent": "ReconForge-JSAnalysis/1.0",
            "Accept": "*/*",
        }
        if custom_headers:
            headers.update(custom_headers)

        downloaded: List[Dict[str, Any]] = []
        sourcemap_urls: List[str] = []
        fetched_sourcemaps: List[str] = []
        delay = 1.0 / max(int(rate_limit or 10), 1)
        start_ts = time.time()

        yield {
            "type": "log",
            "message": f"[*] JS Analysis: fetching {len(targets)} file(s) (mode: {scan_mode}, cap: {max_bytes // 1024} KB/file)...",
        }

        async with httpx.AsyncClient(
            headers=headers,
            timeout=timeout,
            follow_redirects=True,
            verify=False,
        ) as client:
            for js_url in targets:
                try:
                    if delay > 0:
                        await asyncio.sleep(delay)
                    async with client.stream("GET", js_url) as resp:
                        if resp.status_code >= 400:
                            yield {"type": "log", "message": f"[-] JS Analysis: {js_url} returned HTTP {resp.status_code}; skipping."}
                            continue
                        final_url = str(resp.url)
                        if scope_cfg and not is_in_scope(final_url, scope_cfg):
                            yield {
                                "type": "log",
                                "message": f"[-] JS Analysis: skipping {js_url} (redirect target {final_url} is out of scope); not hashed.",
                            }
                            continue
                        chunks: List[bytes] = []
                        size = 0
                        size_capped = False
                        async for chunk in resp.aiter_bytes():
                            if not chunk:
                                continue
                            remaining = max_bytes - size
                            if remaining <= 0:
                                size_capped = True
                                break
                            if len(chunk) > remaining:
                                size_capped = True
                            chunks.append(chunk[:remaining])
                            size += min(len(chunk), remaining)

                    raw_body = b"".join(chunks)
                    if not raw_body:
                        yield {"type": "log", "message": f"[-] JS Analysis: {js_url} returned an empty body; not hashed."}
                        continue
                    if size_capped:
                        yield {
                            "type": "log",
                            "message": (
                                f"[!] JS Analysis: {js_url} exceeded the {max_bytes // 1024} KB size cap; "
                                "analyzing the truncated prefix."
                            ),
                        }
                    sha256 = hashlib.sha256(raw_body).hexdigest()
                    text_body = raw_body.decode("utf-8", errors="replace")
                    host = (urlparse(js_url).hostname or "").lower()

                    body_path = save_js_body(project_id, sha256, raw_body) if project_id else None

                    downloaded.append({
                        "url": js_url,
                        "host": host,
                        "sha256": sha256,
                        "size": len(raw_body),
                        "body_path": body_path,
                        "text": text_body,
                    })

                    yield {
                        "type": "js_event",
                        "data": {
                            "url": js_url,
                            "host": host,
                            "hash": sha256,
                            "sha256": sha256,
                            "size": len(raw_body),
                            "content_length": len(raw_body),
                            "source": "js_analysis",
                            "kind": "js",
                            "body_path": body_path,
                            "metadata": {
                                "url": js_url,
                                "host": host,
                                "hash": sha256,
                                "sha256": sha256,
                                "content_length": len(raw_body),
                                "source": "js_analysis",
                                "kind": "js",
                                "body_path": body_path,
                            },
                        },
                    }

                    maps_enabled = scan_mode in ("deep", "full") or not bool(cfg.get("sourcemaps_deep_only", True))
                    if maps_enabled and cfg.get("sourcemap_max_files", 10) > len(fetched_sourcemaps):
                        for map_url in self.extract_sourcemap_urls(js_url, text_body):
                            if scope_cfg and not is_in_scope(map_url, scope_cfg):
                                yield {
                                    "type": "log",
                                    "message": f"[-] JS Analysis: source-map URL {map_url} is out of scope; not fetched.",
                                }
                                continue
                            if map_url in sourcemap_urls:
                                continue
                            sourcemap_urls.append(map_url)
                            if len(fetched_sourcemaps) >= int(cfg.get("sourcemap_max_files", 10) or 10):
                                break
                            if delay > 0:
                                await asyncio.sleep(delay)
                            try:
                                async with client.stream("GET", map_url) as mresp:
                                    if mresp.status_code >= 400:
                                        continue
                                    if scope_cfg and not is_in_scope(str(mresp.url), scope_cfg):
                                        yield {
                                            "type": "log",
                                            "message": f"[-] JS Analysis: source-map redirect target {mresp.url} is out of scope; not fetched.",
                                        }
                                        continue
                                    map_chunks: List[bytes] = []
                                    map_size = 0
                                    async for chunk in mresp.aiter_bytes():
                                        if not chunk:
                                            continue
                                        remaining = max_bytes - map_size
                                        if remaining <= 0:
                                            break
                                        map_chunks.append(chunk[:remaining])
                                        map_size += min(len(chunk), remaining)
                                map_body = b"".join(map_chunks)
                                if not map_body:
                                    continue
                                map_hash = hashlib.sha256(map_body).hexdigest()
                                map_host = (urlparse(map_url).hostname or "").lower()
                                map_path = save_js_body(project_id, map_hash, map_body) if project_id else None
                                fetched_sourcemaps.append(map_url)
                                yield {
                                    "type": "js_event",
                                    "data": {
                                        "url": map_url,
                                        "host": map_host,
                                        "hash": map_hash,
                                        "sha256": map_hash,
                                        "size": len(map_body),
                                        "content_length": len(map_body),
                                        "source": "sourcemapper",
                                        "kind": "sourcemap",
                                        "parent_js": js_url,
                                        "body_path": map_path,
                                        "metadata": {
                                            "url": map_url,
                                            "host": map_host,
                                            "hash": map_hash,
                                            "sha256": map_hash,
                                            "content_length": len(map_body),
                                            "source": "sourcemapper",
                                            "kind": "sourcemap",
                                            "parent_js": js_url,
                                            "body_path": map_path,
                                        },
                                    },
                                }
                                yield {"type": "log", "message": f"[+] Source map discovered: {map_url}"}
                            except Exception as map_exc:
                                logger.debug("Source map fetch failed for %s: %s", map_url, map_exc)

                except Exception as exc:
                    logger.debug("JS fetch failed for %s: %s", js_url, exc)
                    yield {
                        "type": "log",
                        "message": (
                            f"[-] JS Analysis: download error for {js_url}; not hashed: "
                            f"{type(exc).__name__}: {str(exc)[:160]}"
                        ),
                    }

        # ------------------------------------------------------------------
        # Endpoint extraction
        # ------------------------------------------------------------------
        endpoints_found: List[Tuple[str, str]] = []
        extraction_source = ""
        temp_dir = None
        temp_map: Dict[str, str] = {}

        try:
            if jsluice_path and downloaded:
                temp_dir = tempfile.mkdtemp(prefix="reconforge_jsluice_")
                temp_files: List[str] = []
                for idx, item in enumerate(downloaded):
                    if not item.get("text"):
                        continue
                    fpath = os.path.join(temp_dir, f"js_{idx}.js")
                    with open(fpath, "w", encoding="utf-8", errors="replace") as f:
                        f.write(item["text"])
                    temp_files.append(fpath)
                    temp_map[fpath] = item["url"]
                if temp_files:
                    wsl_files = [self.wsl_path_convert(p) if platform.system().lower() == "windows" else p for p in temp_files]
                    cmd = [*self._tool_prefix(jsluice_path), "urls", *wsl_files]
                    yield {"type": "log", "message": self.format_cmd_log(cmd)}
                    rc, out, err = await self._run_tool(cmd, timeout=120)
                    if rc == 0:
                        endpoints_found = self.parse_jsluice_output(out.splitlines(), temp_map)
                        extraction_source = "jsluice"
                    else:
                        yield {
                            "type": "stage_error",
                            "stage": "JS Analysis (jsluice)",
                            "tool": "jsluice",
                            "returncode": rc,
                            "message": f"jsluice exited with code {rc}: {(err or out).strip()[:300]}",
                        }
            elif xn_path and downloaded:
                extraction_source = "xnlinkfinder"
                for item in downloaded[: min(len(downloaded), 25)]:
                    js_url = item["url"]
                    cmd = [*self._tool_prefix(xn_path), "-i", js_url, "-o", "cli", "-silent"]
                    yield {"type": "log", "message": self.format_cmd_log(cmd)}
                    rc, out, err = await self._run_tool(cmd, timeout=90)
                    if rc == 0:
                        for found_url in self.parse_xnlinkfinder_output(out.splitlines(), js_url):
                            endpoints_found.append((found_url, js_url))

            if not jsluice_path and not xn_path and linkfinder_path and targets:
                yield {"type": "log", "message": "[*] jsluice/xnLinkFinder unavailable — falling back to LinkFinder."}
                from app.providers.linkfinder_provider import LinkfinderProvider
                lf_count = 0
                async for ev in LinkfinderProvider().discover(targets):
                    if ev.get("type") == "url_event":
                        d = ev.get("data") or {}
                        u = d.get("url")
                        if u:
                            endpoints_found.append((u, d.get("js_file") or ""))
                            lf_count += 1
                    elif ev.get("type") == "scan_summary" and ev.get("provider") == "LinkFinder":
                        pass
                    yield ev
                extraction_source = "linkfinder"
                yield {"type": "scan_summary", "provider": "linkfinder", "status": "completed", "count": lf_count, "extracted_endpoints": lf_count}
                yield {"type": "log", "message": "[√] Provider linkfinder completed"}
        finally:
            if temp_dir:
                try:
                    import shutil
                    shutil.rmtree(temp_dir, ignore_errors=True)
                except Exception:
                    pass

        deduped_endpoints: List[Tuple[str, str]] = []
        seen_endpoints = set()
        for endpoint, source_js in endpoints_found:
            if endpoint and endpoint not in seen_endpoints:
                seen_endpoints.add(endpoint)
                deduped_endpoints.append((endpoint, source_js or ""))

        for endpoint, source_js in deduped_endpoints:
            if scope_cfg and not is_in_scope(endpoint, scope_cfg):
                continue
            host = (urlparse(endpoint).hostname or "").lower()
            yield {
                "type": "url_event",
                "data": {
                    "url": endpoint,
                    "original_url": endpoint,
                    "source": "js_analysis",
                    "sources": ["js_analysis", extraction_source] if extraction_source else ["js_analysis"],
                    "api_endpoint": endpoint,
                    "js_file": source_js,
                    "host": host,
                },
            }

        # Source mapper: recover source files for referenced maps, store ONLY the
        # recovered file list (paths), never the recovered source contents.
        sourcemap_file_list_path = None
        recovered_file_count = 0
        mapper_targets: List[str] = []
        if scan_mode in ("deep", "full") and sourcemapper_path:
            for item in downloaded:
                allowed, _map_urls, reason = await self._sourcemap_targets_in_scope(
                    item["url"], item.get("text") or "", scope_cfg, timeout
                )
                if allowed:
                    mapper_targets.append(item["url"])
                elif reason != "no_sourcemap_reference":
                    yield {
                        "type": "log",
                        "message": f"[-] SourceMapper: skipping {item['url']} ({reason}).",
                    }
        if scan_mode in ("deep", "full") and sourcemapper_path and mapper_targets:
            mapper_budget = min(len(mapper_targets), 5)
            yield {"type": "log", "message": f"[*] SourceMapper: reconstructing sources for {mapper_budget} JS file(s) with referenced maps..."}
            out_dir = tempfile.mkdtemp(prefix="reconforge_sourcemapper_")
            recovered_map: Dict[str, List[str]] = {}
            try:
                out_dir_arg = self.wsl_path_convert(out_dir) if platform.system().lower() == "windows" else out_dir
                for js_url in mapper_targets[:mapper_budget]:
                    cmd = [*self._tool_prefix(sourcemapper_path), "-url", js_url, "-output", out_dir_arg]
                    rc, out, err = await self._run_tool(cmd, timeout=45)
                    if rc != 0:
                        logger.debug("sourcemapper failed for %s: %s", js_url, (err or out)[:200])
                        yield {
                            "type": "log",
                            "message": f"[-] SourceMapper failed for {js_url}: {(err or out).strip()[:200] or 'no output'}",
                        }
                        continue
                    recovered: List[str] = []
                    for root, _dirs, files in os.walk(out_dir):
                        for fname in files:
                            recovered.append(
                                os.path.relpath(os.path.join(root, fname), out_dir).replace("\\", "/")
                            )
                    recovered = sorted(recovered)
                    recovered_map[js_url] = recovered
                    recovered_file_count += len(recovered)
                    yield {
                        "type": "log",
                        "message": f"[+] SourceMapper recovered {len(recovered)} source file(s) for {js_url}.",
                    }
                if project_id and recovered_map:
                    sourcemap_file_list_path = save_sourcemap_file_list(project_id, recovered_map)
                    if sourcemap_file_list_path:
                        yield {
                            "type": "log",
                            "message": f"[+] Source-map recovered file list stored at {sourcemap_file_list_path}.",
                        }
            finally:
                try:
                    import shutil
                    shutil.rmtree(out_dir, ignore_errors=True)
                except Exception:
                    pass

        duration = int(time.time() - start_ts)
        yield {
            "type": "scan_summary",
            "provider": "js_analysis",
            "status": "completed",
            "count": len(deduped_endpoints),
            "files_fetched": len(downloaded),
            "endpoints_extracted": len(deduped_endpoints),
            "sourcemaps_found": len(fetched_sourcemaps),
            "sourcemap_recovered_files": recovered_file_count,
            "sourcemap_file_list_path": sourcemap_file_list_path,
            "files_hashed": len(downloaded),
            "extraction_source": extraction_source or "none",
            "duration_seconds": duration,
        }
        yield {
            "type": "scan_summary",
            "provider": "linkfinder",
            "status": "completed",
            "count": len(deduped_endpoints),
            "extracted_endpoints": len(deduped_endpoints),
        }
        yield {
            "type": "log",
            "message": (
                f"[√] JS Analysis complete: {len(downloaded)} file(s) hashed, "
                f"{len(deduped_endpoints)} endpoint(s), {len(fetched_sourcemaps)} source map(s)."
            ),
        }
