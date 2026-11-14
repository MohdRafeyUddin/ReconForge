"""FFUF Content Discovery Provider
==================================
Performs directory and file discovery on priority hosts:
  - Runs ONLY on cluster representatives and 401/403 (is_interesting) hosts.
  - Never runs on every live host.
  - Auto-calibration (-ac) is mandatory to suppress soft-404 false positives.
  - Enforces project rate limits, per-host result caps (default 200), and custom -H headers.
  - Configurable wordlists under ~/wordlists in WSL.
  - Hosts flagged CDN/WAF use a reduced rate (max 5 rps) and small wordlist with no recursion.
  - Every discovered URL passes is_in_scope before emission and storage.
"""

import asyncio
import json
import logging
import os
import platform
import subprocess
import tempfile
import time
from typing import Any, AsyncGenerator, Dict, List, Optional, Set
from urllib.parse import urlparse

from app.core.scope import is_in_scope
from app.providers.base import BaseProvider

logger = logging.getLogger("reconforge.providers.ffuf")

# Default wordlist search candidates in WSL/Linux
WORDLIST_CANDIDATES = {
    "small": [
        "~/wordlists/common-1k.txt",
        "~/wordlists/fast-common.txt",
        "~/wordlists/common.txt",
        "~/wordlists/SecLists/Discovery/Web-Content/common.txt",
        "/usr/share/wordlists/dirb/common.txt",
        "/usr/share/wordlists/seclists/Discovery/Web-Content/common.txt",
        "/usr/share/seclists/Discovery/Web-Content/common.txt",
    ],
    "medium": [
        "~/wordlists/raft-medium-words.txt",
        "~/wordlists/SecLists/Discovery/Web-Content/raft-medium-words.txt",
        "~/wordlists/SecLists/Discovery/Web-Content/raft-medium-directories.txt",
        "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt",
        "/usr/share/wordlists/seclists/Discovery/Web-Content/raft-medium-words.txt",
        "/usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt",
    ],
}

DEFAULT_FALLBACK_WORDS = [
    "admin", "api", "v1", "v2", "login", "dashboard", "portal", "console",
    "docs", "swagger", "openapi.json", "graphql", "graphiql", "config",
    "health", "status", "robots.txt", "sitemap.xml", ".env", "test",
    "backup", "staging", "dev", "internal", "auth", "oauth", "user",
    "register", "profile", "settings", "manage", "metrics", "debug",
    "actuator", "version", "app", "assets", "static", "public"
]


class FfufProvider(BaseProvider):
    @property
    def name(self) -> str:
        return "ffuf"

    @property
    def description(self) -> str:
        return "Priority-scoped web directory and file discovery using FFUF auto-calibration."

    def _resolve_wordlist_path(self, mode: str, custom_path: Optional[str] = None) -> str:
        """Resolves the wordlist path for WSL/Linux execution."""
        if custom_path and str(custom_path).strip():
            return str(custom_path).strip()

        is_windows = platform.system().lower() == "windows"
        wsl_user = os.getenv("WSL_USER", "kali")
        home_prefix = f"/home/{wsl_user}" if is_windows else os.path.expanduser("~")

        key = "small" if mode == "fast" else "medium"
        candidates = WORDLIST_CANDIDATES.get(key, WORDLIST_CANDIDATES["small"])

        for cand in candidates:
            resolved = cand.replace("~", home_prefix)
            if not is_windows:
                if os.path.exists(resolved):
                    return resolved
            else:
                # In WSL, return candidate formatted with home
                return resolved

        return f"{home_prefix}/wordlists/common.txt"

    def _get_wordlist_length(self, wl_path: str, is_windows: bool = False) -> int:
        """Determines or estimates wordlist line count."""
        try:
            if os.path.exists(wl_path):
                with open(wl_path, "r", encoding="utf-8", errors="ignore") as f:
                    return max(1, sum(1 for _ in f))
            # Known standard SecLists wordlists line count heuristics
            if "common-1k" in wl_path:
                return 1000
            if "raft-medium" in wl_path:
                return 60000
            if "common.txt" in wl_path:
                return 4700
            if is_windows:
                res = subprocess.run(["wsl", "-e", "wc", "-l", wl_path], capture_output=True, text=True, timeout=5)
                if res.returncode == 0 and res.stdout.strip():
                    parts = res.stdout.strip().split()
                    if parts and parts[0].isdigit():
                        return max(1, int(parts[0]))
        except Exception:
            pass
        return 1000

    def _create_fallback_wordlist(self) -> str:
        """Creates a temporary ~1k-line wordlist when no external SecLists files are present."""
        tmp = tempfile.NamedTemporaryFile(mode="w+", delete=False, suffix=".txt", encoding="utf-8")
        words = list(DEFAULT_FALLBACK_WORDS)
        if len(words) < 1000:
            base_words = list(words)
            for i in range(1, 15):
                for w in base_words:
                    words.append(f"{w}_{i}")
                    if len(words) >= 1000:
                        break
                if len(words) >= 1000:
                    break
            for n in range(1, 1001 - len(words) + 1):
                words.append(f"endpoint_{n}")
                if len(words) >= 1000:
                    break
        tmp.write("\n".join(words[:1000]) + "\n")
        tmp.close()
        return tmp.name

    @classmethod
    def build_cmd(
        cls,
        tool_path: str,
        fuzz_url: str,
        wordlist_path: str,
        wsl_out_path: str,
        rate_limit: int = 20,
        threads: int = 20,
        scan_mode: str = "fast",
        custom_headers: Optional[Dict[str, str]] = None,
        detected_tech: Optional[List[str]] = None,
        maxtime: int = 120,
        maxtime_job: int = 120,
        is_waf: bool = False,
        is_windows: bool = False,
    ) -> List[str]:
        """
        Builds the FFUF command line argument list.
        Enforces auto-calibration (-ac), hard time limits (-maxtime, -maxtime-job),
        project rate limits (-rate), and custom headers (-H).
        NEVER uses -r (redirect following).
        Fast mode: small wordlist, no recursion.
        Deep mode: larger wordlist, tech-based extensions, recursion depth max 1.
        WAF/CDN hosts: forces small wordlist, no recursion, and reduced rate limit.
        """
        current_rate = min(rate_limit, 5) if is_waf else rate_limit
        current_threads = min(current_rate, 8) if is_waf else min(threads, current_rate)
        current_mode = "fast" if is_waf else scan_mode

        cmd: List[str] = ["wsl", "-e"] if is_windows else []
        cmd.extend([
            tool_path,
            "-u", fuzz_url,
            "-w", wordlist_path,
            "-ac",                      # Auto-calibrate soft-404 suppression
            "-rate", str(current_rate),
            "-t", str(current_threads),
            "-timeout", "10",
            "-maxtime", str(maxtime),
            "-maxtime-job", str(maxtime_job),
            "-mc", "200,204,301,302,307,401,403",
            "-of", "json",
            "-o", wsl_out_path,
            "-s",                       # Silent progress output
        ])

        # Recursion & extensions in deep mode (skipped on WAF hosts)
        if current_mode == "deep" and not is_waf:
            cmd.extend(["-recursion", "-recursion-depth", "1"])
            # Tech-based extensions
            exts = [".json", ".html"]
            host_tech = [t.lower() for t in (detected_tech or [])]
            if any("php" in t for t in host_tech):
                exts.append(".php")
            if any("asp" in t or "iis" in t or ".net" in t for t in host_tech):
                exts.extend([".asp", ".aspx"])
            if any("java" in t or "spring" in t or "tomcat" in t for t in host_tech):
                exts.append(".jsp")
            if exts:
                cmd.extend(["-e", ",".join(exts)])

        # Custom headers (-H)
        if custom_headers:
            for h_name, h_val in custom_headers.items():
                if h_name and h_val:
                    cmd.extend(["-H", f"{h_name}: {h_val}"])

        return cmd

    async def discover(self, seed_domains: List[str], **kwargs: Any) -> AsyncGenerator[Dict[str, Any], None]:
        """BaseProvider compatibility wrapper."""
        async for item in self.discover_content(seed_domains, **kwargs):
            yield item

    async def discover_content(
        self,
        targets: List[str],
        scan_mode: str = "fast",
        rate_limit: int = 20,
        custom_headers: Optional[Dict[str, str]] = None,
        scope: Optional[Dict[str, List[str]]] = None,
        wordlist_path: Optional[str] = None,
        max_results_per_host: int = 200,
        waf_detected_hosts: Optional[Set[str]] = None,
        detected_tech_per_host: Optional[Dict[str, List[str]]] = None,
    ) -> AsyncGenerator[Dict[str, Any], None]:
        """
        Executes FFUF content discovery on filtered priority targets.
        Yields logs, content_path_event events, and Asset documents.
        """
        if not targets:
            yield {
                "type": "scan_summary",
                "provider": self.name,
                "status": "SKIPPED",
                "count": 0,
                "reason": "no_priority_targets",
            }
            return

        is_windows = platform.system().lower() == "windows"
        try:
            tool_path = self.detect_tool("ffuf")
        except ValueError as err:
            logger.warning("[ffuf] Tool detection failed: %s", err)
            yield {
                "type": "stage_skipped",
                "stage": "Content Discovery (ffuf)",
                "tool": "ffuf",
                "reason": f"tool_missing: {err}",
            }
            return

        waf_hosts = set(waf_detected_hosts or [])
        tech_map = detected_tech_per_host or {}
        custom_headers = custom_headers or {}

        # Fallback wordlist file created on host
        host_fallback_file = self._create_fallback_wordlist()
        wsl_fallback_file = self.wsl_path_convert(host_fallback_file) if is_windows else host_fallback_file

        total_discovered = 0
        total_targets_scanned = 0
        start_ts = time.time()

        yield {
            "type": "log",
            "message": f"\n========== Content Discovery (FFUF) ==========\n"
                       f"[*] Launching FFUF on {len(targets)} priority hosts (Mode: {scan_mode.upper()})...\n"
                       f"[*] Auto-calibration (-ac) active | Per-host result cap: {max_results_per_host}",
        }

        try:
            for target_url in targets:
                target_url = target_url.strip().rstrip("/")
                if not target_url:
                    continue

                parsed = urlparse(target_url)
                host = parsed.netloc.lower() or parsed.path.split("/")[0].lower()
                if ":" in host:
                    host = host.split(":")[0]

                # Scope verification
                if not is_in_scope(target_url, scope):
                    yield {
                        "type": "log",
                        "message": f"[*] Scope exclusion: target {target_url} skipped from content discovery.",
                    }
                    continue

                total_targets_scanned += 1
                is_waf = host in waf_hosts

                # Rate limit calculation: reduce significantly for WAF/CDN hosts
                current_rate = min(rate_limit, 5) if is_waf else rate_limit
                current_threads = min(current_rate, 8) if is_waf else min(current_rate, 20)

                # Wordlist selection
                current_mode = "fast" if is_waf else scan_mode
                resolved_wl = self._resolve_wordlist_path(current_mode, wordlist_path)

                # Output temp file for JSON results
                out_tmp = tempfile.NamedTemporaryFile(suffix=".json", delete=False)
                out_tmp.close()
                wsl_out_path = self.wsl_path_convert(out_tmp.name) if is_windows else out_tmp.name

                # Target fuzzing URL
                fuzz_url = f"{target_url}/FUZZ"
                
                # Requirement 6: Derive -maxtime from wordlist length / rate (with a cap)
                import math
                wl_len = self._get_wordlist_length(resolved_wl, is_windows=is_windows)
                derived_time = int(math.ceil(wl_len / max(current_rate, 1))) + 15
                max_cap = 300 if current_mode == "fast" else 600
                host_timeout = max(30, min(derived_time, max_cap))

                # Build command using verified builder
                cmd = self.build_cmd(
                    tool_path=tool_path,
                    fuzz_url=fuzz_url,
                    wordlist_path=resolved_wl,
                    wsl_out_path=wsl_out_path,
                    rate_limit=current_rate,
                    threads=current_threads,
                    scan_mode=current_mode,
                    custom_headers=custom_headers,
                    detected_tech=tech_map.get(host, []),
                    maxtime=host_timeout,
                    maxtime_job=host_timeout,
                    is_waf=is_waf,
                    is_windows=is_windows,
                )

                yield {"type": "log", "message": self.format_cmd_log(cmd)}

                # Process execution with cancellation & timeout check
                from app.job_control import register_process, unregister_process, check_job_status, kill_process_tree
                await check_job_status()

                proc = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                )
                register_process(proc)

                timed_out = False
                try:
                    loop = asyncio.get_event_loop()
                    await asyncio.wait_for(loop.run_in_executor(None, proc.wait), timeout=host_timeout)
                except asyncio.TimeoutError:
                    timed_out = True
                    kill_process_tree(proc, "ffuf")
                    yield {
                        "type": "stage_timeout",
                        "stage": "content_discovery",
                        "tool": "ffuf",
                        "reason": f"ffuf timeout ({host_timeout}s) exceeded for {target_url}",
                    }
                    yield {"type": "log", "message": f"[-] FFUF timeout ({host_timeout}s) exceeded for {target_url}."}
                finally:
                    unregister_process(proc)

                proc_out = ""
                proc_err = ""
                try:
                    if proc.stdout is not None:
                        out_val = proc.stdout.read()
                        if isinstance(out_val, str):
                            proc_out = out_val
                        elif isinstance(out_val, bytes):
                            proc_out = out_val.decode("utf-8", "ignore")
                    if proc.stderr is not None:
                        err_val = proc.stderr.read()
                        if isinstance(err_val, str):
                            proc_err = err_val
                        elif isinstance(err_val, bytes):
                            proc_err = err_val.decode("utf-8", "ignore")
                except Exception:
                    pass

                # Requirement 4: If tool exits non-zero (including 4294967295 / WSL errors),
                # discard stdout, emit stage_error, and never parse stdout of a failed process
                ret = getattr(proc, "returncode", None)
                if not isinstance(ret, int):
                    if hasattr(proc, "poll") and callable(getattr(proc, "poll", None)):
                        try:
                            p_ret = proc.poll()
                            if isinstance(p_ret, int):
                                ret = p_ret
                        except Exception:
                            pass
                if not isinstance(ret, int) and hasattr(proc, "wait") and callable(getattr(proc, "wait", None)):
                    try:
                        w_ret = proc.wait()
                        if isinstance(w_ret, int):
                            ret = w_ret
                    except Exception:
                        pass
                if not isinstance(ret, int):
                    ret = 0

                if ret != 0 and not timed_out:
                    err_msg = proc_err.strip() or f"Process exited with code {ret}"
                    if ret == 127 or "not found" in err_msg.lower():
                        from app.core.tools import invalidate_tool_cache
                        invalidate_tool_cache("ffuf")
                    logger.error(f"[ffuf] Tool ffuf exited with non-zero exit code {ret} on {target_url}: {err_msg}")
                    yield {
                        "type": "stage_error",
                        "stage": "content_discovery",
                        "tool": "ffuf",
                        "returncode": ret,
                        "error": f"Tool ffuf exited with code {ret}",
                        "reason": f"Tool ffuf exited with code {ret}: {err_msg}",
                    }
                    yield {"type": "log", "message": f"[-] Stage error: ffuf exited with code {ret} on {target_url}: {err_msg[:120]}"}
                    try:
                        if os.path.exists(out_tmp.name):
                            os.unlink(out_tmp.name)
                    except Exception:
                        pass
                    continue

                import re
                req_matches = re.findall(r"Progress:\s*\[(\d+)/\d+\]", proc_out + " " + proc_err)
                requests_sent = int(req_matches[-1]) if req_matches else wl_len

                # Parse JSON output from temp file (keeping partial output on timeout)
                host_findings = 0
                results = []
                calibration_meta = []
                if os.path.exists(out_tmp.name) and os.path.getsize(out_tmp.name) > 0:
                    try:
                        try:
                            with open(out_tmp.name, "r", encoding="utf-8", errors="replace") as f:
                                data = json.load(f)

                            results = data.get("results") or []
                            config_meta = data.get("config") or {}
                            calibration_meta = config_meta.get("autocalibration_strings", [])
                        except Exception as json_err:
                            # Attempt recovery of complete JSON objects if cut off mid-write
                            logger.debug("[ffuf] Attempting partial JSON recovery: %s", json_err)
                            try:
                                with open(out_tmp.name, "r", encoding="utf-8", errors="replace") as f:
                                    raw_content = f.read()
                                obj_matches = re.findall(r'(\{"input":.*?,"resultfile":""\})', raw_content)
                                for om in obj_matches:
                                    try:
                                        results.append(json.loads(om))
                                    except Exception:
                                        pass
                            except Exception:
                                pass

                        # Requirement 6: If every response is 400, emit a warning
                        if results and all(int(r.get("status", 0)) == 400 for r in results):
                            warn_400 = f"[!] WARNING: Target {host} returned HTTP 400 Bad Request for all responses ({len(results)} responses)."
                            logger.warning(warn_400)
                            yield {"type": "log", "message": warn_400}
                            yield {
                                "type": "warning_event",
                                "warning": "ffuf_all_400",
                                "host": host,
                                "message": warn_400,
                            }

                        for r in results:
                            if host_findings >= max_results_per_host:
                                yield {
                                    "type": "log",
                                    "message": f"[*] Per-host result cap ({max_results_per_host}) reached for {host}.",
                                }
                                break

                            path_url = r.get("url") or f"{target_url}/{r.get('input', {}).get('FUZZ', '')}"
                            status_code = int(r.get("status") or 200)
                            content_len = int(r.get("length") or 0)
                            words = int(r.get("words") or 0)
                            lines = int(r.get("lines") or 0)
                            redirect_loc = r.get("redirectlocation") or ""

                            # Strict scope verification
                            if not is_in_scope(path_url, scope):
                                continue

                            host_findings += 1
                            total_discovered += 1

                            asset_doc = {
                                "domain": host,
                                "type": "content_path",
                                "value": path_url,
                                "status": "live",
                                "status_code": status_code,
                                "status_class": f"{status_code // 100}xx",
                                "is_interesting": status_code in (401, 403),
                                "metadata": {
                                    "url": path_url,
                                    "host": host,
                                    "status_code": status_code,
                                    "content_length": content_len,
                                    "words": words,
                                    "lines": lines,
                                    "redirect_location": redirect_loc,
                                    "calibration_used": True,
                                    "calibration_strings": calibration_meta,
                                    "source": "ffuf",
                                },
                                "discovered_by": "ffuf",
                                "sources": ["ffuf"],
                            }

                            yield {"type": "asset", "data": asset_doc}
                            yield {
                                "type": "content_path_event",
                                "data": {
                                    "host": host,
                                    "url": path_url,
                                    "status_code": status_code,
                                    "content_length": content_len,
                                    "source": "ffuf",
                                },
                            }
                    except Exception as parse_err:
                        logger.debug("[ffuf] Error parsing JSON output: %s", parse_err)
                else:
                    logger.debug("[ffuf] No output file produced or output was empty for %s", target_url)

                try:
                    if os.path.exists(out_tmp.name):
                        os.unlink(out_tmp.name)
                except Exception:
                    pass

                yield {
                    "type": "log",
                    "message": f"[*] FFUF finished on {host}: {requests_sent} requests sent, {host_findings} content paths discovered.",
                }
        finally:
            try:
                if os.path.exists(host_fallback_file):
                    os.unlink(host_fallback_file)
            except Exception:
                pass

        duration = round(time.time() - start_ts, 2)
        yield {
            "type": "scan_summary",
            "provider": self.name,
            "status": "completed",
            "count": total_discovered,
            "targets_scanned": total_targets_scanned,
            "duration_seconds": duration,
        }
        yield {
            "type": "log",
            "message": f"[√] FFUF Content Discovery completed. Total paths: {total_discovered} | Duration: {duration}s",
        }

