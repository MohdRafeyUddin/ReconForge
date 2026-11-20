import asyncio
import logging
import os
import platform
import subprocess
import time
from typing import AsyncGenerator, Dict, Any, List
from urllib.parse import urlparse
from app.core.redaction import redact_text
from app.providers.base import BaseProvider

logger = logging.getLogger("reconforge.providers.linkfinder")

class LinkfinderProvider(BaseProvider):
    @property
    def name(self) -> str:
        return "LinkFinder"

    @property
    def description(self) -> str:
        return "Extracts API endpoints and secrets from JavaScript files."

    async def discover(self, seed_domains: List[str]) -> AsyncGenerator[Dict[str, Any], None]:
        js_urls = list(dict.fromkeys(u.strip() for u in seed_domains if u and u.strip()))
        
        yield {"type": "log", "message": "\n========== LinkFinder JS Analysis =========="}

        if not js_urls:
            msg = "LinkFinder completed. No JS URLs to analyze."
            logger.info(msg)
            yield {"type": "log", "message": msg}
            yield {
                "type": "scan_summary",
                "provider": "linkfinder",
                "extracted_endpoints": 0,
                "status": "completed",
                "count": 0,
                "skipped_reason": "no_live_hosts_upstream"
            }
            yield {"type": "log", "message": "[√] Provider linkfinder completed"}
            return

        yield {"type": "log", "message": "Launching LinkFinder..."}
        
        tool_path = self.detect_tool("linkfinder")
        is_windows = platform.system().lower() == "windows"

        if not tool_path:
            err_msg = "LinkFinder script path not found (None)"
            logger.error(err_msg)
            yield {
                "type": "stage_error",
                "stage": "linkfinder",
                "tool": "linkfinder",
                "message": err_msg,
            }
            yield {
                "type": "scan_summary",
                "provider": "linkfinder",
                "extracted_endpoints": 0,
                "status": "SKIPPED",
                "reason": "tool_not_found",
            }
            yield {"type": "log", "message": "[!] Provider linkfinder skipped: tool_not_found"}
            return

        yield {"type": "log", "message": f"[*] LinkFinder: analysing {len(js_urls)} JavaScript file(s)..."}
        
        start_ts = time.time()
        endpoints_found = set()
        total_endpoints_count = 0
        has_failed_exit = False
        
        # Define secret detection keywords
        secret_keywords = {"api_key", "secret", "token", "password", "aws_access_key", "passwd", "auth_token", "jwt", "bearer", "apikey", "credential"}
        
        for js_url in js_urls:
            try:
                parsed_js = urlparse(js_url)
                host = parsed_js.hostname or parsed_js.netloc
            except Exception:
                host = "unknown"
                
            # Build command
            if is_windows:
                cmd = ["wsl", "-e", "python3", tool_path, "-i", js_url, "-o", "cli"]
            else:
                cmd = ["python3", tool_path, "-i", js_url, "-o", "cli"]
                
            yield {"type": "log", "message": self.format_cmd_log(cmd)}
            logger.debug(f"Running LinkFinder on {js_url}")
            
            try:
                from app.job_control import register_process, unregister_process, check_job_status
                await check_job_status()
                
                # Check absolute timeout for LinkFinder run on individual URL (e.g. 30 seconds)
                process = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    encoding="utf-8",
                    errors="replace"
                )
                register_process(process)
                
                url_endpoints_found = 0
                try:
                    # Give it up to 30s per URL, or overall timeout check
                    loop = asyncio.get_event_loop()
                    
                    async def read_stream():
                        assert process.stdout is not None
                        while True:
                            await check_job_status()
                            line = await loop.run_in_executor(None, process.stdout.readline)
                            if not line:
                                break
                            clean_line = line.strip()
                            if not clean_line or clean_line.startswith(("LinkFinder", "Running", "Usage")):
                                continue
                            
                            # LinkFinder outputs lines of routes or URLs. Let's parse.
                            # Standard outputs:
                            # /api/v1/users
                            # http://site.com/route
                            endpoint_candidate = clean_line
                            
                            # Check if the line is a secret candidate
                            secret_cand = None
                            line_lower = clean_line.lower()
                            if any(kw in line_lower for kw in secret_keywords) and ("=" in clean_line or ":" in clean_line):
                                # Never propagate raw candidate values to logs,
                                # WebSocket events or stored URL metadata.
                                secret_cand = redact_text(clean_line)
                                
                            yield endpoint_candidate, secret_cand
                            
                    # Process lines
                    async for endpoint, secret in read_stream():
                        # We yield a url_event with the source so it can merge
                        # We also emit linkfinder specific properties
                        ep_key = (endpoint, js_url)
                        if ep_key not in endpoints_found:
                            endpoints_found.add(ep_key)
                            url_endpoints_found += 1
                            
                            # Yield url_event for the merge engine
                            yield {
                                "type": "url_event",
                                "data": {
                                    "url": endpoint,
                                    "original_url": endpoint,
                                    "source": "linkfinder",
                                    "api_endpoint": endpoint,
                                    "js_file": js_url,
                                    "secret_candidate": secret,
                                    "host": host
                                }
                            }
                            
                            yield {
                                "type": "log",
                                "message": f"[+] LinkFinder found endpoint: {endpoint} in {js_url}" + (f" [SECRET KEY CANDIDATE DETECTED]" if secret else "")
                            }
                            
                except asyncio.TimeoutError:
                    logger.warning(f"LinkFinder timeout on URL: {js_url}")
                finally:
                    unregister_process(process)
                    if process.poll() is None:
                        process.terminate()
                        process.wait()

                # If it produces no output and exit code != 0, emit stage_error
                ret = getattr(process, "returncode", 0)
                if ret is None:
                    ret = process.poll() or 0
                if url_endpoints_found == 0 and ret != 0:
                    has_failed_exit = True
                    stderr_val = ""
                    try:
                        if process.stderr:
                            stderr_val = process.stderr.read() or ""
                    except Exception:
                        pass
                    err_snippet = stderr_val.strip()[:500] if stderr_val else f"exit code {ret}"
                    logger.error(f"[linkfinder] LinkFinder exited with code {ret} on {js_url}: {err_snippet}")
                    yield {
                        "type": "stage_error",
                        "stage": "linkfinder",
                        "tool": "linkfinder",
                        "returncode": ret,
                        "error": f"LinkFinder exited with code {ret}: {err_snippet}",
                        "reason": f"LinkFinder exited with code {ret} and produced no output: {err_snippet}",
                    }
                    yield {
                        "type": "log",
                        "message": f"[-] Stage error: LinkFinder exited with code {ret} on {js_url}: {err_snippet}",
                    }
                        
            except Exception as e:
                if "not found" in str(e).lower() or isinstance(e, FileNotFoundError):
                    from app.core.tools import invalidate_tool_cache
                    invalidate_tool_cache("linkfinder")
                    yield {
                        "type": "stage_error",
                        "stage": "linkfinder",
                        "tool": "linkfinder",
                        "message": f"LinkFinder execution failed: {e}",
                    }
                logger.error(f"Failed to run LinkFinder on {js_url}: {e}")
                
            # Sleep briefly to be nice to event loop
            await asyncio.sleep(0.05)
            
            # Enforce overall timeout protection (300 seconds)
            if time.time() - start_ts > 300:
                warn_msg = "[-] LinkFinder provider exceeded overall timeout of 300s. Stopping analysis."
                logger.warning(warn_msg)
                yield {"type": "log", "message": warn_msg}
                break

        duration_s = int(time.time() - start_ts)
        complete_msg = f"[√] LinkFinder completed. Total endpoints extracted: {len(endpoints_found)}"
        yield {"type": "log", "message": complete_msg}
        yield {
            "type": "scan_summary",
            "provider": "linkfinder",
            "status": "failed" if (len(endpoints_found) == 0 and has_failed_exit) else "completed",
            "count": len(endpoints_found)
        }
        yield {"type": "log", "message": "[√] Provider linkfinder completed"}
