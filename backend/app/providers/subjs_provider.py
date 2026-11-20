import asyncio
import logging
import os
import platform
import subprocess
import tempfile
import time
from typing import AsyncGenerator, Dict, Any, List
from urllib.parse import urlparse
from app.providers.base import BaseProvider

logger = logging.getLogger("reconforge.providers.subjs")

class SubjsProvider(BaseProvider):
    @property
    def name(self) -> str:
        return "SubJS"

    @property
    def description(self) -> str:
        return "Discovers JavaScript files from live HTTPX URLs."

    async def discover(self, seed_domains: List[str]) -> AsyncGenerator[Dict[str, Any], None]:
        urls = list(dict.fromkeys(u.strip() for u in seed_domains if u and u.strip()))
        
        yield {"type": "log", "message": "\n========== SubJS JavaScript Discovery =========="}

        if not urls:
            msg = "SubJS completed. No input URLs provided."
            logger.info(msg)
            yield {"type": "log", "message": msg}
            yield {
                "type": "scan_summary",
                "provider": "subjs",
                "js_files": 0,
                "skipped_reason": "no_live_hosts_upstream"
            }
            return

        yield {"type": "log", "message": "Launching SubJS..."}
        
        tool_path = self.detect_tool("subjs") or "subjs"
        is_windows = platform.system().lower() == "windows"

        yield {"type": "log", "message": f"[*] Scanning {len(urls)} URLs for JS files..."}

        # SubJS only reads URLs from a file (-i); it ignores stdin.
        temp_in = tempfile.NamedTemporaryFile(
            mode="w", delete=False, suffix=".txt", encoding="utf-8", newline="\n"
        )
        for url in urls:
            temp_in.write(f"{url}\n")
        temp_in.close()
        wsl_in = self.wsl_path_convert(temp_in.name) if is_windows else temp_in.name
        if is_windows:
            cmd = ["wsl", "-e", tool_path, "-i", wsl_in, "-c", "10", "-t", "15"]
        else:
            cmd = [tool_path, "-i", wsl_in, "-c", "10", "-t", "15"]

        yield {"type": "log", "message": self.format_cmd_log(cmd)}

        start_ts = time.time()
        js_files_found = set()
        
        try:
            from app.job_control import register_process, unregister_process, check_job_status
            await check_job_status()
            
            process = subprocess.Popen(
                cmd,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding="utf-8",
                errors="replace",
                bufsize=1
            )
            register_process(process)

            # Read stdout with timeout protection (300 seconds)
            timeout = 300
            loop = asyncio.get_event_loop()
            
            async def read_stream():
                assert process.stdout is not None
                while True:
                    await check_job_status()
                    line = await loop.run_in_executor(None, process.stdout.readline)
                    if not line:
                        break
                    js_url = line.strip()
                    if not js_url or not js_url.startswith(("http://", "https://")):
                        continue
                        
                    if js_url not in js_files_found:
                        js_files_found.add(js_url)
                        try:
                            parsed = urlparse(js_url)
                            host = parsed.hostname or parsed.netloc
                        except Exception:
                            host = "unknown"
                            
                        # Emit standard asset for MongoDB persistence
                        yield {
                            "type": "asset",
                            "data": {
                                "domain": js_url,
                                "type": "js_file",
                                "status": "live",
                                "metadata": {
                                    "url": js_url,
                                    "host": host,
                                    "size": "unknown",
                                    "source": "subjs"
                                },
                                "discovered_by": "subjs",
                                "sources": ["subjs"]
                            }
                        }
                        
                        # Emit js_event for live WS stream
                        yield {
                            "type": "js_event",
                            "data": {
                                "url": js_url,
                                "host": host,
                                "size": "unknown",
                                "source": "subjs"
                            }
                        }
                        
                        # Yield log event
                        yield {
                            "type": "log",
                            "message": f"[+] Discovered JS file: {js_url}"
                        }
                    await asyncio.sleep(0)
                    
            try:
                async for event in read_stream():
                    yield event
            except asyncio.TimeoutError:
                logger.warning(f"[-] SubJS scan timed out after {timeout}s. Terminating process.")
                yield {"type": "log", "message": f"[-] SubJS scan timed out after {timeout} seconds."}
            finally:
                unregister_process(process)
                if process.poll() is None:
                    process.terminate()
                    try:
                        process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait()
                        
            exit_code = process.wait()
            if exit_code != 0:
                if exit_code == 127:
                    from app.core.tools import invalidate_tool_cache
                    invalidate_tool_cache("subjs")
                    yield {
                        "type": "stage_error",
                        "stage": "js_analysis",
                        "tool": "subjs",
                        "message": f"SubJS binary not found at {tool_path}",
                    }
                logger.warning(f"[-] SubJS exited with code {exit_code}")
                yield {"type": "log", "message": f"[-] SubJS exited with code {exit_code}"}
                
        except Exception as exc:
            if "not found" in str(exc).lower() or isinstance(exc, FileNotFoundError):
                from app.core.tools import invalidate_tool_cache
                invalidate_tool_cache("subjs")
                yield {
                    "type": "stage_error",
                    "stage": "js_analysis",
                    "tool": "subjs",
                    "message": f"SubJS execution failed: {exc}",
                }
            err_msg = f"[-] SubJS execution failed: {exc}"
            logger.exception(err_msg)
            yield {"type": "log", "message": err_msg}
        finally:
            try:
                if os.path.exists(temp_in.name):
                    os.unlink(temp_in.name)
            except Exception:
                pass

        duration_s = int(time.time() - start_ts)
        complete_msg = f"[√] SubJS completed. Total JavaScript files discovered: {len(js_files_found)}"
        yield {"type": "log", "message": complete_msg}
        yield {
            "type": "scan_summary",
            "provider": "subjs",
            "status": "completed",
            "count": len(js_files_found)
        }
        yield {"type": "log", "message": "[√] Provider subjs completed"}
