import asyncio
import logging
import os
import platform
import subprocess
import time
from typing import AsyncGenerator, Dict, Any, List
from urllib.parse import urlparse
from app.providers.base import BaseProvider

logger = logging.getLogger("reconforge.providers.gau")

class GauProvider(BaseProvider):
    @property
    def name(self) -> str:
        return "GAU"

    @property
    def description(self) -> str:
        return "Queries historical URLs using Wayback Machine, Common Crawl, and OTX."

    async def discover(self, seed_domains: List[str]) -> AsyncGenerator[Dict[str, Any], None]:
        hosts = list(dict.fromkeys(h.strip().lower() for h in seed_domains if h and h.strip()))
        
        yield {"type": "log", "message": "\n========== GAU Historical URLs =========="}

        if not hosts:
            msg = "GAU completed. No target hosts provided."
            logger.info(msg)
            yield {"type": "log", "message": msg}
            yield {
                "type": "scan_summary",
                "provider": "gau",
                "urls_found": 0,
                "historical_urls": 0,
                "skipped_reason": "no_live_hosts_upstream"
            }
            return

        yield {"type": "log", "message": "Launching GAU..."}
        
        tool_path = self.detect_tool("gau")
        is_windows = platform.system().lower() == "windows"
        
        # Verify tool works/exists in WSL/Linux
        test_cmd = ["wsl", "test", "-x", tool_path] if is_windows else ["test", "-x", tool_path]
        try:
            res = subprocess.run(test_cmd, capture_output=True, timeout=5)
            if res.returncode != 0 and not tool_path.startswith("gau"):
                # Graceful skip
                warn_msg = f"[!] GAU executable not found or not executable at {tool_path}. Skipping GAU."
                logger.warning(warn_msg)
                yield {"type": "log", "message": warn_msg}
                yield {
                    "type": "scan_summary",
                    "provider": "gau",
                    "urls_found": 0,
                    "historical_urls": 0,
                    "status": "SKIPPED"
                }
                yield {"type": "log", "message": "[!] Provider gau skipped"}
                return
        except Exception as exc:
            warn_msg = f"[!] Error detecting GAU executable: {exc}. Skipping GAU."
            logger.warning(warn_msg)
            yield {"type": "log", "message": warn_msg}
            yield {
                "type": "scan_summary",
                "provider": "gau",
                "urls_found": 0,
                "historical_urls": 0,
                "status": "SKIPPED"
            }
            yield {"type": "log", "message": "[!] Provider gau skipped"}
            return

        yield {"type": "log", "message": f"[*] Querying historical URLs for {len(hosts)} hosts..."}
        
        # Build command
        if is_windows:
            cmd = ["wsl", tool_path, "--providers", "wayback,commoncrawl,otx"]
        else:
            cmd = [tool_path, "--providers", "wayback,commoncrawl,otx"]
            
        exec_msg = f"[*] Executing command: {' '.join(cmd)}"
        logger.info(exec_msg)
        yield {"type": "log", "message": exec_msg}
        
        start_ts = time.time()
        urls_found_count = 0
        seen_urls = set()
        
        try:
            from app.job_control import register_process, unregister_process, check_job_status
            await check_job_status()
            
            process = subprocess.Popen(
                cmd,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding="utf-8",
                errors="replace",
                bufsize=1
            )
            register_process(process)
            
            # Write hosts to stdin
            try:
                process.stdin.write("\n".join(hosts) + "\n")
                process.stdin.close()
            except Exception as e:
                logger.error(f"Error writing to GAU stdin: {e}")
                
            # Read stdout with timeout protection (300 seconds)
            timeout = 300
            loop = asyncio.get_event_loop()
            
            async def read_stream():
                nonlocal urls_found_count
                assert process.stdout is not None
                while True:
                    await check_job_status()
                    line = await loop.run_in_executor(None, process.stdout.readline)
                    if not line:
                        break
                    url = line.strip()
                    if not url:
                        continue
                        
                    urls_found_count += 1
                    if url not in seen_urls:
                        seen_urls.add(url)
                        try:
                            parsed = urlparse(url)
                            has_params = bool(parsed.query)
                            path = parsed.path
                            ext = os.path.splitext(path)[1].lstrip('.').lower()
                        except Exception:
                            has_params = False
                            ext = ""
                            
                        yield {
                            "type": "url_event",
                            "data": {
                                "url": url,
                                "original_url": url,
                                "source": "gau",
                                "has_params": has_params,
                                "extension": ext,
                                "discovered_at": int(time.time())
                            }
                        }
                    await asyncio.sleep(0)
                    
            try:
                # Run the read_stream and enforce timeout
                async for event in read_stream():
                    yield event
            except asyncio.TimeoutError:
                logger.warning(f"[-] GAU scan timed out after {timeout}s. Terminating process.")
                yield {"type": "log", "message": f"[-] GAU scan timed out after {timeout} seconds."}
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
                logger.warning(f"[-] GAU exited with code {exit_code}")
                yield {"type": "log", "message": f"[-] GAU exited with code {exit_code}"}
                
        except Exception as exc:
            err_msg = f"[-] GAU execution failed: {exc}"
            logger.exception(err_msg)
            yield {"type": "log", "message": err_msg}
            
        duration_s = int(time.time() - start_ts)
        complete_msg = f"[√] GAU completed. Total historical URLs found: {urls_found_count} (Unique: {len(seen_urls)})"
        yield {"type": "log", "message": complete_msg}
        yield {
            "type": "scan_summary",
            "provider": "gau",
            "status": "completed",
            "count": len(seen_urls)
        }
        yield {"type": "log", "message": "[√] Provider gau completed"}
