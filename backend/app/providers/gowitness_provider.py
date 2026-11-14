import asyncio
import glob
import logging
import os
import platform
import subprocess
import tempfile
import time
from datetime import datetime
from typing import AsyncGenerator, Dict, Any, List
from urllib.parse import urlparse
from app.providers.base import BaseProvider

logger = logging.getLogger("reconforge.providers.gowitness")

class GowitnessProvider(BaseProvider):
    @property
    def name(self) -> str:
        return "GoWitness"

    @property
    def description(self) -> str:
        return "Captures screenshots of live HTTPX hosts using GoWitness."

    async def discover(self, seed_domains: List[str]) -> AsyncGenerator[Dict[str, Any], None]:
        urls = list(dict.fromkeys(u.strip() for u in seed_domains if u and u.strip()))
        
        yield {"type": "log", "message": "\n========== GoWitness Screenshot Capture =========="}

        if not urls:
            msg = "GoWitness completed. No target URLs provided."
            logger.info(msg)
            yield {"type": "log", "message": msg}
            yield {
                "type": "scan_summary",
                "provider": "gowitness",
                "screenshots": 0,
                "skipped_reason": "no_live_hosts_upstream"
            }
            return

        yield {"type": "log", "message": "Launching GoWitness..."}
        
        tool_path = self.detect_tool("gowitness") or "gowitness"
        is_windows = platform.system().lower() == "windows"

        yield {"type": "log", "message": f"[*] Capturing screenshots for {len(urls)} live URLs..."}
        
        # Make sure backend/screenshots folder exists so we can store images
        os.makedirs("screenshots", exist_ok=True)
        
        start_ts = time.time()
        screenshots_captured = 0
        
        for url in urls:
            try:
                parsed = urlparse(url)
                host = parsed.hostname or parsed.netloc
            except Exception:
                host = "unknown"
                
            # Create a clean temporary directory for this screenshot run
            temp_dir = tempfile.mkdtemp(dir="screenshots")
            wsl_temp_dir = self.wsl_path_convert(temp_dir)
            
            # Build command
            if is_windows:
                cmd = ["wsl", "-e", tool_path, "single", "-u", url, "--screenshot-path", wsl_temp_dir, "--write-db=false"]
            else:
                cmd = [tool_path, "single", "-u", url, "--screenshot-path", temp_dir, "--write-db=false"]
                
            logger.debug(f"Running GoWitness on {url}")
            
            try:
                from app.job_control import register_process, unregister_process, check_job_status
                await check_job_status()
                
                # Run single GoWitness capture with timeout protection (60 seconds per URL)
                process = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    encoding="utf-8",
                    errors="replace"
                )
                register_process(process)
                
                try:
                    # Run and wait for exit
                    loop = asyncio.get_event_loop()
                    await loop.run_in_executor(None, lambda: process.wait(timeout=60))
                    
                    # Find any created png file
                    png_files = glob.glob(os.path.join(temp_dir, "*.png"))
                    if png_files:
                        # Rename and move to screenshots folder
                        dest_filename = f"screenshot_{host}_{int(time.time())}.png"
                        os.rename(png_files[0], os.path.join("screenshots", dest_filename))
                        screenshots_captured += 1
                        
                        relative_path = f"/screenshots/{dest_filename}"
                        
                        # Yield standard asset event for DB storage
                        yield {
                            "type": "asset",
                            "data": {
                                "domain": url,
                                "type": "screenshot",
                                "status": "live",
                                "metadata": {
                                    "url": url,
                                    "title": f"Screenshot of {host}",
                                    "screenshot_path": relative_path,
                                    "timestamp": datetime.utcnow().isoformat(),
                                    "source": "gowitness",
                                    "host": host
                                },
                                "discovered_by": "gowitness",
                                "sources": ["gowitness"]
                            }
                        }
                        
                        # Yield screenshot_event for WS broadcast
                        yield {
                            "type": "screenshot_event",
                            "data": {
                                "url": url,
                                "title": f"Screenshot of {host}",
                                "screenshot_path": relative_path,
                                "timestamp": datetime.utcnow().isoformat(),
                                "source": "gowitness",
                                "host": host
                            }
                        }
                        
                        yield {
                            "type": "log",
                            "message": f"[+] Captured screenshot for {url}"
                        }
                    else:
                        logger.warning(f"No screenshot file created by GoWitness for {url}")
                        
                except subprocess.TimeoutExpired:
                    logger.warning(f"GoWitness screenshot capture timed out on URL: {url}")
                finally:
                    unregister_process(process)
                    if process.poll() is None:
                        process.terminate()
                        process.wait()
                        
            except Exception as e:
                if "not found" in str(e).lower() or isinstance(e, FileNotFoundError):
                    from app.core.tools import invalidate_tool_cache
                    invalidate_tool_cache("gowitness")
                    yield {
                        "type": "stage_error",
                        "stage": "visual_verification",
                        "tool": "gowitness",
                        "message": f"GoWitness execution failed: {e}",
                    }
                logger.error(f"Failed to capture screenshot for {url}: {e}")
                
            finally:
                # Remove temporary directory
                try:
                    if os.path.exists(temp_dir):
                        for f in os.listdir(temp_dir):
                            os.unlink(os.path.join(temp_dir, f))
                        os.rmdir(temp_dir)
                except Exception as e:
                    logger.warning(f"Failed to clean up temp dir {temp_dir}: {e}")
                    
            await asyncio.sleep(0.05)
            
            # Enforce overall timeout protection (600 seconds)
            if time.time() - start_ts > 600:
                warn_msg = "[-] GoWitness provider exceeded overall timeout of 600s. Stopping."
                logger.warning(warn_msg)
                yield {"type": "log", "message": warn_msg}
                break

        duration_s = int(time.time() - start_ts)
        complete_msg = f"[√] GoWitness completed. Screenshots captured: {screenshots_captured}"
        yield {"type": "log", "message": complete_msg}
        yield {
            "type": "scan_summary",
            "provider": "gowitness",
            "status": "completed",
            "count": screenshots_captured
        }
        yield {"type": "log", "message": "[√] Provider gowitness completed"}
