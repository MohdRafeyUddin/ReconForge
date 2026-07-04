import asyncio
import logging
import os
import platform
import re
import subprocess
import tempfile
import time
from datetime import datetime
from typing import AsyncGenerator, Dict, Any, List
from urllib.parse import urlparse, parse_qs
from app.providers.base import BaseProvider

logger = logging.getLogger("reconforge.providers.dalfox")

class DalfoxProvider(BaseProvider):
    @property
    def name(self) -> str:
        return "Dalfox"

    @property
    def description(self) -> str:
        return "Confirms Cross-Site Scripting (XSS) vulnerabilities."

    async def discover(self, seed_domains: List[str]) -> AsyncGenerator[Dict[str, Any], None]:
        urls = list(dict.fromkeys(u.strip() for u in seed_domains if u and u.strip()))
        
        yield {"type": "log", "message": "\n========== Dalfox XSS Confirmation =========="}

        if not urls:
            msg = "Dalfox completed. No input URLs provided."
            logger.info(msg)
            yield {"type": "log", "message": msg}
            yield {
                "type": "scan_summary",
                "provider": "dalfox",
                "confirmed_xss": 0,
                "status": "completed",
                "count": 0,
                "skipped_reason": "no_live_hosts_upstream"
            }
            yield {"type": "log", "message": "[√] Provider dalfox completed"}
            return

        yield {"type": "log", "message": "Launching Dalfox..."}
        
        tool_path = self.detect_tool("dalfox")
        is_windows = platform.system().lower() == "windows"
        
        # Verify tool works/exists
        test_cmd = ["wsl", "test", "-x", tool_path] if is_windows else ["test", "-x", tool_path]
        try:
            res = subprocess.run(test_cmd, capture_output=True, timeout=5)
            if res.returncode != 0 and not tool_path.startswith("dalfox"):
                # Graceful skip
                warn_msg = f"[!] Dalfox executable not found or not executable at {tool_path}. Skipping Dalfox."
                logger.warning(warn_msg)
                yield {"type": "log", "message": warn_msg}
                yield {
                    "type": "scan_summary",
                    "provider": "dalfox",
                    "confirmed_xss": 0,
                    "status": "SKIPPED"
                }
                yield {"type": "log", "message": "[!] Provider dalfox skipped"}
                return
        except Exception as exc:
            warn_msg = f"[!] Error detecting Dalfox executable: {exc}. Skipping Dalfox."
            logger.warning(warn_msg)
            yield {"type": "log", "message": warn_msg}
            yield {
                "type": "scan_summary",
                "provider": "dalfox",
                "confirmed_xss": 0,
                "status": "SKIPPED"
            }
            yield {"type": "log", "message": "[!] Provider dalfox skipped"}
            return

        yield {"type": "log", "message": f"[*] Testing {len(urls)} XSS parameter targets..."}
        
        temp_path = ""
        start_ts = time.time()
        confirmed_count = 0
        poc_regex = re.compile(r"\[POC\]\[([A-Z])\]\[([a-zA-Z0-9_-]+)\]\s+(https?://\S+)")
        
        try:
            with tempfile.NamedTemporaryFile(
                mode="w",
                encoding="utf-8",
                delete=False,
                suffix=".txt",
                dir=os.getcwd()
            ) as target_file:
                target_file.write("\n".join(urls))
                target_file.write("\n")
                temp_path = target_file.name
                
            wsl_temp_path = self.wsl_path_convert(temp_path)
            
            # Build command with low concurrency as requested
            if is_windows:
                cmd = ["wsl", tool_path, "file", wsl_temp_path, "--silent", "--concurrency", "5"]
            else:
                cmd = [tool_path, "file", temp_path, "--silent", "--concurrency", "5"]
                
            exec_msg = f"[*] Executing command: {' '.join(cmd)}"
            logger.info(exec_msg)
            yield {"type": "log", "message": exec_msg}
            
            from app.job_control import register_process, unregister_process, check_job_status
            await check_job_status()
            
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding="utf-8",
                errors="replace",
                bufsize=1
            )
            register_process(process)
            
            timeout = 900
            loop = asyncio.get_event_loop()
            
            async def read_stream():
                nonlocal confirmed_count
                assert process.stdout is not None
                while True:
                    await check_job_status()
                    line = await loop.run_in_executor(None, process.stdout.readline)
                    if not line:
                        break
                    clean_line = line.strip()
                    if not clean_line:
                        continue
                        
                    logger.debug(f"[dalfox] {clean_line}")
                    
                    # Yield log line for operator terminal
                    if "POC" in clean_line:
                        yield {"type": "log", "message": f"[+] Dalfox POC: {clean_line}"}
                        
                    match = poc_regex.search(clean_line)
                    if match:
                        method = match.group(1)
                        vuln_type = match.group(2)
                        vulnerable_url = match.group(3)
                        
                        # Parse parameters & payloads
                        parameter = "unknown"
                        payload = ""
                        try:
                            parsed = urlparse(vulnerable_url)
                            params = parse_qs(parsed.query)
                            for k, v_list in params.items():
                                for val in v_list:
                                    if any(char in val for char in ["<", ">", "alert", "script", "onclick"]):
                                        parameter = k
                                        payload = val
                                        break
                                if parameter != "unknown":
                                    break
                            if parameter == "unknown" and params:
                                parameter = list(params.keys())[0]
                                payload = params[parameter][0] if params[parameter] else ""
                        except Exception:
                            pass
                            
                        confirmed_count += 1
                        
                        # Yield flat finding asset
                        yield {
                            "type": "asset",
                            "data": {
                                "domain": vulnerable_url,
                                "type": "finding",
                                "status": "live",
                                "metadata": {
                                    "source": "dalfox",
                                    "severity": "high",
                                    "matched_url": vulnerable_url,
                                    "payload": payload,
                                    "parameter": parameter,
                                    "evidence": clean_line,
                                    "timestamp": datetime.utcnow().isoformat()
                                },
                                "discovered_by": "dalfox",
                                "sources": ["dalfox"]
                            }
                        }
                        
                        # Yield finding_event
                        yield {
                            "type": "finding_event",
                            "data": {
                                "source": "dalfox",
                                "severity": "high",
                                "matched_url": vulnerable_url,
                                "payload": payload,
                                "parameter": parameter,
                                "evidence": clean_line,
                                "timestamp": datetime.utcnow().isoformat()
                            }
                        }
                    await asyncio.sleep(0)
                    
            try:
                async for event in read_stream():
                    yield event
            except asyncio.TimeoutError:
                logger.warning(f"[-] Dalfox scan timed out after {timeout}s. Terminating process.")
                yield {"type": "log", "message": f"[-] Dalfox scan timed out after {timeout} seconds."}
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
                logger.warning(f"[-] Dalfox exited with code {exit_code}")
                yield {"type": "log", "message": f"[-] Dalfox exited with code {exit_code}"}
                
        except Exception as exc:
            err_msg = f"[-] Dalfox execution failed: {exc}"
            logger.exception(err_msg)
            yield {"type": "log", "message": err_msg}
            
        finally:
            if temp_path and os.path.exists(temp_path):
                try:
                    os.unlink(temp_path)
                except Exception:
                    pass
                    
        duration_s = int(time.time() - start_ts)
        complete_msg = f"[√] Dalfox XSS Scan complete. Confirmed findings: {confirmed_count}"
        yield {"type": "log", "message": complete_msg}
        yield {
            "type": "scan_summary",
            "provider": "dalfox",
            "status": "completed",
            "count": confirmed_count
        }
        yield {"type": "log", "message": "[√] Provider dalfox completed"}
