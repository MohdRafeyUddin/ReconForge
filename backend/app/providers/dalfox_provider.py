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

    async def discover(
        self,
        seed_domains: List[str],
        rate_limit: Optional[int] = None,
        custom_headers: Optional[Dict[str, str]] = None,
    ) -> AsyncGenerator[Dict[str, Any], None]:
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
        
        tool_path = self.detect_tool("dalfox") or "dalfox"
        is_windows = platform.system().lower() == "windows"

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
            
            # Rate limit and concurrency
            worker_count = min(rate_limit, 10) if rate_limit else 5
            delay_ms = int(1000 / rate_limit) if rate_limit and rate_limit > 0 else 0

            dalfox_flags = ["file", wsl_temp_path if is_windows else temp_path, "--silent", "--worker", str(worker_count)]
            if delay_ms > 0:
                dalfox_flags.extend(["--delay", str(delay_ms)])

            if custom_headers:
                for hk, hv in custom_headers.items():
                    if hk and hv:
                        dalfox_flags.extend(["-H", f"{hk}: {hv}"])

            if is_windows:
                cmd = ["wsl", "-e", tool_path, *dalfox_flags]
            else:
                cmd = [tool_path, *dalfox_flags]
                
            exec_msg = self.format_cmd_log(cmd)
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
                if exit_code == 127:
                    from app.core.tools import invalidate_tool_cache
                    invalidate_tool_cache("dalfox")
                    yield {
                        "type": "stage_error",
                        "stage": "validation",
                        "tool": "dalfox",
                        "message": f"Dalfox executable not found at {tool_path}",
                    }
                logger.warning(f"[-] Dalfox exited with code {exit_code}")
                yield {"type": "log", "message": f"[-] Dalfox exited with code {exit_code}"}
                
        except Exception as exc:
            if "not found" in str(exc).lower() or isinstance(exc, FileNotFoundError):
                from app.core.tools import invalidate_tool_cache
                invalidate_tool_cache("dalfox")
                yield {
                    "type": "stage_error",
                    "stage": "validation",
                    "tool": "dalfox",
                    "message": f"Dalfox execution failed: {exc}",
                }
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
