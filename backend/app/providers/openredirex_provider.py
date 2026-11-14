import asyncio
import logging
import os
import platform
import subprocess
import tempfile
import time
from datetime import datetime
from typing import AsyncGenerator, Dict, Any, List
from urllib.parse import urlparse, parse_qs
from app.providers.base import BaseProvider

logger = logging.getLogger("reconforge.providers.openredirex")

class OpenredirexProvider(BaseProvider):
    @property
    def name(self) -> str:
        return "OpenRedirex"

    @property
    def description(self) -> str:
        return "Confirms Open Redirect vulnerabilities."

    async def discover(
        self,
        seed_domains: List[str],
        rate_limit: Optional[int] = None,
        custom_headers: Optional[Dict[str, str]] = None,
    ) -> AsyncGenerator[Dict[str, Any], None]:
        urls = list(dict.fromkeys(u.strip() for u in seed_domains if u and u.strip()))
        
        yield {"type": "log", "message": "\n========== OpenRedirex Confirmation =========="}

        if not urls:
            msg = "OpenRedirex completed. No input URLs provided."
            logger.info(msg)
            yield {"type": "log", "message": msg}
            yield {
                "type": "scan_summary",
                "provider": "openredirex",
                "confirmed_redirects": 0,
                "status": "completed",
                "count": 0,
                "skipped_reason": "no_live_hosts_upstream"
            }
            yield {"type": "log", "message": "[√] Provider openredirex completed"}
            return

        yield {"type": "log", "message": "Launching OpenRedirex..."}
        
        tool_path = self.detect_tool("openredirex")
        is_windows = platform.system().lower() == "windows"

        if not tool_path:
            err_msg = "OpenRedirex script path not found (None)"
            logger.error(err_msg)
            yield {
                "type": "stage_error",
                "stage": "openredirex",
                "tool": "openredirex",
                "message": err_msg,
            }
            yield {
                "type": "scan_summary",
                "provider": "openredirex",
                "confirmed_redirects": 0,
                "status": "SKIPPED",
                "reason": "tool_not_found",
            }
            yield {"type": "log", "message": "[!] Provider openredirex skipped: tool_not_found"}
            return

        yield {"type": "log", "message": f"[*] Testing {len(urls)} redirect parameter targets..."}
        
        temp_urls_path = ""
        temp_payloads_path = ""
        start_ts = time.time()
        confirmed_count = 0
        
        # Core open redirect payloads
        common_payloads = [
            "https://google.com",
            "//google.com",
            r"/\/google.com",
            "https:google.com",
            "//https://google.com"
        ]
        
        try:
            # 1. Write URLs to target file
            with tempfile.NamedTemporaryFile(
                mode="w",
                encoding="utf-8",
                delete=False,
                suffix="_urls.txt",
                dir=os.getcwd()
            ) as target_file:
                target_file.write("\n".join(urls))
                target_file.write("\n")
                temp_urls_path = target_file.name
                
            # 2. Write Payloads to payloads file
            with tempfile.NamedTemporaryFile(
                mode="w",
                encoding="utf-8",
                delete=False,
                suffix="_payloads.txt",
                dir=os.getcwd()
            ) as payloads_file:
                payloads_file.write("\n".join(common_payloads))
                payloads_file.write("\n")
                temp_payloads_path = payloads_file.name
                
            wsl_urls_path = self.wsl_path_convert(temp_urls_path)
            wsl_payloads_path = self.wsl_path_convert(temp_payloads_path)
            
            # Build command using concurrency from config
            concurrency = str(rate_limit) if rate_limit else "10"
            if is_windows:
                cmd = ["wsl", "-e", "python3", tool_path, "-l", wsl_urls_path, "-p", wsl_payloads_path, "-c", concurrency]
            else:
                cmd = ["python3", tool_path, "-l", temp_urls_path, "-p", temp_payloads_path, "-c", concurrency]
                
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
            
            timeout = 600
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
                        
                    logger.debug(f"[openredirex] {clean_line}")
                    
                    # Yield log line for operator terminal
                    if "vulnerable" in clean_line.lower() or "redirect" in clean_line.lower():
                        yield {"type": "log", "message": f"[+] OpenRedirex POC: {clean_line}"}
                        
                    # Parse line if open redirect is confirmed
                    # Output shape: "[VULNERABLE] http://example.com/redirect?url=https://google.com"
                    if "vulnerable" in clean_line.lower() and "http" in clean_line:
                        vulnerable_url = None
                        for word in clean_line.split():
                            if word.startswith(("http://", "https://")):
                                vulnerable_url = word.strip()
                                break
                        if not vulnerable_url:
                            continue
                            
                        # Parse parameter and payload
                        parameter = "unknown"
                        payload = ""
                        try:
                            parsed = urlparse(vulnerable_url)
                            params = parse_qs(parsed.query)
                            for k, v_list in params.items():
                                for val in v_list:
                                    if "google" in val or "//" in val:
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
                                    "source": "openredirex",
                                    "severity": "medium",
                                    "matched_url": vulnerable_url,
                                    "payload": payload,
                                    "parameter": parameter,
                                    "evidence": clean_line,
                                    "timestamp": datetime.utcnow().isoformat()
                                },
                                "discovered_by": "openredirex",
                                "sources": ["openredirex"]
                            }
                        }
                        
                        # Yield finding_event
                        yield {
                            "type": "finding_event",
                            "data": {
                                "source": "openredirex",
                                "severity": "medium",
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
                logger.warning(f"[-] OpenRedirex scan timed out after {timeout}s. Terminating process.")
                yield {"type": "log", "message": f"[-] OpenRedirex scan timed out after {timeout} seconds."}
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
                    invalidate_tool_cache("openredirex")
                    yield {
                        "type": "stage_error",
                        "stage": "validation",
                        "tool": "openredirex",
                        "message": f"OpenRedirex executable not found at {tool_path}",
                    }
                logger.warning(f"[-] OpenRedirex exited with code {exit_code}")
                yield {"type": "log", "message": f"[-] OpenRedirex exited with code {exit_code}"}
                
        except Exception as exc:
            if "not found" in str(exc).lower() or isinstance(exc, FileNotFoundError):
                from app.core.tools import invalidate_tool_cache
                invalidate_tool_cache("openredirex")
                yield {
                    "type": "stage_error",
                    "stage": "validation",
                    "tool": "openredirex",
                    "message": f"OpenRedirex execution failed: {exc}",
                }
            err_msg = f"[-] OpenRedirex execution failed: {exc}"
            logger.exception(err_msg)
            yield {"type": "log", "message": err_msg}
            
        finally:
            # Clean up temp files
            for p in [temp_urls_path, temp_payloads_path]:
                if p and os.path.exists(p):
                    try:
                        os.unlink(p)
                    except Exception:
                        pass
                        
        duration_s = int(time.time() - start_ts)
        complete_msg = f"[√] OpenRedirex Scan complete. Confirmed findings: {confirmed_count}"
        yield {"type": "log", "message": complete_msg}
        yield {
            "type": "scan_summary",
            "provider": "openredirex",
            "status": "completed",
            "count": confirmed_count
        }
        yield {"type": "log", "message": "[√] Provider openredirex completed"}
