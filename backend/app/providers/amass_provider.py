import asyncio
import logging
import platform
import subprocess
from typing import AsyncGenerator, Dict, Any, List, Set

from app.providers.base import BaseProvider

logger = logging.getLogger("reconforge.providers.amass")


class AmassProvider(BaseProvider):

    @property
    def name(self) -> str:
        return "Amass"

    @property
    def description(self) -> str:
        return "In-depth Attack Surface Mapping using passive enumeration via Amass."

    async def discover(
        self,
        seed_domains: List[str]
    ) -> AsyncGenerator[Dict[str, Any], None]:

        # Keep only the requested Executing Amass... log
        logger.info("Executing Amass...")
        yield {"type": "log", "message": "Executing Amass..."}

        is_windows = platform.system().lower() == "windows"
        try:
            tool_path = self.detect_tool("amass")
        except Exception:
            tool_path = None

        if not tool_path:
            # Overrides and default set amass to /snap/bin/amass
            tool_path = "/snap/bin/amass"

        if not tool_path:
            err_msg = "Amass binary not found (tool_missing: amass)"
            logger.error(err_msg)
            yield {
                "type": "stage_error",
                "stage": "amass",
                "tool": "amass",
                "message": err_msg,
            }
            yield {
                "type": "stage_skipped",
                "stage": "Passive Discovery (amass)",
                "tool": "amass",
                "reason": "tool_missing: amass",
            }
            yield {
                "type": "scan_summary",
                "provider": "amass",
                "status": "SKIPPED",
                "reason": "tool_missing: amass",
                "count": 0,
            }
            return

        import time
        from app.config import settings
        from app.job_control import kill_process_tree
        timeout_min = getattr(settings, "AMASS_TIMEOUT_MINUTES", 5)
        timeout_seconds = int(timeout_min * 60)

        seen_subdomains: Set[str] = set()

        for domain in seed_domains:
            if is_windows:
                executable = "wsl"
                args = [
                    "-e",
                    tool_path,
                    "enum",
                    "-passive",
                    "-d",
                    domain,
                    "-timeout",
                    str(timeout_min),
                ]
            else:
                executable = tool_path
                args = [
                    "enum",
                    "-passive",
                    "-d",
                    domain,
                    "-timeout",
                    str(timeout_min),
                ]

            try:
                from app.job_control import register_process, unregister_process, check_job_status
                await check_job_status()

                cmd_list = [executable, *args]
                yield {"type": "log", "message": self.format_cmd_log(cmd_list)}

                process = subprocess.Popen(
                    cmd_list,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    bufsize=1,
                )
                register_process(process)

                domain_subdomains = 0
                timed_out = False
                start_ts = time.time()
                loop = asyncio.get_event_loop()

                async def read_stream():
                    nonlocal domain_subdomains
                    assert process.stdout is not None
                    while True:
                        await check_job_status()
                        rem = timeout_seconds - (time.time() - start_ts)
                        if rem <= 0:
                            timed_out = True
                            break
                        if hasattr(process.stdout, "readline"):
                            line = await asyncio.wait_for(
                                loop.run_in_executor(None, process.stdout.readline),
                                timeout=max(0.1, rem),
                            )
                        elif isinstance(process.stdout, (list, tuple)):
                            line = process.stdout.pop(0) if process.stdout else None
                        else:
                            line = None
                        if not line:
                            break
                        line_str = line.strip()
                        if not line_str:
                            continue

                        subdomain = line_str.lower().strip()
                        domain_lc = domain.lower().strip()
                        if subdomain == domain_lc or subdomain.endswith(f".{domain_lc}"):
                            pass
                        else:
                            continue

                        if subdomain in seen_subdomains:
                            continue
                        seen_subdomains.add(subdomain)
                        domain_subdomains += 1

                        sub_msg = f"Found subdomain: {subdomain}"
                        logger.info(sub_msg)
                        yield {"type": "log", "message": sub_msg}

                        yield {
                            "type": "asset",
                            "data": {
                                "domain": subdomain,
                                "type": "subdomain",
                                "status": "unknown",
                                "open_ports": [],
                                "metadata": {"source": "amass"},
                                "discovered_by": "amass",
                            },
                        }
                        await asyncio.sleep(0)

                try:
                    async for event in read_stream():
                        yield event
                        if (time.time() - start_ts) >= timeout_seconds:
                            timed_out = True
                            break
                except asyncio.TimeoutError:
                    timed_out = True
                finally:
                    unregister_process(process)
                    if timed_out or (time.time() - start_ts >= timeout_seconds):
                        kill_process_tree(process, "amass")
                        yield {
                            "type": "stage_timeout",
                            "stage": "amass",
                            "tool": "amass",
                            "reason": f"amass timeout ({timeout_seconds}s) exceeded for {domain}",
                        }
                        yield {"type": "log", "message": f"[-] Amass timeout ({timeout_seconds}s) exceeded for {domain}."}
                    elif process.poll() is None and hasattr(process, "terminate"):
                        try:
                            process.terminate()
                            if hasattr(process, "wait"):
                                process.wait()
                        except Exception:
                            pass

                exit_code = process.poll() or 0
                if exit_code == 127:
                    from app.core.tools import invalidate_tool_cache
                    invalidate_tool_cache("amass")
                    yield {
                        "type": "stage_error",
                        "stage": "amass",
                        "tool": "amass",
                        "message": f"Amass executable not found at {tool_path}",
                    }

                # Check if 0 results produced
                if domain_subdomains == 0 and not timed_out:
                    stderr_out = ""
                    try:
                        if process.stderr:
                            stderr_out = process.stderr.read() or ""
                    except Exception:
                        pass
                    stderr_preview = stderr_out[:500].strip()
                    warn_msg = f"[!] Amass produced 0 results for domain {domain}. Stderr: {stderr_preview}"
                    logger.warning(warn_msg)
                    yield {"type": "log", "message": warn_msg}
                    yield {
                        "type": "warning_event",
                        "stage": "amass",
                        "message": warn_msg,
                        "stderr": stderr_preview,
                    }

            except Exception as e:
                logger.exception(f"[-] Failed to execute amass: {str(e)}")
                raise

            await asyncio.sleep(0)

        # Keep only Amass completed. log
        logger.info("Amass completed.")
        yield {
            "type": "log",
            "message": "Amass completed."
        }
