import asyncio
import logging
import os
import platform
import subprocess
from typing import AsyncGenerator, Dict, Any, List

from app.providers.base import BaseProvider

logger = logging.getLogger("reconforge.providers.chaos")


class ChaosProvider(BaseProvider):
    @property
    def name(self) -> str:
        return "Chaos"

    @property
    def description(self) -> str:
        return "Discovers subdomains using ProjectDiscovery's Chaos dataset."

    async def discover(self, seed_domains: List[str]) -> AsyncGenerator[Dict[str, Any], None]:
        msg = f"[*] Chaos Provider selected. Seed domains: {', '.join(seed_domains)}"
        logger.info(msg)
        yield {"type": "log", "message": msg}

        is_windows = platform.system().lower() == "windows"

        chaos_key = (
            os.getenv("PDCP_API_KEY")
            or os.getenv("CHAOS_KEY")
            or os.getenv("PROJECTDISCOVERY_API_KEY")
        )
        if not chaos_key:
            try:
                from app.core.provider_keys import load_provider_keys
                chaos_key = load_provider_keys().get("chaos")
            except Exception:
                chaos_key = None

        if not chaos_key:
            skip_msg = "[*] Chaos API key not configured. Skipping Chaos dataset query."
            logger.info(skip_msg)
            yield {"type": "log", "message": skip_msg}
            yield {
                "type": "stage_skipped",
                "stage": "Passive Discovery (chaos)",
                "tool": "chaos",
                "reason": "no_api_key",
            }
            yield {
                "type": "scan_summary",
                "provider": "chaos",
                "status": "SKIPPED",
                "count": 0,
                "reason": "no_api_key",
            }
            return

        tool_path = self.detect_tool("chaos")
        if not tool_path:
            err_msg = "Chaos binary not found (tool_missing: chaos)"
            logger.error(err_msg)
            yield {
                "type": "stage_error",
                "stage": "chaos",
                "tool": "chaos",
                "message": err_msg,
            }
            yield {
                "type": "scan_summary",
                "provider": "chaos",
                "status": "SKIPPED",
                "count": 0,
            }
            return

        from app.core.scope import get_root_domain

        for domain in seed_domains:
            target_domain = get_root_domain(domain) or domain
            key_args = ["-key", chaos_key] if chaos_key else []
            if is_windows:
                executable = "wsl"
                args = ["-e", tool_path, *key_args, "-d", target_domain, "-silent", "-duc"]
            else:
                executable = tool_path
                args = [*key_args, "-d", target_domain, "-silent", "-duc"]

            safe_args = [a if a != chaos_key else "[REDACTED]" for a in args]
            cmd_str = f"{executable} {' '.join(safe_args)}"
            exec_msg = f"[*] Executing command: {cmd_str}"
            logger.info(exec_msg)
            yield {"type": "log", "message": exec_msg}

            seen: set[str] = set()
            discovered_count = 0

            try:
                from app.job_control import register_process, unregister_process, check_job_status
                await check_job_status()

                # Keep subprocess pattern consistent with other providers.
                process = subprocess.Popen(
                    [executable, *args],
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    bufsize=1,
                )
                register_process(process)

                try:
                    # Stream stdout line-by-line.
                    assert process.stdout is not None
                    for line in process.stdout:
                        await check_job_status()
                        subdomain = (line or "").strip().lower()
                        if not subdomain:
                            continue

                        # Deduplicate within this provider run/domain.
                        if subdomain in seen:
                            continue
                        seen.add(subdomain)

                        discovered_count += 1
                        sub_msg = f"[+] [Chaos] Found: {subdomain}"
                        logger.info(sub_msg)
                        yield {"type": "log", "message": sub_msg}

                        # Emit asset immediately so jobs.py can persist + stream to UI.
                        yield {
                            "type": "asset",
                            "data": {
                                "domain": subdomain,
                                "type": "subdomain",
                                "status": "unknown",
                                "open_ports": [],
                                "metadata": {"source": "chaos"},
                                "discovered_by": "chaos",
                            },
                        }

                        await asyncio.sleep(0)
                finally:
                    unregister_process(process)
                    if process.poll() is None:
                        process.terminate()
                        process.wait()

                stderr_out = ""
                if process.stderr:
                    stderr_out = process.stderr.read() or ""
                    if stderr_out.strip():
                        logger.warning(
                            f"[-] [chaos stderr] {stderr_out.strip()}"
                        )
                        yield {"type": "log", "message": f"[chaos stderr] {stderr_out.strip()}"}

                exit_code = process.wait()
                if exit_code != 0:
                    err_msg = f"[-] chaos exited with status: {exit_code}"
                    logger.error(err_msg)
                    yield {"type": "log", "message": err_msg}
                    raise RuntimeError(err_msg)

                logger.info(
                    f"[+] Chaos discovered {discovered_count} subdomains for {domain}"
                )

            except Exception as e:
                err_msg = f"[-] Failed to execute chaos: {str(e)}"
                logger.exception(err_msg)
                yield {"type": "log", "message": err_msg}
                raise

            await asyncio.sleep(0)

        done_msg = "[√] Chaos scan complete."
        logger.info(done_msg)
        yield {"type": "log", "message": done_msg}

