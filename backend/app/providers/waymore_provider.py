"""Waymore Historical URL Extraction Provider
==============================================
Optional supplement to GAU for historical URL discovery from archive sources
(Wayback Machine, Common Crawl, AlienVault, URLScan, VirusTotal, etc.).
  - Gated via is_tool_available("waymore") / tool_missing handling.
  - Results are scope-filtered and fed to the URL Merge Engine.
"""

import asyncio
import logging
import os
import platform
import subprocess
import tempfile
import time
from typing import Any, AsyncGenerator, Dict, List, Optional

from app.core.scope import is_in_scope
from app.providers.base import BaseProvider

logger = logging.getLogger("reconforge.providers.waymore")


class WaymoreProvider(BaseProvider):
    @property
    def name(self) -> str:
        return "waymore"

    @property
    def description(self) -> str:
        return "Optional historical URL extraction supplement from multiple archive indices."

    @classmethod
    def build_cmd(
        cls,
        tool_path: str,
        domain: str,
        wsl_out: str,
        is_windows: bool = False,
    ) -> List[str]:
        """
        Builds the Waymore command:
          -mode U (URLs only)
          -i <domain>
          -oU <wsl_out>
          -f
        """
        cmd: List[str] = ["wsl", "-e"] if is_windows else []
        cmd.extend([
            tool_path,
            "-i", domain,
            "-mode", "U",          # URLs only
            "-oU", wsl_out,
            "-f",                  # Don't prompt for responses
        ])
        return cmd

    async def discover(self, seed_domains: List[str], **kwargs: Any) -> AsyncGenerator[Dict[str, Any], None]:
        async for item in self.discover_urls(seed_domains, **kwargs):
            yield item

    async def discover_urls(
        self,
        domains: List[str],
        scope: Optional[Dict[str, List[str]]] = None,
        timeout: int = 180,
    ) -> AsyncGenerator[Dict[str, Any], None]:
        """
        Runs Waymore across target domains to extract historical URLs.
        Applies a hard global timeout across all domains; on timeout,
        emits a stage_timeout event and ends gracefully.
        """
        if not domains:
            yield {
                "type": "scan_summary",
                "provider": self.name,
                "status": "SKIPPED",
                "count": 0,
            }
            return

        is_windows = platform.system().lower() == "windows"
        try:
            tool_path = self.detect_tool("waymore")
        except ValueError:
            yield {
                "type": "stage_skipped",
                "stage": "Historical URLs (waymore)",
                "tool": "waymore",
                "reason": "tool_missing: waymore",
            }
            yield {
                "type": "log",
                "message": "[!] Tool 'waymore' is not installed in WSL. Skipping Waymore supplement.",
            }
            yield {
                "type": "scan_summary",
                "provider": self.name,
                "status": "SKIPPED",
                "count": 0,
            }
            return

        total_discovered = 0
        start_ts = time.time()

        from app.core.scope import get_root_domain
        # Run once on apex domain or raise global timeout to scale with host count
        apex_targets = list(dict.fromkeys(get_root_domain(d) for d in domains if get_root_domain(d)))
        if not apex_targets:
            apex_targets = list(dict.fromkeys(d.strip().lower() for d in domains if d and d.strip()))

        # Scale global timeout with host count (at least 120s per domain)
        global_timeout = max(timeout, len(apex_targets) * 120)

        yield {
            "type": "log",
            "message": f"\n========== Historical URLs (Waymore Supplement) ==========\n"
                       f"[*] Querying archive indices for {len(apex_targets)} apex domain(s) (Global timeout: {global_timeout}s)...",
        }

        processed_domains = set()

        for domain in apex_targets:
            # Check remaining global time
            elapsed = time.time() - start_ts
            remaining_time = global_timeout - elapsed
            if remaining_time <= 0:
                unprocessed = [d for d in apex_targets if d not in processed_domains]
                warn_msg = f"[!] Waymore global timeout ({global_timeout}s) exceeded: {len(unprocessed)} unprocessed host(s): {', '.join(unprocessed)}"
                logger.warning(warn_msg)
                yield {
                    "type": "stage_timeout",
                    "stage": "historical_urls",
                    "tool": "waymore",
                    "reason": f"waymore global timeout ({global_timeout}s) exceeded",
                    "unprocessed_hosts": unprocessed,
                }
                yield {"type": "log", "message": warn_msg}
                break

            domain = domain.strip().lower()
            if not domain or not is_in_scope(domain, scope):
                processed_domains.add(domain)
                continue

            out_tmp = tempfile.NamedTemporaryFile(suffix=".txt", delete=False)
            out_tmp.close()
            wsl_out = self.wsl_path_convert(out_tmp.name) if is_windows else out_tmp.name

            cmd = self.build_cmd(tool_path, domain, wsl_out, is_windows=is_windows)

            yield {"type": "log", "message": self.format_cmd_log(cmd)}

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
                await asyncio.wait_for(loop.run_in_executor(None, proc.wait), timeout=remaining_time)
            except asyncio.TimeoutError:
                timed_out = True
                kill_process_tree(proc, "waymore")
                processed_domains.add(domain)
                unprocessed = [d for d in apex_targets if d not in processed_domains]
                warn_msg = f"[-] Waymore global timeout exceeded during domain {domain}. {len(unprocessed)} unprocessed host(s): {', '.join(unprocessed)}"
                logger.warning(warn_msg)
                yield {
                    "type": "stage_timeout",
                    "stage": "historical_urls",
                    "tool": "waymore",
                    "reason": f"waymore global timeout ({global_timeout}s) exceeded",
                    "unprocessed_hosts": unprocessed,
                }
                yield {"type": "log", "message": warn_msg}
            finally:
                unregister_process(proc)

            processed_domains.add(domain)

            domain_urls = []
            if os.path.exists(out_tmp.name) and os.path.getsize(out_tmp.name) > 0:
                try:
                    with open(out_tmp.name, "r", encoding="utf-8", errors="replace") as f:
                        for line in f:
                            u = line.strip()
                            if u and is_in_scope(u, scope):
                                domain_urls.append(u)
                except Exception as e:
                    logger.debug("[waymore] Error reading output: %s", e)

            try:
                if os.path.exists(out_tmp.name):
                    os.unlink(out_tmp.name)
            except Exception:
                pass

            domain_urls = list(dict.fromkeys(domain_urls))
            for u in domain_urls:
                total_discovered += 1
                yield {
                    "type": "url_event",
                    "data": {
                        "url": u,
                        "original_url": u,
                        "source": "waymore",
                        "sources": ["waymore"],
                    },
                }

            if timed_out:
                break

            yield {
                "type": "log",
                "message": f"[+] Waymore extracted {len(domain_urls)} URLs for {domain}.",
            }

        duration = round(time.time() - start_ts, 2)
        yield {
            "type": "scan_summary",
            "provider": self.name,
            "status": "completed",
            "count": total_discovered,
            "duration_seconds": duration,
        }
        yield {
            "type": "log",
            "message": f"[√] Waymore completed: {total_discovered} historical URLs | Duration: {duration}s",
        }

