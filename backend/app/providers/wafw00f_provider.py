"""Wafw00fProvider
=================
Optional Web Application Firewall (WAF) fingerprinting provider using wafw00f.
Identifies WAF technologies guarding live web endpoints.
"""

import asyncio
import json
import logging
import os
import platform
import subprocess
import time
from typing import Any, AsyncGenerator, Dict, List, Optional

from app.providers.base import BaseProvider
from app.core.tools import is_tool_available

logger = logging.getLogger("reconforge.providers.wafw00f")


class Wafw00fProvider(BaseProvider):
    @property
    def name(self) -> str:
        return "wafw00f"

    @property
    def description(self) -> str:
        return "Detects and fingerprints Web Application Firewalls (WAF) guarding target hosts."

    async def discover(
        self,
        targets: List[str],
        rate_limit: Optional[int] = None,
    ) -> AsyncGenerator[Dict[str, Any], None]:
        clean_targets = list(dict.fromkeys(t.strip() for t in targets if t and t.strip()))
        if not clean_targets:
            yield {"type": "log", "message": "[*] No targets provided for wafw00f."}
            return

        if not is_tool_available("wafw00f"):
            yield {"type": "log", "message": "[!] Tool 'wafw00f' is not installed in WSL. Skipping WAF fingerprinting."}
            yield {"type": "stage_skipped", "stage": "WAF Fingerprinting (wafw00f)", "tool": "wafw00f", "reason": "tool_missing: wafw00f"}
            yield {"type": "scan_summary", "provider": "wafw00f", "status": "SKIPPED", "count": 0}
            return

        is_windows = platform.system().lower() == "windows"
        tool_path = self.detect_tool("wafw00f")
        if not tool_path:
            err_msg = "wafw00f binary not found (tool_missing: wafw00f)"
            logger.error(err_msg)
            yield {
                "type": "stage_error",
                "stage": "wafw00f",
                "tool": "wafw00f",
                "message": err_msg,
            }
            yield {
                "type": "scan_summary",
                "provider": self.name,
                "status": "SKIPPED",
                "count": 0,
            }
            return
        executable = "wsl" if is_windows else tool_path
        args = ["-e", tool_path] if is_windows else []

        yield {"type": "log", "message": f"\n========== WAF Detection (wafw00f) ==========\n[*] Fingerprinting WAFs on {len(clean_targets)} targets..."}

        from app.job_control import register_process, unregister_process, check_job_status
        await check_job_status()

        waf_detected_count = 0

        # Run wafw00f per target or batch
        for target in clean_targets[:30]:  # Cap batch to avoid excessive scan times
            await check_job_status()
            url = target if target.startswith("http") else f"https://{target}"
            cmd = [executable, *args, url]

            try:
                proc = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                )
                register_process(proc)

                try:
                    stdout, stderr = proc.communicate(timeout=25)
                finally:
                    unregister_process(proc)

                detected_waf = None
                for line in (stdout or "").splitlines():
                    line_clean = line.strip()
                    if "is behind" in line_clean:
                        # e.g.: "The site https://example.com is behind Cloudflare (Cloudflare Inc.) WAF."
                        parts = line_clean.split("is behind", 1)
                        if len(parts) > 1:
                            detected_waf = parts[1].replace("WAF.", "").replace("WAF", "").strip()
                            break

                if detected_waf and "no waf" not in detected_waf.lower():
                    waf_detected_count += 1
                    msg = f"[+] [WAF] {target} is protected by {detected_waf}"
                    logger.info(msg)
                    yield {"type": "log", "message": msg}
                    yield {
                        "type": "asset",
                        "data": {
                            "domain": target.split("//")[-1].split("/")[0].split(":")[0],
                            "type": "subdomain",
                            "status": "live",
                            "cdn_waf": {
                                "is_waf": True,
                                "waf_name": detected_waf,
                                "detected_by": "wafw00f",
                                "exclusion_reason": f"WAF detected ({detected_waf}) - rate auto-reduced and excluded from aggressive port fuzzing",
                            },
                            "discovered_by": "wafw00f",
                            "sources": ["wafw00f"],
                        },
                    }
            except Exception as exc:
                logger.debug("wafw00f failed on %s: %s", target, exc)

        yield {
            "type": "scan_summary",
            "provider": "wafw00f",
            "status": "completed",
            "count": waf_detected_count,
        }
        yield {"type": "log", "message": f"[√] wafw00f finished: {waf_detected_count} WAF(s) detected."}
