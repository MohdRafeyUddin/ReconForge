"""Phase 8.6 — Technology-aware routing: WPScan for WordPress hosts.

Runs only when WordPress is detected, the project uses the
``recon_validation`` profile and Deep mode is selected. WPScan is optional;
a missing binary emits a ``tool_missing`` skip and never fails the scan.
"""

import asyncio
import json
import logging
import platform
import subprocess
import time
from datetime import datetime
from typing import Any, AsyncGenerator, Dict, List, Optional
from urllib.parse import urlparse

from app.providers.base import BaseProvider

logger = logging.getLogger("reconforge.providers.wpscan")


class WpscanProvider(BaseProvider):
    @property
    def name(self) -> str:
        return "WPScan"

    @property
    def description(self) -> str:
        return "WordPress vulnerability scanning routed from detected technology."

    @staticmethod
    def severity_from_cvss(score: Any) -> str:
        try:
            val = float(score)
        except Exception:
            return "medium"
        if val >= 9.0:
            return "critical"
        if val >= 7.0:
            return "high"
        if val >= 4.0:
            return "medium"
        return "low"

    @staticmethod
    def parse_wpscan_output(output: str) -> Dict[str, Any]:
        """Finds and parses the JSON object emitted by WPScan."""
        text = (output or "").strip()
        if not text:
            return {}
        start = text.find("{")
        if start < 0:
            return {}
        try:
            return json.loads(text[start:])
        except Exception:
            # Try the last JSON object on the output
            end = text.rfind("}")
            if end > start:
                try:
                    return json.loads(text[start:end + 1])
                except Exception:
                    return {}
        return {}

    @staticmethod
    def findings_from_report(report: Dict[str, Any], target_url: str) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        if not isinstance(report, dict):
            return findings
        host = (urlparse(target_url).hostname or "").lower()
        now = datetime.utcnow().isoformat()

        def add_vuln(component: str, vuln: Dict[str, Any]) -> None:
            if not isinstance(vuln, dict):
                return
            vuln_id = str(vuln.get("id") or vuln.get("cve") or "unknown")
            title = str(vuln.get("title") or vuln.get("name") or "WordPress vulnerability")
            cvss_obj = vuln.get("cvss") or {}
            cvss_score = cvss_obj.get("score") if isinstance(cvss_obj, dict) else cvss_obj
            severity = WpscanProvider.severity_from_cvss(cvss_score)
            findings.append({
                "type": "finding_event",
                "data": {
                    "source": "wpscan",
                    "severity": severity,
                    "template_id": f"wpscan-{component}-{vuln_id}",
                    "matched_url": target_url,
                    "host": host,
                    "evidence": title,
                    "component": component,
                    "cve": vuln.get("cve") or "",
                    "cvss": cvss_score if cvss_score is not None else "",
                    "fixed_in": vuln.get("fixed_in") or "",
                    "timestamp": now,
                },
            })

        version = report.get("version") or {}
        if isinstance(version, dict):
            vnumber = version.get("number")
            for vuln in version.get("vulnerabilities") or []:
                add_vuln(f"core-{vnumber or 'unknown'}", vuln)

        for group_key in ("plugins", "themes"):
            group = report.get(group_key) or {}
            if not isinstance(group, dict):
                continue
            for name, data in group.items():
                if not isinstance(data, dict):
                    continue
                for vuln in data.get("vulnerabilities") or []:
                    add_vuln(f"{group_key[:-1]}-{name}", vuln)

        return findings

    def _strict_tool(self, tool_name: str) -> Optional[str]:
        try:
            return self.detect_tool(tool_name)
        except Exception:
            return None

    @staticmethod
    def _tool_prefix(tool_path: str) -> List[str]:
        if platform.system().lower() == "windows":
            return ["wsl", "-e", tool_path]
        return [tool_path]

    async def _run_tool(self, args: List[str], timeout: int) -> Any:
        from app.job_control import register_process, unregister_process, kill_process_tree

        def _run() -> Any:
            proc = subprocess.Popen(
                args,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding="utf-8",
                errors="replace",
            )
            register_process(proc)
            try:
                out, err = proc.communicate(timeout=timeout)
                return proc.returncode, out or "", err or ""
            except subprocess.TimeoutExpired:
                kill_process_tree(proc, "wpscan")
                try:
                    out, err = proc.communicate(timeout=5)
                except Exception:
                    out, err = "", ""
                return -1, out or "", err or ""
            finally:
                unregister_process(proc)

        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, _run)

    async def discover(self, seed_domains: List[str], **kwargs: Any) -> AsyncGenerator[Dict[str, Any], None]:
        async for event in self.scan(seed_domains, **kwargs):
            yield event

    async def scan(
        self,
        targets: List[str],
        rate_limit: int = 5,
        max_hosts: int = 10,
        project_config: Optional[Dict[str, Any]] = None,
    ) -> AsyncGenerator[Dict[str, Any], None]:
        urls = list(dict.fromkeys(u.strip() for u in (targets or []) if u and u.strip()))[:max_hosts]
        yield {"type": "log", "message": "\n========== Tech-Aware Routing: WPScan =========="}

        if not urls:
            yield {"type": "scan_summary", "provider": "wpscan", "status": "SKIPPED", "count": 0, "reason": "no_wordpress_hosts"}
            return

        tool_path = self._strict_tool("wpscan")
        if not tool_path:
            yield {"type": "stage_skipped", "stage": "Tech Routing (wpscan)", "tool": "wpscan", "reason": "tool_missing: wpscan"}
            yield {"type": "scan_summary", "provider": "wpscan", "status": "SKIPPED", "count": 0, "reason": "tool_missing"}
            return

        start_ts = time.time()
        total = 0
        throttle_ms = int(1000 / max(int(rate_limit or 5), 1))
        for url in urls:
            args = [
                "--url", url,
                "--format", "json",
                "--no-banner",
                "--random-user-agent",
                "--disable-tls-checks",
                "--enumerate", "vp",
                "--throttle", str(throttle_ms),
            ]
            cmd = [*self._tool_prefix(tool_path), *args]
            yield {"type": "log", "message": self.format_cmd_log(cmd)}
            rc, out, err = await self._run_tool(cmd, timeout=300)
            report = self.parse_wpscan_output(out)
            if not report:
                if rc != 0:
                    yield {
                        "type": "stage_error",
                        "stage": "Tech Routing (wpscan)",
                        "tool": "wpscan",
                        "returncode": rc,
                        "message": f"wpscan exited with code {rc} for {url}: {(err or out).strip()[:300]}",
                    }
                continue
            findings = self.findings_from_report(report, url)
            for event in findings:
                total += 1
                yield event
            yield {
                "type": "log",
                "message": f"[*] WPScan {url}: {len(findings)} vulnerability finding(s).",
            }

        yield {
            "type": "scan_summary",
            "provider": "wpscan",
            "status": "completed",
            "count": total,
            "hosts_scanned": len(urls),
            "duration_seconds": int(time.time() - start_ts),
        }
        yield {"type": "log", "message": f"[√] WPScan complete: {total} finding(s) across {len(urls)} host(s)."}
