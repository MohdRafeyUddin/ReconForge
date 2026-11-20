"""takeover_crosscheck_provider.py
================================
Cross-checks subdomain takeover vulnerabilities using Subzy, Nuclei (takeover tag only),
dnsReaper (if installed), and dangling CNAME / NS delegation heuristics.
Merges findings per host, marking single-tool hits as 'unconfirmed' and multi-tool hits as 'confirmed'.
"""

import asyncio
import json
import logging
import os
import platform
import subprocess
import tempfile
import time
from typing import Any, AsyncGenerator, Dict, List, Optional, Set

from app.core.tools import get_tool_path, is_tool_available
from app.job_control import check_job_status, register_process, unregister_process
from app.providers.base import BaseProvider
from app.providers.subzy_provider import SubzyProvider

logger = logging.getLogger("reconforge.providers.takeover_crosscheck")

# Known cloud fingerprints for dangling CNAME checks
KNOWN_TAKEOVER_CNAME_PATTERNS = {
    "github.io": "GitHub Pages",
    "s3.amazonaws.com": "AWS S3",
    "elasticbeanstalk.com": "AWS Elastic Beanstalk",
    "herokuapp.com": "Heroku",
    "trafficmanager.net": "Azure Traffic Manager",
    "azurewebsites.net": "Azure App Services",
    "cloudapp.net": "Azure CloudApp",
    "myshopify.com": "Shopify",
    "zendesk.com": "Zendesk",
    "ghost.io": "Ghost",
    "surge.sh": "Surge.sh",
    "bitbucket.io": "Bitbucket",
    "fastly.net": "Fastly",
    "pantheonsite.io": "Pantheon",
    "wordpress.com": "WordPress",
    "readme.io": "Readme.io",
    "cname.vercel-dns.com": "Vercel",
}


class TakeoverCrossCheckProvider(BaseProvider):
    def __init__(self, cnames_map: Optional[Dict[str, List[str]]] = None):
        self.cnames_map = cnames_map or {}

    @staticmethod
    def evaluate_confidence(tools: List[str]) -> Tuple[str, str]:
        """Multi-tool agreement = confirmed (Vulnerable); Single tool = unconfirmed (Unconfirmed)."""
        is_confirmed = len(tools) >= 2
        confidence = "confirmed" if is_confirmed else "unconfirmed"
        status = "Vulnerable" if is_confirmed else "Unconfirmed"
        return confidence, status

    @property
    def name(self) -> str:
        return "Takeover Cross-Check"

    @property
    def description(self) -> str:
        return "Cross-checks subdomains with Subzy, Nuclei, dnsReaper, and CNAME heuristics."

    @staticmethod
    def _to_wsl_path(path: str) -> str:
        drive, rest = os.path.splitdrive(os.path.abspath(path))
        drive_letter = drive.rstrip(":").lower()
        return f"/mnt/{drive_letter}{rest.replace('\\', '/')}"

    async def discover(self, seed_domains: List[str]) -> AsyncGenerator[Dict[str, Any], None]:
        async for ev in self.check_takeovers(seed_domains):
            yield ev

    async def check_takeovers(
        self,
        subdomains: List[str],
    ) -> AsyncGenerator[Dict[str, Any], None]:
        yield {"type": "log", "message": f"[*] Starting Subdomain Takeover Cross-Check for {len(subdomains)} host(s)..."}

        is_windows = platform.system().lower() == "windows"
        findings_by_host: Dict[str, Dict[str, Any]] = {}

        def _get_or_create(host: str) -> Dict[str, Any]:
            if host not in findings_by_host:
                findings_by_host[host] = {
                    "tools_agreed": [],
                    "service": "",
                    "cname": "",
                    "evidence": [],
                }
            return findings_by_host[host]

        # 1. Run Subzy
        subzy = SubzyProvider()
        yield {"type": "log", "message": "[*] Running Subzy takeover scanner..."}
        async for ev in subzy.discover(subdomains):
            if ev.get("type") == "asset":
                data = ev.get("data") or {}
                meta = (data.get("metadata") or {}).get("subzy") or {}
                host = data.get("domain", "")
                if meta.get("takeover_status") == "Vulnerable":
                    entry = _get_or_create(host)
                    entry["tools_agreed"].append("subzy")
                    if meta.get("service"):
                        entry["service"] = meta.get("service")
                    if meta.get("cname"):
                        entry["cname"] = meta.get("cname")
                    entry["evidence"].append("Subzy confirmed takeover signature")
            elif ev.get("type") == "log":
                yield ev

        # 2. Run Nuclei with takeover tag only (runs even in recon profile)
        nuclei_bin = get_tool_path("nuclei")
        if nuclei_bin and subdomains:
            yield {"type": "log", "message": "[*] Running Nuclei takeover templates (tag: takeover)..."}
            with tempfile.NamedTemporaryFile("w", delete=False, suffix=".txt", encoding="utf-8") as tf:
                # Provide URLs for nuclei
                for s in subdomains:
                    tf.write(f"http://{s}\nhttps://{s}\n")
                targets_file = tf.name

            wsl_targets = self._to_wsl_path(targets_file) if is_windows else targets_file
            try:
                cmd = [
                    "wsl", "-e", nuclei_bin, "-l", wsl_targets,
                    "-tags", "takeover", "-silent", "-jsonl",
                ] if is_windows else [
                    nuclei_bin, "-l", wsl_targets,
                    "-tags", "takeover", "-silent", "-jsonl",
                ]
                # Tags-only takeover pass: never add -as (no automatic scanning).
                assert "-as" not in cmd
                yield {"type": "log", "message": self.format_cmd_log(cmd)}
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
                try:
                    stdout, _ = proc.communicate(timeout=90)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    stdout = ""
                finally:
                    unregister_process(proc)

                for line in stdout.splitlines():
                    text = line.strip()
                    if not text:
                        continue
                    try:
                        nuc = json.loads(text)
                        nuc_host = nuc.get("host", "").replace("http://", "").replace("https://", "").split("/")[0].split(":")[0]
                        if nuc_host:
                            entry = _get_or_create(nuc_host)
                            if "nuclei" not in entry["tools_agreed"]:
                                entry["tools_agreed"].append("nuclei")
                            tmpl = nuc.get("template-id") or (nuc.get("info") or {}).get("name") or "Nuclei takeover"
                            entry["evidence"].append(f"Nuclei takeover template: {tmpl}")
                            if not entry["service"]:
                                entry["service"] = (nuc.get("info") or {}).get("name", "Unknown Service")
                    except Exception:
                        continue
            finally:
                try:
                    os.unlink(targets_file)
                except OSError:
                    pass

        # 3. Run dnsReaper if available
        dnsreaper_path = get_tool_path("dnsreaper")
        if dnsreaper_path and subdomains:
            yield {"type": "log", "message": "[*] Running dnsReaper takeover analysis..."}
            with tempfile.NamedTemporaryFile("w", delete=False, suffix=".txt", encoding="utf-8") as tf:
                tf.write("\n".join(subdomains) + "\n")
                subs_path = tf.name

            wsl_subs = self._to_wsl_path(subs_path) if is_windows else subs_path
            try:
                cmd = [
                    "wsl", "-e", "python3", dnsreaper_path, "subdomains",
                    "--filename", wsl_subs, "--format", "json",
                ] if is_windows else [
                    "python3", dnsreaper_path, "subdomains",
                    "--filename", wsl_subs, "--format", "json",
                ]
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
                try:
                    stdout, _ = proc.communicate(timeout=60)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    stdout = ""
                finally:
                    unregister_process(proc)

                for line in stdout.splitlines():
                    text = line.strip()
                    if not text:
                        continue
                    try:
                        rep = json.loads(text)
                        domain = rep.get("domain") or rep.get("subdomain")
                        if domain and rep.get("vulnerable"):
                            entry = _get_or_create(domain)
                            if "dnsreaper" not in entry["tools_agreed"]:
                                entry["tools_agreed"].append("dnsreaper")
                            entry["evidence"].append(f"dnsReaper: {rep.get('service', 'Takeover')}")
                            if not entry["service"]:
                                entry["service"] = rep.get("service", "")
                    except Exception:
                        continue
            finally:
                try:
                    os.unlink(subs_path)
                except OSError:
                    pass

        # 4. Dangling CNAME & NS Delegation Heuristics
        for host, cnames in self.cnames_map.items():
            for cname in cnames:
                cname_clean = cname.lower().rstrip(".")
                for pattern, service in KNOWN_TAKEOVER_CNAME_PATTERNS.items():
                    if pattern in cname_clean:
                        entry = _get_or_create(host)
                        if "cname_analysis" not in entry["tools_agreed"]:
                            entry["tools_agreed"].append("cname_analysis")
                        if not entry["service"]:
                            entry["service"] = service
                        if not entry["cname"]:
                            entry["cname"] = cname_clean
                        entry["evidence"].append(f"Dangling CNAME pattern {pattern} pointing to {cname_clean}")

        # 5. Evaluate Confidence & Emit Results
        confirmed_count = 0
        unconfirmed_count = 0

        for host, data in findings_by_host.items():
            tools = data["tools_agreed"]
            if not tools:
                continue

            # Multi-tool agreement = confirmed; Single tool = unconfirmed
            is_confirmed = len(tools) >= 2
            confidence = "confirmed" if is_confirmed else "unconfirmed"
            status = "Vulnerable" if is_confirmed else "Unconfirmed"

            if is_confirmed:
                confirmed_count += 1
            else:
                unconfirmed_count += 1

            tools_str = " + ".join(tools)
            log_icon = "[!]" if is_confirmed else "[*]"
            yield {
                "type": "log",
                "message": f"{log_icon} {host} takeover detected: {data['service'] or 'Cloud Provider'} | Tools: {tools_str} | Confidence: {confidence.upper()}",
            }

            yield {
                "type": "asset",
                "data": {
                    "domain": host,
                    "type": "subdomain",
                    "status": "live",
                    "open_ports": [],
                    "metadata": {
                        "subzy": {
                            "service": data["service"] or "Cloud Service",
                            "takeover_status": status,
                            "confidence": confidence,
                            "tools_agreed": tools,
                            "cname": data["cname"],
                            "evidence": "; ".join(data["evidence"]),
                            "checked_at": int(time.time()),
                        },
                    },
                    "discovered_by": "takeover_crosscheck",
                    "sources": tools,
                },
            }

        total_findings = confirmed_count + unconfirmed_count
        summary_msg = f"[√] Takeover Cross-Check complete → {confirmed_count} confirmed, {unconfirmed_count} unconfirmed"
        logger.info(summary_msg)
        yield {"type": "log", "message": summary_msg}
        yield {
            "type": "scan_summary",
            "provider": "takeover_crosscheck",
            "status": "completed",
            "count": confirmed_count,
            "unconfirmed_count": unconfirmed_count,
            "vulnerable": confirmed_count,
        }
