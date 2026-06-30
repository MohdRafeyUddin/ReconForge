"""Internal Nuclei provider for vulnerability and exposure scanning.

Nuclei runs automatically after Katana, scanning first-party live URLs
using safe reconnaissance templates.
"""

import asyncio
import json
import logging
import os
import platform
import subprocess
import tempfile
import time
from collections import defaultdict
from datetime import datetime
from typing import AsyncGenerator, Dict, Any, List, Optional
from urllib.parse import urlparse

from app.providers.base import BaseProvider

logger = logging.getLogger("reconforge.providers.nuclei")

# Safe categories/tags as defined in the requirements
DEFAULT_CATEGORIES = [
    "exposure", "exposures", "tech", "technologies", "misconfig", "misconfiguration",
    "default-login", "default-logins", "panel", "panels", "dns", "ssl", "file", "files",
    "workflow", "workflows"
]


class NucleiProvider(BaseProvider):
    @property
    def name(self) -> str:
        return "Nuclei"

    @property
    def description(self) -> str:
        return "Internal vulnerability and exposure scanner."

    @staticmethod
    def _windows_path_to_wsl(path: str) -> str:
        drive, rest = os.path.splitdrive(os.path.abspath(path))
        drive_letter = drive.rstrip(":").lower()
        rest = rest.replace("\\", "/")
        return f"/mnt/{drive_letter}{rest}"

    async def discover(self, seed_domains: List[str]) -> AsyncGenerator[Dict[str, Any], None]:
        # seed_domains here represents the URLs to scan
        urls = list(dict.fromkeys(u.strip() for u in seed_domains if u and u.strip()))

        yield {"type": "log", "message": "\n========== Nuclei =========="}
        yield {"type": "log", "message": "Starting Nuclei..."}
        yield {"type": "log", "message": f"Scanning {len(urls)} URLs..."}

        if not urls:
            msg = "Nuclei completed. No URLs to scan."
            logger.info(msg)
            yield {"type": "log", "message": msg}
            yield {"type": "scan_summary", "provider": self.name, "urls_scanned": 0, "findings_found": 0}
            return

        is_windows = platform.system().lower() == "windows"
        executable = "wsl" if is_windows else "/home/kali/go/bin/nuclei"
        temp_path = ""
        start_ts = time.time()

        # Group by target host to associate findings later
        target_hosts = set()
        for u in urls:
            try:
                parsed = urlparse(u)
                h = parsed.hostname or parsed.path
                if ":" in h:
                    h = h.split(":", 1)[0]
                if h:
                    target_hosts.add(h.lower().strip())
            except Exception:
                pass

        # Structure to collect findings by host: host -> list of findings
        crawled_findings: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        total_findings_found = 0

        # Severity counters for logging/telemetry
        severity_counts = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0
        }

        try:
            with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False, encoding="utf-8", newline="\n") as f:
                temp_path = f.name
                f.write("\n".join(urls) + "\n")

            with open(temp_path, "r", encoding="utf-8") as f_check:
                lines = f_check.read().splitlines()
                lines_count = len(lines)

            temp_log = (
                f"[TEMP LOG] Nuclei File Creation:\n"
                f"  - Number of URLs written to the temporary Nuclei input file: {len(urls)}\n"
                f"  - Number of lines in the temporary file: {lines_count}"
            )
            logger.info(temp_log)
            yield {"type": "log", "message": temp_log}

            wsl_temp_path = self._windows_path_to_wsl(temp_path) if is_windows else temp_path

            args = ["/home/kali/go/bin/nuclei"] if is_windows else []
            nuclei_flags = [
                "-l", wsl_temp_path,
                "-tags", ",".join(DEFAULT_CATEGORIES),
                "-jsonl",
                "-silent",
                "-duc",  # Disable update check
            ]
            cmd = [executable, *args, *nuclei_flags]

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
                bufsize=1,
            )
            register_process(process)

            try:
                assert process.stdout is not None

                for raw_line in process.stdout:
                    await check_job_status()
                    line = (raw_line or "").strip()
                    if not line:
                        continue

                    try:
                        record = json.loads(line)
                    except Exception:
                        continue

                    template_id = record.get("template-id") or record.get("template_id")
                    info = record.get("info") or {}
                    name = info.get("name")
                    severity = (info.get("severity") or "info").lower()
                    matched_url = record.get("matched-at") or record.get("matched_at") or record.get("matched")

                    if not template_id or not matched_url:
                        continue

                    # Stream finding in real-time
                    yield {
                        "type": "log",
                        "message": f"\nFinding:\nSeverity: {severity.upper()}\nTemplate: {name or template_id}\nMatched URL:\n{matched_url}"
                    }

                    # Parse detailed info fields
                    description = info.get("description") or ""
                    tags = info.get("tags") or []
                    if isinstance(tags, str):
                        tags = [t.strip() for t in tags.split(",") if t.strip()]

                    classification = info.get("classification") or {}
                    cve = classification.get("cve-id") or classification.get("cve_id")

                    reference_urls = info.get("reference") or []
                    if isinstance(reference_urls, str):
                        reference_urls = [r.strip() for r in reference_urls.split(",") if r.strip()]

                    finding = {
                        "template_id": template_id,
                        "name": name or template_id,
                        "severity": severity,
                        "matched_url": matched_url,
                        "description": description,
                        "tags": tags,
                        "cve": cve,
                        "reference_urls": reference_urls,
                        "timestamp": record.get("timestamp") or datetime.utcnow().isoformat()
                    }

                    # Find which target host this belongs to
                    try:
                        parsed_match = urlparse(matched_url)
                        match_host = parsed_match.hostname or parsed_match.path
                        if ":" in match_host:
                            match_host = match_host.split(":", 1)[0]
                        match_host = match_host.lower().strip()
                    except Exception:
                        continue

                    matched_host = None
                    if match_host in target_hosts:
                        matched_host = match_host
                    else:
                        for th in target_hosts:
                            if match_host.endswith("." + th) or th.endswith("." + match_host):
                                matched_host = th
                                break

                    if matched_host:
                        crawled_findings[matched_host].append(finding)
                        total_findings_found += 1
                        if severity in severity_counts:
                            severity_counts[severity] += 1

                    await asyncio.sleep(0)
            finally:
                unregister_process(process)
                if process.poll() is None:
                    process.terminate()
                    process.wait()

            stderr_out = ""
            try:
                if process.stderr is not None:
                    stderr_out = process.stderr.read() or ""
            except Exception:
                pass

            if stderr_out.strip():
                logger.warning(f"[nuclei stderr] {stderr_out.strip()}")
                yield {"type": "log", "message": f"[nuclei stderr] {stderr_out.strip()}"}

            exit_code = process.wait()
            if exit_code != 0:
                msg = f"[-] Nuclei exited with code: {exit_code}"
                logger.error(msg)
                yield {"type": "log", "message": msg}

        except Exception as exc:
            logger.error(f"[-] Nuclei scan failed: {exc}", exc_info=True)
            yield {"type": "log", "message": f"[-] Nuclei scan failed: {str(exc)}"}
        finally:
            if temp_path and os.path.exists(temp_path):
                try:
                    os.unlink(temp_path)
                except Exception:
                    pass

        # Yield asset events to update the database for each host that had findings
        for host, findings in crawled_findings.items():
            yield {
                "type": "asset",
                "data": {
                    "domain": host,
                    "type": "subdomain",
                    "status": "live",
                    "metadata": {
                        "source": "nuclei",
                        "nuclei": {
                            "findings": findings,
                            "scanned_at": int(time.time()),
                        }
                    },
                    "discovered_by": "nuclei",
                    "sources": ["nuclei"],
                }
            }

        duration_s = int(time.time() - start_ts)
        yield {"type": "log", "message": "\nNuclei completed."}
        yield {
            "type": "scan_summary",
            "provider": self.name,
            "urls_scanned": len(urls),
            "findings_found": total_findings_found,
            "duration_seconds": duration_s,
            "severity_counts": severity_counts
        }
