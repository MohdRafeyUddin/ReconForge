"""Internal Nuclei provider for vulnerability and exposure scanning.

Nuclei runs automatically after Katana, scanning first-party live URLs
using safe reconnaissance templates.
"""

import asyncio
import json
import logging
import os
import platform
import queue
import subprocess
import tempfile
import threading
import time
from collections import defaultdict
from datetime import datetime
from typing import AsyncGenerator, Dict, Any, List, Optional
from urllib.parse import urlparse

from app.providers.base import BaseProvider

logger = logging.getLogger("reconforge.providers.nuclei")

# Multi-pass Nuclei configuration
NUCLEI_PASSES = [
    {
        "name": "Critical",
        "tags": "cve,rce,oast",
        "severity": "critical,high"
    },
    {
        "name": "Exposure",
        "tags": "exposure,misconfig,config,default-login,panel,tech,dns,ssl",
        "severity": "medium,high,critical"
    },
    {
        "name": "BugClass",
        "tags": "sqli,xss,ssrf,lfi,ssti,xxe,redirect,idor,injection",
        "severity": "medium,high,critical"
    }
]

PASS_TIMEOUT_SECONDS = 1800

class NucleiProvider(BaseProvider):
    @property
    def name(self) -> str:
        return "Nuclei"

    @property
    def description(self) -> str:
        return "Internal multi-pass vulnerability and exposure scanner."

    @staticmethod
    def _windows_path_to_wsl(path: str) -> str:
        drive, rest = os.path.splitdrive(os.path.abspath(path))
        drive_letter = drive.rstrip(":").lower()
        rest = rest.replace("\\", "/")
        return f"/mnt/{drive_letter}{rest}"

    @staticmethod
    def normalize_url(u: str) -> str:
        u = u.strip()
        if not u:
            return ""
        has_scheme = u.startswith("http://") or u.startswith("https://")
        temp_u = u if has_scheme else "http://" + u
        try:
            parsed = urlparse(temp_u)
            path = parsed.path
            while "//" in path:
                path = path.replace("//", "/")
            scheme = parsed.scheme if has_scheme else ""
            netloc = parsed.netloc
            if has_scheme:
                rebuilt = f"{parsed.scheme}://{netloc}{path}"
            else:
                rebuilt = f"{netloc}{path}"
            if parsed.query:
                rebuilt += f"?{parsed.query}"
            return rebuilt
        except Exception:
            return u

    async def discover(self, seed_domains: List[str]) -> AsyncGenerator[Dict[str, Any], None]:
        # 1. Normalize and deduplicate input URLs
        urls = []
        seen = set()
        for u in seed_domains:
            norm = self.normalize_url(u)
            if norm and norm not in seen:
                seen.add(norm)
                urls.append(norm)

        yield {"type": "log", "message": "\n========== Nuclei =========="}
        yield {"type": "log", "message": "Starting Multi-Pass Nuclei..."}
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
        seen_findings = set()

        # Severity counters for logging/telemetry
        severity_counts = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0
        }

        def read_stdout(stream, q):
            for line in stream:
                q.put(line)
            logger.info("Reader EOF")
            q.put(None)

        def process_line(line: str, current_pass_name: str, current_pass_severity_counts: Dict[str, int]) -> List[Dict[str, Any]]:
            nonlocal total_findings_found, pass_findings_found
            events = []
            try:
                record = json.loads(line)
            except Exception:
                return events

            template_id = record.get("template-id") or record.get("template_id")
            info = record.get("info") or {}
            template_name = info.get("name") or template_id
            severity = (info.get("severity") or "info").lower()
            matched_url = record.get("matched-at") or record.get("matched_at") or record.get("matched")

            if not template_id or not matched_url:
                return events

            # Deduplicate findings in this execution
            f_key = (template_id, matched_url)
            if f_key in seen_findings:
                return events
            seen_findings.add(f_key)

            # Extract additional metadata fields
            try:
                parsed_match = urlparse(matched_url)
                match_host = parsed_match.hostname or parsed_match.path
                if ":" in match_host:
                    match_host = match_host.split(":", 1)[0]
                match_host = match_host.lower().strip()
            except Exception:
                match_host = ""

            ip = record.get("ip") or ""
            tags = info.get("tags") or []
            if isinstance(tags, str):
                tags = [t.strip() for t in tags.split(",") if t.strip()]

            classification = info.get("classification") or {}
            cve = classification.get("cve-id") or classification.get("cve_id") or ""
            cwe = classification.get("cwe-id") or classification.get("cwe_id") or ""
            cvss = classification.get("cvss-score") or classification.get("cvss_score") or ""
            curl_command = record.get("curl-command") or record.get("curl_command") or ""
            timestamp = record.get("timestamp") or datetime.utcnow().isoformat()
            request = record.get("request") or ""
            response = record.get("response") or ""

            finding = {
                "template_id": template_id,
                "template_name": template_name,
                "severity": severity,
                "matched_url": matched_url,
                "host": match_host,
                "ip": ip,
                "tags": tags,
                "classification": classification,
                "cve": cve,
                "cwe": cwe,
                "cvss": cvss,
                "curl_command": curl_command,
                "timestamp": timestamp,
                "request": request,
                "response": response,
                "pass_name": current_pass_name,
                "source": "nuclei"
            }

            # Stream finding in real-time to log console
            events.append({
                "type": "log",
                "message": f"\nFinding:\nSeverity: {severity.upper()}\nTemplate: {template_name}\nMatched URL:\n{matched_url}"
            })

            # Emit FindingDetected WebSocket event
            events.append({
                "type": "scan_summary",
                "event": "FindingDetected",
                "pass_name": current_pass_name,
                "finding": finding
            })

            matched_host = None
            if match_host:
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
                pass_findings_found += 1
                if severity in severity_counts:
                    severity_counts[severity] += 1
                if severity in current_pass_severity_counts:
                    current_pass_severity_counts[severity] += 1

                # Yield asset event immediately to update database & UI
                events.append({
                    "type": "asset",
                    "data": {
                        "domain": matched_host,
                        "type": "subdomain",
                        "status": "live",
                        "metadata": {
                            "source": "nuclei",
                            "nuclei": {
                                "findings": [finding],
                                "scanned_at": int(time.time()),
                            }
                        },
                        "discovered_by": "nuclei",
                        "sources": ["nuclei"],
                    }
                })

            return events

        try:
            # Create ONE temp file and reuse it for all three passes
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

            # Run sequential passes
            for pass_info in NUCLEI_PASSES:
                pass_name = pass_info["name"]
                pass_tags = pass_info["tags"]
                pass_severity = pass_info["severity"]

                # Emit NucleiPassStarted event
                yield {
                    "type": "scan_summary",
                    "event": "NucleiPassStarted",
                    "pass_name": pass_name
                }
                yield {"type": "log", "message": f"\n[*] Starting pass: {pass_name} (tags: {pass_tags})"}
                yield {"type": "log", "message": "Loading templates..."}
                yield {"type": "log", "message": "Templates loaded."}
                yield {"type": "log", "message": f"Scanning {len(urls)} URLs..."}

                args = ["/home/kali/go/bin/nuclei"] if is_windows else []
                # Removed -stats flag
                nuclei_flags = [
                    "-l", wsl_temp_path,
                    "-tags", pass_tags,
                    "-severity", pass_severity,
                    "-jsonl",
                    "-silent",
                    "-duc",
                    "-rl", "150",
                    "-c", "25",
                    "-bs", "25"
                ]
                cmd = [executable, *args, *nuclei_flags]

                exec_msg = f"[*] Executing pass {pass_name}: {' '.join(cmd)}"
                logger.info(exec_msg)
                yield {"type": "log", "message": exec_msg}

                from app.job_control import register_process, unregister_process, check_job_status
                await check_job_status()

                process = None
                t = None
                pass_findings_found = 0
                pass_severity_counts = {
                    "critical": 0,
                    "high": 0,
                    "medium": 0,
                    "low": 0,
                    "info": 0
                }
                pass_start_ts = time.time()
                timeout_exceeded = False

                try:
                    process = subprocess.Popen(
                        cmd,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.STDOUT,  # Merge stderr into stdout
                        text=True,
                        encoding="utf-8",
                        errors="replace",
                        bufsize=1,
                    )
                    logger.info("Process started")
                    register_process(process)

                    q = queue.Queue()
                    t = threading.Thread(target=read_stdout, args=(process.stdout, q))
                    t.daemon = True
                    t.start()
                    logger.info("Reader thread started")

                    last_progress_time = time.time()

                    while True:
                        await check_job_status()

                        # Timeout protection
                        if time.time() - pass_start_ts > PASS_TIMEOUT_SECONDS:
                            timeout_exceeded = True
                            logger.warning(f"Pass {pass_name} exceeded timeout of {PASS_TIMEOUT_SECONDS}s. Terminating process.")
                            yield {
                                "type": "log",
                                "message": f"[-] Pass {pass_name} timed out after {PASS_TIMEOUT_SECONDS} seconds. Terminating..."
                            }
                            break

                        try:
                            raw_line = q.get_nowait()
                        except queue.Empty:
                            # Terminate polling loop when process has exited and queue is empty
                            if process.poll() is not None:
                                break

                            now = time.time()
                            if now - last_progress_time > 15:
                                elapsed = int(now - pass_start_ts)
                                # Emit ProgressUpdated event
                                yield {
                                    "type": "scan_summary",
                                    "event": "ProgressUpdated",
                                    "pass_name": pass_name,
                                    "elapsed": elapsed,
                                    "findings_count": pass_findings_found
                                }
                                yield {"type": "log", "message": f"Nuclei running... {elapsed}s"}
                                last_progress_time = now
                            await asyncio.sleep(0.2)
                            continue

                        if raw_line is None:
                            break

                        line = raw_line.strip()
                        if not line:
                            continue

                        events = process_line(line, pass_name, pass_severity_counts)
                        for ev in events:
                            yield ev

                        last_progress_time = time.time()
                        await asyncio.sleep(0)

                    # Terminate process if timeout exceeded
                    if timeout_exceeded and process and process.poll() is None:
                        process.terminate()
                        try:
                            process.wait(timeout=5)
                        except subprocess.TimeoutExpired:
                            process.kill()
                            process.wait()

                    # Process exited: capture return code
                    return_code = process.poll() if process else None
                    logger.info(f"Process exited ({return_code})")

                    # Drain remaining queue entries
                    drain_start = time.time()
                    while True:
                        try:
                            raw_line = q.get_nowait()
                            if raw_line is None:
                                break
                            line = raw_line.strip()
                            if line:
                                events = process_line(line, pass_name, pass_severity_counts)
                                for ev in events:
                                    yield ev
                        except queue.Empty:
                            if not t.is_alive():
                                break
                            if time.time() - drain_start > 5:
                                break
                            await asyncio.sleep(0.05)
                    logger.info("Queue drained")

                    # Join reader thread
                    if t and t.is_alive():
                        t.join(timeout=5)
                    logger.info("Reader joined")

                except Exception as pass_exc:
                    logger.error(f"[-] Pass {pass_name} failed: {pass_exc}", exc_info=True)
                    yield {"type": "log", "message": f"[-] Pass {pass_name} failed: {str(pass_exc)}"}

                finally:
                    # Clean up pass resources
                    if process:
                        unregister_process(process)
                        if process.poll() is None:
                            process.terminate()
                            try:
                                process.wait(timeout=5)
                            except subprocess.TimeoutExpired:
                                process.kill()
                                process.wait()
                    if t and t.is_alive():
                        t.join(timeout=5)
                    logger.info("Cleanup complete")

                    # Yield PassSummary event
                    yield {
                        "type": "scan_summary",
                        "event": "PassSummary",
                        "pass_name": pass_name,
                        "findings_found": pass_findings_found,
                        "urls_scanned": len(urls),
                        "severity_counts": pass_severity_counts
                    }

                    # Emit NucleiPassCompleted event
                    yield {
                        "type": "scan_summary",
                        "event": "NucleiPassCompleted",
                        "pass_name": pass_name
                    }
                    yield {"type": "log", "message": f"[*] Completed pass: {pass_name}"}
                    logger.info("Pass completed")

        except Exception as exc:
            logger.error(f"[-] Nuclei scan failed: {exc}", exc_info=True)
            yield {"type": "log", "message": f"[-] Nuclei scan failed: {str(exc)}"}
        finally:
            if temp_path and os.path.exists(temp_path):
                try:
                    os.unlink(temp_path)
                except Exception:
                    pass

        duration_s = int(time.time() - start_ts)
        yield {"type": "log", "message": "\nMulti-Pass Nuclei completed."}
        yield {
            "type": "scan_summary",
            "provider": self.name,
            "urls_scanned": len(urls),
            "findings_found": total_findings_found,
            "duration_seconds": duration_s,
            "severity_counts": severity_counts
        }
        logger.info("Provider completed")
