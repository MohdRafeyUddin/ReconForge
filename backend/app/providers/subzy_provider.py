"""SubzyProvider
===============
Checks resolved subdomains for subdomain takeover vulnerabilities using subzy.

Pipeline position:  … → DNSx → **Subzy** → Naabu → HTTPX → …

Responsibilities:
- Accepts a flat list of resolved subdomain strings (output of DnsxProvider).
- Runs subzy with JSON output.
- Classifies each result as:
      "Vulnerable"      – subzy detected a takeover fingerprint
      "Not Vulnerable"  – explicitly confirmed clean
      "Unknown"         – could not determine
- Yields log events and asset events using the standard ReconForge format.
- Emits a scan_summary event when finished.

subzy is intentionally NOT registered as a standalone discovery provider.
UnifiedDiscoveryProvider calls it after DNSx resolution.
"""

import asyncio
import json
import logging
import os
import platform
import subprocess
import tempfile
import time
from typing import Any, AsyncGenerator, Dict, List, Optional

from app.providers.base import BaseProvider

logger = logging.getLogger("reconforge.providers.subzy")

# Canonical takeover status values
STATUS_VULNERABLE = "Vulnerable"
STATUS_NOT_VULNERABLE = "Not Vulnerable"
STATUS_UNKNOWN = "Unknown"


class SubzyProvider(BaseProvider):
    """Subdomain takeover checker powered by subzy."""

    @property
    def name(self) -> str:
        return "Subzy"

    @property
    def description(self) -> str:
        return (
            "Checks resolved subdomains for takeover vulnerabilities using subzy, "
            "classifying each as Vulnerable, Not Vulnerable, or Unknown."
        )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _windows_path_to_wsl(path: str) -> str:
        drive, rest = os.path.splitdrive(os.path.abspath(path))
        drive_letter = drive.rstrip(":").lower()
        rest = rest.replace("\\", "/")
        return f"/mnt/{drive_letter}{rest}"

    @staticmethod
    def _parse_result(line: str) -> Optional[Dict[str, Any]]:
        """Parse a single subzy JSON output line.

        subzy JSON schema (simplified):
            {
              "subdomain": "foo.example.com",
              "vulnerable": true | false,
              "service": "GitHub Pages",
              "cname": "..."
            }

        Returns dict with keys: subdomain, takeover_status, service, cname.
        Returns None if line is unparseable or missing required fields.
        """
        text = (line or "").strip()
        if not text:
            return None

        # subzy sometimes emits plain-text status lines; ignore those
        if not text.startswith("{"):
            return None

        try:
            payload = json.loads(text)
        except json.JSONDecodeError:
            return None

        subdomain = (payload.get("subdomain") or payload.get("host") or "").strip().lower()
        if not subdomain:
            return None

        vulnerable_raw = payload.get("vulnerable")
        if vulnerable_raw is True:
            takeover_status = STATUS_VULNERABLE
        elif vulnerable_raw is False:
            takeover_status = STATUS_NOT_VULNERABLE
        else:
            takeover_status = STATUS_UNKNOWN

        service = payload.get("service") or payload.get("fingerprint") or ""
        cname   = payload.get("cname") or ""

        return {
            "subdomain": subdomain,
            "takeover_status": takeover_status,
            "service": str(service),
            "cname": str(cname),
        }

    # ------------------------------------------------------------------
    # Main entry point
    # ------------------------------------------------------------------

    async def discover(
        self, seed_domains: List[str]
    ) -> AsyncGenerator[Dict[str, Any], None]:
        """
        seed_domains – resolved subdomain strings from DnsxProvider.
        """
        hosts = list(
            dict.fromkeys(h.strip().lower() for h in seed_domains if h and h.strip())
        )

        yield {"type": "log", "message": "\n========== Subzy Takeover Check =========="}
        yield {"type": "log", "message": "Launching Subzy..."}
        yield {"type": "log", "message": f"Checking {len(hosts)} resolved subdomains..."}

        if not hosts:
            msg = "Subzy completed. No subdomains provided."
            logger.info(msg)
            yield {"type": "log", "message": msg}
            yield {
                "type": "scan_summary",
                "provider": self.name,
                "checked": 0,
                "vulnerable": 0,
                "not_vulnerable": 0,
                "unknown": 0,
            }
            return

        is_windows = platform.system().lower() == "windows"
        executable = "wsl" if is_windows else "/home/kali/go/bin/subzy"
        temp_path = ""
        start_ts = time.time()

        vulnerable_count = 0
        not_vulnerable_count = 0
        unknown_count = 0

        try:
            # Write hosts to a temp file for subzy --targets flag
            with tempfile.NamedTemporaryFile(
                mode="w",
                encoding="utf-8",
                delete=False,
                suffix=".txt",
                dir=os.getcwd(),
            ) as target_file:
                target_file.write("\n".join(hosts))
                target_file.write("\n")
                temp_path = target_file.name

            list_path = (
                self._windows_path_to_wsl(temp_path) if is_windows else temp_path
            )

            subzy_bin = "/home/kali/go/bin/subzy"
            args = [subzy_bin] if is_windows else []
            subzy_flags = [
                "run",
                "--targets", list_path,
                "--output", "json",
                "--hide_fails",     # only print vulnerable + unknown
            ]
            cmd = [executable, *args, *subzy_flags]

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
                    result = self._parse_result(raw_line)
                    if result is None:
                        continue

                    subdomain      = result["subdomain"]
                    takeover_status = result["takeover_status"]
                    service        = result["service"]
                    cname          = result["cname"]

                    # Count by status
                    if takeover_status == STATUS_VULNERABLE:
                        vulnerable_count += 1
                        icon = "[!]"
                    elif takeover_status == STATUS_NOT_VULNERABLE:
                        not_vulnerable_count += 1
                        icon = "[+]"
                    else:
                        unknown_count += 1
                        icon = "[?]"

                    log_parts = [f"{icon} {subdomain} → {takeover_status}"]
                    if service:
                        log_parts.append(f"Service={service}")
                    if cname:
                        log_parts.append(f"CNAME={cname}")
                    log_msg = " | ".join(log_parts)
                    logger.info(log_msg)
                    yield {"type": "log", "message": log_msg}

                    yield {
                        "type": "asset",
                        "data": {
                            "domain": subdomain,
                            "type": "subdomain",
                            # Keep existing status if not vulnerable; mark vulnerable clearly
                            "status": "vulnerable" if takeover_status == STATUS_VULNERABLE else "resolved",
                            "open_ports": [],
                            "metadata": {
                                "source": "subzy",
                                "subzy": {
                                    "takeover_status": takeover_status,
                                    "service": service,
                                    "cname": cname,
                                    "checked_at": int(time.time()),
                                },
                            },
                            "discovered_by": "subzy",
                            "sources": ["subzy"],
                        },
                    }
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
                stderr_out = ""

            if stderr_out.strip():
                logger.warning("[subzy stderr] %s", stderr_out.strip())
                yield {"type": "log", "message": f"[subzy stderr] {stderr_out.strip()}"}

        except Exception as exc:
            logger.exception("[-] SubzyProvider failed: %s", exc)
            yield {"type": "log", "message": f"[-] SubzyProvider failed: {exc}"}

        finally:
            if temp_path:
                try:
                    os.unlink(temp_path)
                except OSError:
                    logger.warning("Failed to remove Subzy target file: %s", temp_path)

        duration_s = int(time.time() - start_ts)
        complete_msg = (
            f"Subzy completed. "
            f"Vulnerable: {vulnerable_count} | "
            f"Not Vulnerable: {not_vulnerable_count} | "
            f"Unknown: {unknown_count} | "
            f"Duration: {duration_s}s"
        )
        logger.info(complete_msg)
        yield {"type": "log", "message": complete_msg}
        yield {
            "type": "scan_summary",
            "provider": self.name,
            "checked": len(hosts),
            "vulnerable": vulnerable_count,
            "not_vulnerable": not_vulnerable_count,
            "unknown": unknown_count,
            "duration_seconds": duration_s,
        }
