"""Internal Naabu provider for open-port enrichment.

Naabu is intentionally not registered as a standalone discovery provider.
Unified Discovery calls it after HTTPX and passes the deduplicated LIVE hosts.
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
from typing import Any, AsyncGenerator, Dict, List, Optional

from app.providers.base import BaseProvider

logger = logging.getLogger("reconforge.providers.naabu")


class NaabuProvider(BaseProvider):
    @property
    def name(self) -> str:
        return "Naabu"

    @property
    def description(self) -> str:
        return "Internal open-port scanner for LIVE hosts discovered by HTTPX."

    @staticmethod
    def _to_int(value: Any) -> Optional[int]:
        try:
            if value is None:
                return None
            return int(str(value).strip())
        except Exception:
            return None

    @staticmethod
    def _windows_path_to_wsl(path: str) -> str:
        drive, rest = os.path.splitdrive(os.path.abspath(path))
        drive_letter = drive.rstrip(":").lower()
        rest = rest.replace("\\", "/")
        return f"/mnt/{drive_letter}{rest}"

    @staticmethod
    def _parse_result(line: str) -> Optional[Dict[str, Any]]:
        text = (line or "").strip()
        if not text:
            return None

        try:
            payload = json.loads(text)
            host = (
                payload.get("host")
                or payload.get("ip")
                or payload.get("hostname")
                or payload.get("input")
            )
            port = NaabuProvider._to_int(payload.get("port"))
            if host and port:
                return {"host": str(host).strip(), "port": port}
        except Exception:
            pass

        # Fallback for plain output such as host:443, https://host:443, or 443.
        if ":" in text:
            left, right = text.rsplit(":", 1)
            port = NaabuProvider._to_int(right)
            host = left.split("//", 1)[-1].split("/", 1)[0].strip()
            if host and port:
                return {"host": host, "port": port}

        return None

    async def discover(
        self,
        seed_domains: List[str],
        rate_limit: Optional[int] = None,
        scan_mode: str = "fast",
        port_range: Optional[str] = None,
        cdn_excluded_hosts: Optional[Dict[str, str]] = None,
        timeout: Optional[int] = None,
        **kwargs: Any,
    ) -> AsyncGenerator[Dict[str, Any], None]:
        from app.core.tools import is_tool_available
        from app.job_control import register_process, unregister_process, check_job_status

        all_hosts = list(dict.fromkeys(h.strip().lower() for h in seed_domains if h and h.strip()))

        yield {"type": "log", "message": f"\n========== Naabu Port Scan ({scan_mode.upper()} MODE) =========="}
        yield {"type": "log", "message": "Launching Naabu..."}

        # CDN exclusions (exclude CDN edge IPs/hosts from wide port scans)
        hosts: List[str] = []
        excluded_map = cdn_excluded_hosts or {}
        for h in all_hosts:
            if h in excluded_map:
                reason = excluded_map[h]
                yield {"type": "log", "message": f"[*] [CDN Exclusion] {h} excluded from wide port scan: {reason}"}
                yield {
                    "type": "asset",
                    "data": {
                        "domain": h,
                        "type": "subdomain",
                        "status": "live",
                        "open_ports": [],
                        "cdn_waf": {
                            "is_cdn": True,
                            "exclusion_reason": reason,
                        },
                        "metadata": {
                            "source": "naabu",
                            "port_scan_skipped": True,
                            "skip_reason": reason,
                        },
                        "discovered_by": "naabu",
                        "sources": ["naabu"],
                    },
                }
            else:
                hosts.append(h)

        yield {"type": "log", "message": f"Scanning {len(hosts)} target host(s)..."}

        if not hosts:
            msg = "Naabu completed. No candidate hosts to scan."
            logger.info(msg)
            yield {"type": "log", "message": msg}
            yield {"type": "scan_summary", "provider": self.name, "hosts_scanned": 0, "open_ports": 0}
            return

        is_windows = platform.system().lower() == "windows"
        tool_path = self.detect_tool("naabu")

        if not tool_path:
            err_msg = "Naabu binary not found (tool_missing: naabu)"
            logger.error(err_msg)
            yield {
                "type": "stage_error",
                "stage": "naabu",
                "tool": "naabu",
                "message": err_msg,
            }
            yield {
                "type": "scan_summary",
                "provider": "naabu",
                "status": "SKIPPED",
                "count": 0,
            }
            return

        executable = "wsl" if is_windows else tool_path
        temp_path = ""
        open_ports_by_host: Dict[str, set[int]] = defaultdict(set)
        start_ts = time.time()

        try:
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

            list_path = self._windows_path_to_wsl(temp_path) if is_windows else temp_path
            args = ["-e", tool_path] if is_windows else []
            naabu_flags = [
                "-list",
                list_path,
                "-json",
                "-silent",
            ]

            # Fast mode uses top ports (default). Deep mode uses wide port range.
            if scan_mode == "deep":
                target_range = port_range if port_range else "1-10000"
                naabu_flags.extend(["-p", target_range])
                yield {"type": "log", "message": f"[*] Deep mode: scanning port range {target_range}"}

            if rate_limit:
                naabu_flags.extend(["-rate", str(rate_limit)])

            cmd = [executable, *args, *naabu_flags]

            exec_msg = self.format_cmd_log(cmd)
            logger.info(exec_msg)
            yield {"type": "log", "message": exec_msg}

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

            stage_timeout = timeout or kwargs.get("timeout") or max(60, len(hosts) * 10)
            try:
                try:
                    stdout_str, stderr_out = process.communicate(timeout=stage_timeout)
                except subprocess.TimeoutExpired:
                    logger.warning("[-] Naabu timed out after %ss; terminating subprocess", stage_timeout)
                    process.kill()
                    stdout_str, stderr_out = process.communicate()

                current_host: Optional[str] = None
                for raw_line in (stdout_str or "").splitlines():
                    await check_job_status()
                    parsed = self._parse_result(raw_line)
                    if not parsed:
                        continue

                    host = parsed["host"].lower()
                    port = parsed["port"]
                    if host not in hosts or port in open_ports_by_host[host]:
                        continue

                    open_ports_by_host[host].add(port)
                    if host != current_host:
                        current_host = host
                        yield {"type": "log", "message": host}
                    yield {"type": "log", "message": str(port)}

                    await asyncio.sleep(0)
            finally:
                unregister_process(process)
                if process.poll() is None:
                    process.terminate()
                    process.wait()

            if (stderr_out or "").strip():
                logger.warning(f"[naabu stderr] {stderr_out.strip()}")
                yield {"type": "log", "message": f"[naabu stderr] {stderr_out.strip()}"}

            exit_code = process.poll() or 0
            if exit_code != 0:
                msg = f"[-] Naabu exited with code: {exit_code}"
                logger.error(msg)
                yield {"type": "log", "message": msg}

        except Exception as exc:
            logger.exception(f"[-] NaabuProvider failed: {exc}")
            yield {"type": "log", "message": f"[-] NaabuProvider failed: {str(exc)}"}

        finally:
            if temp_path:
                try:
                    os.unlink(temp_path)
                except OSError:
                    logger.warning("Failed to remove Naabu target file: %s", temp_path)

        # Optional: Nmap -sV service detection on open ports (Deep mode or when ports found)
        host_services: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        if open_ports_by_host:
            if not is_tool_available("nmap"):
                yield {"type": "stage_skipped", "stage": "Service Detection (nmap)", "tool": "nmap", "reason": "tool_missing: nmap"}
                yield {"type": "log", "message": "[!] Tool 'nmap' is not installed in WSL. Skipping service detection (-sV)."}
            else:
                yield {"type": "log", "message": "\n[*] Running Nmap service detection (-sV) on open ports..."}
                nmap_path = self.detect_tool("nmap")
                nmap_exec = "wsl" if is_windows else nmap_path
                nmap_base_args = ["-e", nmap_path] if is_windows else []

                for target_host, ports_set in open_ports_by_host.items():
                    await check_job_status()
                    ports_str = ",".join(str(p) for p in sorted(ports_set))
                    nmap_cmd = [nmap_exec, *nmap_base_args, "-sV", "-T4", "--open", "-p", ports_str, target_host]

                    try:
                        nmap_proc = subprocess.Popen(
                            nmap_cmd,
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE,
                            text=True,
                            encoding="utf-8",
                            errors="replace",
                        )
                        register_process(nmap_proc)
                        try:
                            nmap_out, _ = nmap_proc.communicate(timeout=30)
                        except subprocess.TimeoutExpired:
                            logger.warning("[-] nmap service detection timed out on %s; terminating subprocess", target_host)
                            nmap_proc.kill()
                            nmap_out, _ = nmap_proc.communicate()
                        finally:
                            unregister_process(nmap_proc)

                        # Parse nmap output lines (e.g., "80/tcp open http Apache httpd 2.4.41")
                        for line in (nmap_out or "").splitlines():
                            l_strip = line.strip()
                            if "/tcp" in l_strip or "/udp" in l_strip:
                                parts = l_strip.split(None, 3)
                                if len(parts) >= 3 and parts[1] == "open":
                                    p_num = self._to_int(parts[0].split("/")[0])
                                    proto = parts[0].split("/")[1] if "/" in parts[0] else "tcp"
                                    svc = parts[2]
                                    ver = parts[3] if len(parts) > 3 else ""
                                    svc_info = {"port": p_num, "protocol": proto, "service": svc, "version": ver}
                                    host_services[target_host].append(svc_info)
                                    log_line = f"[+] [nmap -sV] {target_host}:{p_num} -> {svc} {ver}".strip()
                                    logger.info(log_line)
                                    yield {"type": "log", "message": log_line}
                    except Exception as nmap_err:
                        logger.debug("nmap failed on %s: %s", target_host, nmap_err)

        total_ports = sum(len(ports) for ports in open_ports_by_host.values())
        for host, ports in sorted(open_ports_by_host.items()):
            asset_meta = {
                "source": "naabu",
                "naabu": {
                    "open_ports": sorted(ports),
                    "scanned_at": int(time.time()),
                },
            }
            if host in host_services and host_services[host]:
                asset_meta["services"] = host_services[host]

            yield {
                "type": "asset",
                "data": {
                    "domain": host,
                    "type": "subdomain",
                    "status": "live",
                    "open_ports": sorted(ports),
                    "services": host_services.get(host, []),
                    "metadata": asset_meta,
                    "discovered_by": "naabu",
                    "sources": ["naabu"],
                },
            }

        duration_s = int(time.time() - start_ts)
        complete_msg = "Naabu completed."
        logger.info(
            "%s Hosts with open ports: %s | Open ports: %s | Duration: %ss",
            complete_msg,
            len(open_ports_by_host),
            total_ports,
            duration_s,
        )
        yield {"type": "log", "message": complete_msg}

        hosts_in = len(hosts)
        hosts_with_ports = len(open_ports_by_host)
        hosts_no_ports = hosts_in - hosts_with_ports

        yield {
            "type": "scan_summary",
            "provider": self.name,
            "hosts_scanned": hosts_in,
            "hosts_with_open_ports": hosts_with_ports,
            "hosts_no_ports": hosts_no_ports,
            "open_ports": total_ports,
            "duration_seconds": duration_s,
            "hosts_in": hosts_in,
        }
