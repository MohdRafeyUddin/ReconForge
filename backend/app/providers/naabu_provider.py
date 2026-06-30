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

    async def discover(self, seed_domains: List[str]) -> AsyncGenerator[Dict[str, Any], None]:
        hosts = list(dict.fromkeys(h.strip().lower() for h in seed_domains if h and h.strip()))

        yield {"type": "log", "message": "\n========== Naabu =========="}
        yield {"type": "log", "message": "Launching Naabu..."}
        yield {"type": "log", "message": f"Scanning {len(hosts)} LIVE hosts..."}

        if not hosts:
            msg = "Naabu completed. No LIVE hosts provided."
            logger.info(msg)
            yield {"type": "log", "message": msg}
            yield {"type": "scan_summary", "provider": self.name, "hosts_scanned": 0, "open_ports": 0}
            return

        is_windows = platform.system().lower() == "windows"
        executable = "wsl" if is_windows else "/home/kali/go/bin/naabu"
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
            args = ["/home/kali/go/bin/naabu"] if is_windows else []
            naabu_flags = [
                "-list",
                list_path,
                "-json",
                "-silent",
            ]
            cmd = [executable, *args, *naabu_flags]

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
                current_host: Optional[str] = None

                for raw_line in process.stdout:
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

            stderr_out = ""
            try:
                if process.stderr is not None:
                    stderr_out = process.stderr.read() or ""
            except Exception:
                stderr_out = ""

            if stderr_out.strip():
                logger.warning(f"[naabu stderr] {stderr_out.strip()}")
                yield {"type": "log", "message": f"[naabu stderr] {stderr_out.strip()}"}

            exit_code = process.wait()
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

        total_ports = sum(len(ports) for ports in open_ports_by_host.values())
        for host, ports in sorted(open_ports_by_host.items()):
            yield {
                "type": "asset",
                "data": {
                    "domain": host,
                    "type": "subdomain",
                    "status": "live",
                    "open_ports": sorted(ports),
                    "metadata": {
                        "source": "naabu",
                        "naabu": {
                            "open_ports": sorted(ports),
                            "scanned_at": int(time.time()),
                        },
                    },
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
        yield {
            "type": "scan_summary",
            "provider": self.name,
            "hosts_scanned": len(hosts),
            "hosts_with_open_ports": len(open_ports_by_host),
            "open_ports": total_ports,
            "duration_seconds": duration_s,
        }
