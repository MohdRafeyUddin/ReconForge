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

# ---------------------------------------------------------------------------
# Nmap service-detection defaults (global defaults + per-project overrides)
# ---------------------------------------------------------------------------
_NMAP_DEFAULTS_FALLBACK: Dict[str, Any] = {
    "enabled": True,
    "scan_modes": ["deep"],
    "max_hosts": 25,
    "concurrency": 5,
    "timeout_seconds": 15,
    "version_light": True,
    "priority": "interesting",
}
_NMAP_DEFAULTS_PATH = os.path.join(
    os.path.dirname(os.path.dirname(__file__)), "config", "nmap_defaults.json"
)
_NMAP_DEFAULTS_CACHE: Optional[Dict[str, Any]] = None


def _load_nmap_defaults() -> Dict[str, Any]:
    global _NMAP_DEFAULTS_CACHE
    if _NMAP_DEFAULTS_CACHE is not None:
        return dict(_NMAP_DEFAULTS_CACHE)
    defaults = dict(_NMAP_DEFAULTS_FALLBACK)
    try:
        with open(_NMAP_DEFAULTS_PATH, "r", encoding="utf-8") as f:
            loaded = json.load(f)
        if isinstance(loaded, dict):
            for key in defaults:
                if key in loaded and loaded[key] is not None:
                    defaults[key] = loaded[key]
    except Exception as exc:
        logger.warning("Failed to load nmap_defaults.json (%s); using built-in defaults", exc)
    _NMAP_DEFAULTS_CACHE = defaults
    return dict(defaults)


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

    @staticmethod
    def normalize_nmap_options(raw: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Merges per-project options over global defaults and clamps ranges."""
        opts = _load_nmap_defaults()
        if isinstance(raw, dict):
            for key in list(opts.keys()):
                if key in raw and raw[key] is not None:
                    opts[key] = raw[key]
        try:
            opts["max_hosts"] = max(1, min(int(opts.get("max_hosts") or 25), 500))
        except Exception:
            opts["max_hosts"] = 25
        try:
            opts["concurrency"] = max(1, min(int(opts.get("concurrency") or 5), 20))
        except Exception:
            opts["concurrency"] = 5
        try:
            opts["timeout_seconds"] = max(5, min(int(opts.get("timeout_seconds") or 15), 120))
        except Exception:
            opts["timeout_seconds"] = 15
        modes = opts.get("scan_modes")
        if isinstance(modes, str):
            modes = [modes]
        if not isinstance(modes, list):
            modes = ["deep"]
        opts["scan_modes"] = [str(m).strip().lower() for m in modes if str(m).strip()]
        opts["enabled"] = bool(opts.get("enabled", True))
        opts["version_light"] = bool(opts.get("version_light", True))
        return opts

    @staticmethod
    def select_nmap_targets(
        open_ports_by_host: Dict[str, Any],
        scan_mode: str,
        options: Optional[Dict[str, Any]] = None,
    ) -> Any:
        """Returns (selected_targets, skipped_count, skip_reason).

        Deep mode is the default; Fast mode skips service detection entirely.
        Hosts are prioritized by non-standard open ports, then port count, and
        capped at ``max_hosts`` to bound total runtime.
        """
        opts = NaabuProvider.normalize_nmap_options(options)
        if not opts.get("enabled", True):
            return [], 0, "disabled"
        modes = opts.get("scan_modes") or []
        if scan_mode not in modes and "always" not in modes:
            return [], 0, f"{scan_mode} mode (service detection disabled)"

        items = [
            (str(host), sorted(int(p) for p in ports))
            for host, ports in open_ports_by_host.items()
            if ports
        ]
        if opts.get("priority", "interesting") == "interesting":
            items.sort(key=lambda item: (
                -sum(1 for p in item[1] if p not in (80, 443)),
                -len(item[1]),
                item[0],
            ))
        else:
            items.sort(key=lambda item: item[0])

        max_hosts = int(opts["max_hosts"])
        skipped = max(0, len(items) - max_hosts)
        return items[:max_hosts], skipped, ""

    @staticmethod
    def parse_nmap_services(output: str) -> List[Dict[str, Any]]:
        """Parses nmap -sV lines into service records."""
        services: List[Dict[str, Any]] = []
        for line in (output or "").splitlines():
            l_strip = line.strip()
            if "/tcp" not in l_strip and "/udp" not in l_strip:
                continue
            parts = l_strip.split(None, 3)
            if len(parts) < 3 or parts[1] != "open":
                continue
            port_proto = parts[0].split("/")
            try:
                port_num = int(port_proto[0])
            except Exception:
                continue
            services.append({
                "port": port_num,
                "protocol": port_proto[1] if len(port_proto) > 1 else "tcp",
                "service": parts[2],
                "version": parts[3] if len(parts) > 3 else "",
            })
        return services

    async def _run_nmap_async(self, cmd: List[str], timeout: int) -> Any:
        """Runs nmap without blocking the event loop; kills it on timeout."""
        from app.job_control import register_process, unregister_process

        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        register_process(proc)
        try:
            try:
                out_b, err_b = await asyncio.wait_for(proc.communicate(), timeout=timeout)
                return (
                    proc.returncode or 0,
                    (out_b or b"").decode("utf-8", errors="replace"),
                    (err_b or b"").decode("utf-8", errors="replace"),
                )
            except asyncio.TimeoutError:
                try:
                    proc.kill()
                except Exception:
                    pass
                try:
                    await proc.wait()
                except Exception:
                    pass
                return -1, "", f"timeout after {timeout}s"
        finally:
            unregister_process(proc)

    async def discover(
        self,
        seed_domains: List[str],
        rate_limit: Optional[int] = None,
        scan_mode: str = "fast",
        port_range: Optional[str] = None,
        cdn_excluded_hosts: Optional[Dict[str, str]] = None,
        nmap_options: Optional[Dict[str, Any]] = None,
        timeout: Optional[int] = None,
        **kwargs: Any,
    ) -> AsyncGenerator[Dict[str, Any], None]:
        from app.core.tools import is_tool_available
        from app.job_control import register_process, unregister_process, check_job_status

        all_hosts = list(dict.fromkeys(h.strip().lower() for h in seed_domains if h and h.strip()))

        yield {"type": "log", "message": "\n========== Naabu Port Scan =========="}
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

            # Baseline scans stay on the top-1000 ports; the wide switch
            # (passed as scan_mode="deep") upgrades to the project port range.
            if scan_mode == "deep":
                target_range = port_range if port_range else "1-10000"
                naabu_flags.extend(["-p", target_range])
                yield {"type": "log", "message": f"[*] Wide port scan: scanning port range {target_range}"}
            else:
                naabu_flags.extend(["-top-ports", "1000"])
                yield {"type": "log", "message": "[*] Baseline port scan: top 1000 ports"}

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

        # Optional nmap -sV service detection.
        # Bounded by max_hosts/concurrency/timeout; Deep mode only by default.
        host_services: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        nmap_cfg = self.normalize_nmap_options(
            nmap_options if nmap_options is not None else kwargs.get("nmap_options")
        )
        nmap_selected: List[Any] = []
        nmap_skipped = 0
        nmap_reason = ""

        if open_ports_by_host:
            nmap_selected, nmap_skipped, nmap_reason = self.select_nmap_targets(
                open_ports_by_host, scan_mode, nmap_cfg
            )
            if nmap_reason:
                yield {
                    "type": "stage_skipped",
                    "stage": "Service Detection (nmap)",
                    "tool": "nmap",
                    "reason": nmap_reason,
                }
                yield {"type": "log", "message": f"[*] Nmap service detection skipped ({nmap_reason})."}
            elif not is_tool_available("nmap"):
                yield {"type": "stage_skipped", "stage": "Service Detection (nmap)", "tool": "nmap", "reason": "tool_missing: nmap"}
                yield {"type": "log", "message": "[!] Tool 'nmap' is not installed in WSL. Skipping service detection (-sV)."}
            else:
                nmap_path = self.detect_tool("nmap")
                if not nmap_path:
                    yield {"type": "stage_skipped", "stage": "Service Detection (nmap)", "tool": "nmap", "reason": "tool_missing: nmap"}
                    yield {"type": "log", "message": "[!] Tool 'nmap' is not installed in WSL. Skipping service detection (-sV)."}
                else:
                    concurrency = int(nmap_cfg["concurrency"])
                    nmap_timeout = int(nmap_cfg["timeout_seconds"])
                    yield {
                        "type": "log",
                        "message": (
                            f"\n[*] Running Nmap -sV on {len(nmap_selected)}/{len(open_ports_by_host)} host(s) "
                            f"with open ports (concurrency {concurrency}, timeout {nmap_timeout}s/host)..."
                        ),
                    }
                    if nmap_skipped:
                        yield {
                            "type": "log",
                            "message": (
                                f"[*] Service-detection cap: skipping {nmap_skipped} host(s) "
                                f"(max_hosts={nmap_cfg['max_hosts']}). Increase nmap_options.max_hosts to scan more."
                            ),
                        }

                    nmap_exec = "wsl" if is_windows else nmap_path
                    nmap_base_args = ["-e", nmap_path] if is_windows else []
                    sem = asyncio.Semaphore(concurrency)
                    result_queue: asyncio.Queue = asyncio.Queue()

                    async def run_nmap(host: str, ports: List[int]) -> None:
                        services: List[Dict[str, Any]] = []
                        err_msg = ""
                        async with sem:
                            try:
                                await check_job_status()
                                ports_str = ",".join(str(p) for p in ports)
                                nmap_flags = [
                                    "-sV", "-T4", "--open",
                                    "--max-retries", "1",
                                    "--host-timeout", f"{nmap_timeout}s",
                                ]
                                if nmap_cfg.get("version_light", True):
                                    nmap_flags.append("--version-light")
                                nmap_flags.extend(["-p", ports_str, host])
                                cmd = [nmap_exec, *nmap_base_args, *nmap_flags]
                                rc, out, err = await self._run_nmap_async(cmd, timeout=nmap_timeout)
                                services = self.parse_nmap_services(out)
                                if rc != 0:
                                    err_msg = (
                                        f"[-] nmap service detection failed on {host} "
                                        f"(rc={rc}): {(err or '').strip()[:160]}"
                                    )
                            except Exception as exc:
                                err_msg = f"[-] nmap service detection failed on {host}: {exc}"
                            finally:
                                await result_queue.put((host, services, err_msg))

                    nmap_tasks = [asyncio.create_task(run_nmap(h, p)) for h, p in nmap_selected]
                    for _ in nmap_tasks:
                        target_host, services, err_msg = await result_queue.get()
                        if services:
                            host_services[target_host].extend(services)
                            for svc in services:
                                log_line = (
                                    f"[+] [nmap -sV] {target_host}:{svc['port']} -> "
                                    f"{svc['service']} {svc.get('version', '')}"
                                ).strip()
                                logger.info(log_line)
                                yield {"type": "log", "message": log_line}
                        if err_msg:
                            logger.debug(err_msg)
                            yield {"type": "log", "message": err_msg}
                    await asyncio.gather(*nmap_tasks, return_exceptions=True)
                    yield {
                        "type": "log",
                        "message": f"[√] Nmap service detection completed for {len(host_services)} host(s).",
                    }

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
            "nmap_enabled": bool(nmap_cfg.get("enabled")),
            "nmap_hosts_selected": len(nmap_selected),
            "nmap_hosts_with_services": len(host_services),
            "nmap_hosts_skipped": nmap_skipped,
            "nmap_skip_reason": nmap_reason,
        }
