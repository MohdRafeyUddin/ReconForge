"""HttpxProvider
================
Standalone HTTP probing provider.

Phase: Standalone only (NOT integrated into Unified Discovery).

- Receives a list of hostnames (subdomains)
- Executes httpx with JSON output when possible
- Streams results as soon as each host is processed
- Emits provider `log` and `asset` events in the existing ReconForge format
- Preserves backend logging and isolates failures per host

Expected JSON fields (httpx --json output, varies by version):
- host
- url
- status_code
- title
- ip
- server
- tech (or technologies)
- response_time
- content_length

If fields are missing, provider will best-effort map alternatives.
"""

import asyncio
import json
import logging
import platform
import subprocess
import time
from typing import AsyncGenerator, Dict, Any, List, Optional

from app.providers.base import BaseProvider

logger = logging.getLogger("reconforge.providers.httpx")


class HttpxProvider(BaseProvider):
    @property
    def name(self) -> str:
        return "Httpx"

    @property
    def description(self) -> str:
        return (
            "Probes discovered subdomains using httpx and streams live endpoints "
            "with status code, title, IP, server, technologies, response time, and content length."
        )

    @staticmethod
    def _coalesce(d: Dict[str, Any], *keys: str) -> Any:
        for k in keys:
            if k in d and d[k] is not None:
                return d[k]
        return None

    @staticmethod
    def _to_int(value: Any) -> Optional[int]:
        try:
            if value is None:
                return None
            # httpx sometimes reports floats or numeric strings
            return int(float(str(value).strip()))
        except Exception:
            return None

    @staticmethod
    def _normalise_tech(tech: Any) -> List[str]:
        if tech is None:
            return []
        if isinstance(tech, list):
            return [str(x) for x in tech if str(x).strip()]
        if isinstance(tech, str):
            # httpx may return comma/space separated string
            parts = [p.strip() for p in tech.replace("|", ",").replace(" ", ",").split(",")]
            return [p for p in parts if p]
        return [str(tech)]

    async def discover(self, seed_domains: List[str]) -> AsyncGenerator[Dict[str, Any], None]:
        msg = f"[*] Httpx Provider selected. Hosts received: {', '.join(seed_domains)}"
        logger.info(msg)
        yield {"type": "log", "message": msg}

        if not seed_domains:
            complete_msg = "[√] Httpx scan complete. No hosts provided."
            logger.info(complete_msg)
            yield {"type": "log", "message": complete_msg}
            yield {"type": "scan_summary", "provider": self.name, "hosts_processed": 0}
            return

        is_windows = platform.system().lower() == "windows"

        executable = "wsl" if is_windows else "/home/kali/go/bin/httpx"
        args: List[str]
        if is_windows:
            # wsl binary expects a Linux command path as its first arg
            args = [
                "/home/kali/go/bin/httpx",
            ]
        else:
            args = []

        # Build command for both platforms.
        # Flags focus on required fields and JSON output.
        # We stream by reading stdout line-by-line.
        httpx_flags = [
            "-json",
            # Probe http and https by default.
            "-silent",
            # -tech-detect enables technology detection. Flag support depends on httpx version.
            "-tech-detect",
            # Follow redirects so we get final title/status.
            "-follow-redirects",
            # Reasonable timeouts; avoids hanging forever.
            "-timeout",
            "10",
        ]

        # Ensure unique order not required per constraints; keep input order.
        hosts = [h.strip() for h in seed_domains if h and h.strip()]

        # httpx requires targets via the `-u` flag for reliable parsing.
        # Build command: httpx ... -u <host1> -u <host2> ...
        u_args: List[str] = []
        for h in hosts:
            u_args.extend(["-u", h])

        cmd = (
            [executable, *args, *httpx_flags, *u_args]
            if executable == "wsl"
            else [executable, *httpx_flags, *u_args]
        )


        cmd_str = " ".join(cmd)
        exec_msg = f"[*] Executing command: {cmd_str}"
        logger.info(exec_msg)
        yield {"type": "log", "message": exec_msg}

        start_ts = time.time()
        hosts_processed = 0
        live_hosts = 0

        def parse_json_line(line: str) -> Optional[Dict[str, Any]]:
            s = (line or "").strip()
            if not s:
                return None
            try:
                return json.loads(s)
            except Exception:
                return None

        def build_asset(payload: Dict[str, Any]) -> Optional[Dict[str, Any]]:
            # Determine URL/host.
            host = payload.get("host") or payload.get("hostname")
            url = payload.get("url")
            if not url and host:
                # Best-effort
                url = host if str(host).startswith("http") else f"https://{host}"

            status_code = payload.get("status_code")
            if status_code is None:
                status_code = payload.get("status")

            # Live/Dead logic:
            # Consider status code 200-399 as live; others as dead.
            status_int = self._to_int(status_code)
            is_live = status_int is not None and 200 <= status_int < 400

            title = payload.get("title")
            ip = self._coalesce(payload, "ip", "ip_address")
            server = self._coalesce(payload, "server", "server_header")
            tech_raw = self._coalesce(payload, "tech", "technologies", "technology", "tech_detect")
            technologies = self._normalise_tech(tech_raw)
            response_time = self._coalesce(payload, "response_time", "response", "rt")
            response_time_int = self._to_int(response_time)
            content_length = self._coalesce(payload, "content_length", "contentLength", "cl")
            content_length_int = self._to_int(content_length)
            tls_info = self._coalesce(payload, "tls_info", "ssl_info", "tls", "ssl")

            if not host and url:
                # derive host from URL
                try:
                    # minimal parsing
                    stripped = str(url).split("//", 1)[-1]
                    host = stripped.split("/", 1)[0]
                except Exception:
                    host = None

            if not host or not url:
                return None

            # Preserve identity: keep the ORIGINAL scanned hostname as `domain`.
            scanned_host = payload.get("input") or payload.get("host") or payload.get("hostname") or host

            asset = {
                "domain": scanned_host,  # identity must remain the original input hostname
                "type": "subdomain" if is_live is False else "subdomain",
                # Represent as live/dead while staying compatible with existing asset model.
                "status": "live" if is_live else "dead",
                "open_ports": [],
                "metadata": {
                    "url": url,
                    # Redirect target is stored separately to avoid overwriting identity.
                    "redirect_location": payload.get("redirect") or payload.get("redirect_location") or payload.get("location"),
                    "status_code": status_int,
                    "title": title,
                    "ip": ip,
                    "server": server,
                    "technologies": technologies,
                    "response_time": response_time_int,
                    "content_length": content_length_int,
                    "source": "httpx",
                },
                "discovered_by": "httpx",
                "sources": ["httpx"],
            }

            return asset

        try:
            # Stream stdout line-by-line.
            # Use Popen because httpx is interactive/streaming.
            if is_windows:
                # wsl run uses command: wsl /home/kali/go/bin/httpx ...
                process = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    bufsize=1,
                )
            else:
                process = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    bufsize=1,
                )

            assert process.stdout is not None

            for raw_line in process.stdout:
                parsed = parse_json_line(raw_line)
                if not parsed:
                    continue

                asset = build_asset(parsed)
                if not asset:
                    continue

                hosts_processed += 1
                if asset["status"] == "live":
                    live_hosts += 1
                    logger.info(f"[+] Live host: {asset['domain']} ({asset['metadata'].get('url')})")
                else:
                    logger.info(f"[*] Dead host: {asset['domain']} ({asset['metadata'].get('url')})")

                # Emit asset immediately so router->websocket->frontend updates.
                yield {"type": "asset", "data": asset}

                await asyncio.sleep(0)

            # Best-effort stderr logging
            stderr_out = ""
            try:
                if process.stderr is not None:
                    stderr_out = process.stderr.read() or ""
            except Exception:
                stderr_out = ""

            if stderr_out.strip():
                logger.warning(f"[httpx stderr] {stderr_out.strip()}")
                yield {"type": "log", "message": f"[httpx stderr] {stderr_out.strip()}"}

            exit_code = process.wait()
            if exit_code != 0:
                err_msg = f"[-] Httpx exited with code: {exit_code}"
                logger.error(err_msg)
                yield {"type": "log", "message": err_msg}

        except Exception as e:
            # Provider-level failure should not break system; emit error log and finish.
            logger.exception(f"[-] HttpxProvider failed: {e}")
            yield {"type": "log", "message": f"[-] HttpxProvider failed: {str(e)}"}

        duration_s = int(time.time() - start_ts)
        complete_msg = (
            f"[√] Httpx scan complete. Processed: {hosts_processed} | Live: {live_hosts} | Duration: {duration_s}s"
        )
        logger.info(complete_msg)
        yield {"type": "log", "message": complete_msg}

        yield {
            "type": "scan_summary",
            "provider": self.name,
            "hosts_processed": hosts_processed,
            "live_hosts": live_hosts,
            "duration_seconds": duration_s,
        }

