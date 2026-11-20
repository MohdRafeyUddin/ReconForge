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
import os
import platform
import subprocess
import tempfile
import time
from typing import AsyncGenerator, Dict, Any, List, Optional
from urllib.parse import urlparse

from app.providers.base import BaseProvider
from app.core.scope import is_in_scope
from app.core.redaction import SENSITIVE_HEADER_KEYS, redact_text

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

    async def discover(
        self,
        seed_domains: List[str],
        rate_limit: Optional[int] = None,
        custom_headers: Optional[Dict[str, str]] = None,
        scope: Optional[Dict[str, Any]] = None,
        project_id: Optional[str] = None,
        response_body_max_kb: int = 500,
        timeout: Optional[int] = None,
        **kwargs: Any,
    ) -> AsyncGenerator[Dict[str, Any], None]:
        msg = f"[*] Httpx Provider selected. Hosts received: {', '.join(seed_domains)}"
        logger.info(msg)
        yield {"type": "log", "message": msg}

        if not seed_domains:
            complete_msg = "[√] Httpx scan complete. No hosts provided."
            logger.info(complete_msg)
            yield {"type": "log", "message": complete_msg}
            yield {
                "type": "scan_summary",
                "provider": self.name,
                "hosts_processed": 0,
                "hosts_in": 0,
                "hosts_live": 0,
                "hosts_dead": 0,
            }
            yield {
                "type": "scan_summary",
                "event": "PipelineHalted",
                "reason": "no_live_hosts",
                "message": "No live HTTP hosts were found. Katana, GAU, SubJS, LinkFinder, GoWitness, GF, and Nuclei were all skipped because there is nothing for them to scan."
            }
            return

        is_windows = platform.system().lower() == "windows"
        tool_path = self.detect_tool("httpx")

        executable = "wsl" if is_windows else tool_path
        args: List[str]
        if is_windows:
            args = [
                "-e",
                tool_path,
            ]
        else:
            args = []

        # Build command for both platforms.
        # Flags focus on required fields, JSON output, and Phase 3 enrichment.
        httpx_flags = [
            "-json",
            "-silent",
            "-tech-detect",
            "-follow-redirects",
            "-timeout",
            "10",
            # Phase 3 extended probing flags
            "-favicon",
            "-jarm",
            "-tls-grab",
            "-cdn",
            "-hash",
            "sha256",
            "-cname",
            "-asn",
            "-irr",  # include request/response in JSON output for storage
        ]

        if rate_limit:
            httpx_flags.extend(["-rl", str(rate_limit)])

        if custom_headers:
            for hk, hv in custom_headers.items():
                if hk and hv:
                    httpx_flags.extend(["-H", f"{hk}: {hv}"])

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

        exec_msg = self.format_cmd_log(cmd)
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

            # When -follow-redirects is used, verify final target and redirect location against scope
            redirect_target = (
                payload.get("redirect")
                or payload.get("redirect_location")
                or payload.get("location")
            )
            if scope:
                if url and not is_in_scope(url, scope):
                    logger.info(f"[*] HTTPX dropped out-of-scope final URL: {url}")
                    return None
                if host and not is_in_scope(host, scope):
                    logger.info(f"[*] HTTPX dropped out-of-scope final host: {host}")
                    return None
                if redirect_target and not is_in_scope(redirect_target, scope):
                    logger.info(f"[*] HTTPX dropped out-of-scope redirect target: {redirect_target}")
                    return None

            status_code = payload.get("status_code")
            if status_code is None:
                status_code = payload.get("status")

            # Phase 3 Liveness Redefinition:
            # ANY valid HTTP response (including 401, 403, 404, 5xx) qualifies as live.
            status_int = self._to_int(status_code)
            is_live = status_int is not None

            # Determine status class (2xx, 3xx, 4xx, 5xx, or dead)
            if status_int is not None:
                if 200 <= status_int < 300:
                    status_class = "2xx"
                elif 300 <= status_int < 400:
                    status_class = "3xx"
                elif 400 <= status_int < 500:
                    status_class = "4xx"
                elif 500 <= status_int < 600:
                    status_class = "5xx"
                else:
                    status_class = f"{status_int // 100}xx"
            else:
                status_class = "dead"

            # 401/403 hosts flagged interesting
            is_interesting = status_int in (401, 403)
            interesting_reason = (
                f"HTTP {status_int} (Restricted/Auth Required)" if is_interesting else None
            )

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

            # Stored request/response metadata for the asset detail view.
            request_obj = payload.get("request") if isinstance(payload.get("request"), dict) else {}
            response_obj = payload.get("response") if isinstance(payload.get("response"), dict) else {}
            request_method = str(payload.get("method") or request_obj.get("method") or "GET").upper()
            request_headers = self._sanitize_header_items(
                request_obj.get("headers") or payload.get("request_headers")
            )
            response_headers = self._sanitize_header_items(
                response_obj.get("headers") or payload.get("response_headers")
            )

            # Phase 3 enrichments
            favicon_hash = payload.get("favicon_mmh3") or payload.get("favicon") or payload.get("favicon_hash")
            jarm = payload.get("jarm")
            cname = payload.get("cname")
            asn_raw = payload.get("asn") or payload.get("as_number") or payload.get("as_name")
            hash_dict = payload.get("hash") or {}
            body_hash = (
                payload.get("body_sha256")
                or (hash_dict.get("body_sha256") if isinstance(hash_dict, dict) else None)
                or payload.get("sha256")
            )

            # CDN/WAF detection
            is_cdn = bool(payload.get("cdn"))
            cdn_provider = payload.get("cdn_name") or payload.get("cdn_provider") or ""
            server_lower = str(server or "").lower()
            if not is_cdn:
                for cdn_name, pattern in [
                    ("Cloudflare", "cloudflare"),
                    ("CloudFront", "cloudfront"),
                    ("Akamai", "akamai"),
                    ("Fastly", "fastly"),
                    ("Incapsula", "incap"),
                    ("Sucuri", "sucuri"),
                ]:
                    if pattern in server_lower:
                        is_cdn = True
                        cdn_provider = cdn_name
                        break

            cdn_waf_info = None
            if is_cdn:
                cdn_waf_info = {
                    "is_cdn": True,
                    "cdn_provider": cdn_provider or "Generic CDN",
                    "is_waf": bool(str(cdn_provider).lower() in ("cloudflare", "akamai", "imperva", "incapsula", "sucuri")),
                    "exclusion_reason": f"Host is behind CDN ({cdn_provider or 'edge network'}). Excluded from aggressive port scans.",
                }

            if not host and url:
                # derive host from URL
                try:
                    stripped = str(url).split("//", 1)[-1]
                    host = stripped.split("/", 1)[0]
                except Exception:
                    host = None

            if not host or not url:
                return None

            # Preserve identity: keep the ORIGINAL scanned hostname as `domain`.
            scanned_host = payload.get("input") or payload.get("host") or payload.get("hostname") or host

            # Response body persistence to per-project storage
            body_rel_path = None
            body_saved_size = None
            raw_body = payload.get("body") or payload.get("response")
            if raw_body and project_id:
                from app.services.response_storage import save_response_body
                save_res = save_response_body(
                    project_id=project_id,
                    identifier=scanned_host,
                    body=raw_body,
                    max_kb=response_body_max_kb,
                )
                if save_res:
                    body_rel_path, body_saved_size = save_res

            asset = {
                "domain": scanned_host,  # identity must remain the original input hostname
                "type": "subdomain",
                "status": "live" if is_live else "dead",
                "status_class": status_class,
                "is_interesting": is_interesting,
                "interesting_reason": interesting_reason,
                "liveness_version": 2,
                "cdn_waf": cdn_waf_info,
                "open_ports": [],
                "metadata": {
                    "url": url,
                    # Redirect target is stored separately to avoid overwriting identity.
                    "redirect_location": payload.get("redirect") or payload.get("redirect_location") or payload.get("location"),
                    "status_code": status_int,
                    "status_class": status_class,
                    "is_interesting": is_interesting,
                    "interesting_reason": interesting_reason,
                    "liveness_version": 2,
                    "title": title,
                    "ip": ip,
                    "server": server,
                    "technologies": technologies,
                    "response_time": response_time_int,
                    "content_length": content_length_int,
                    "favicon_hash": favicon_hash,
                    "body_hash": body_hash,
                    "jarm": jarm,
                    "cname": cname,
                    "asn": asn_raw,
                    "cdn_waf": cdn_waf_info,
                    "response_body_path": body_rel_path,
                    "response_body_size": body_saved_size,
                    "request_method": request_method,
                    "request_headers": request_headers,
                    "response_headers": response_headers,
                    "source": "httpx",
                },
                "discovered_by": "httpx",
                "sources": ["httpx"],
            }

            return asset

        try:
            from app.job_control import register_process, unregister_process, check_job_status, kill_process_tree
            await check_job_status()

            stage_timeout = timeout or kwargs.get("timeout") or max(120, len(seed_domains) * 10)
            timed_out = False
            loop = asyncio.get_event_loop()

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

            async def read_stream():
                nonlocal hosts_processed, live_hosts
                assert process.stdout is not None
                while True:
                    await check_job_status()
                    line = await loop.run_in_executor(None, process.stdout.readline)
                    if not line:
                        break
                    parsed = parse_json_line(line)
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

                    yield {"type": "asset", "data": asset}
                    await asyncio.sleep(0)

            try:
                async for event in read_stream():
                    yield event
                    if (time.time() - start_ts) >= stage_timeout:
                        timed_out = True
                        break
            except asyncio.TimeoutError:
                timed_out = True
            finally:
                unregister_process(process)
                if timed_out or (time.time() - start_ts >= stage_timeout):
                    kill_process_tree(process, "httpx")
                    yield {
                        "type": "stage_timeout",
                        "stage": "http_probing",
                        "tool": "httpx",
                        "reason": f"httpx probe timeout ({stage_timeout}s) exceeded",
                    }
                    yield {"type": "log", "message": f"[-] HTTPX probe timeout ({stage_timeout}s) exceeded."}
                elif process.poll() is None:
                    process.terminate()
                    process.wait()

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
                if exit_code == 127:
                    from app.core.tools import invalidate_tool_cache
                    invalidate_tool_cache("httpx")
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

        hosts_in = len(hosts)
        hosts_live = live_hosts
        hosts_dead = hosts_in - hosts_live

        if hosts_dead > 0:
            dead_log = f"[*] {hosts_dead} host(s) had open ports but returned no live HTTP response and will be excluded from crawling/URL discovery/vulnerability scanning."
            logger.info(dead_log)
            yield {"type": "log", "message": dead_log}

        yield {
            "type": "scan_summary",
            "provider": self.name,
            "hosts_processed": hosts_processed,
            "live_hosts": live_hosts,
            "duration_seconds": duration_s,
            "hosts_in": hosts_in,
            "hosts_live": hosts_live,
            "hosts_dead": hosts_dead,
        }

        if hosts_live == 0:
            yield {
                "type": "scan_summary",
                "event": "PipelineHalted",
                "reason": "no_live_hosts",
                "message": "No live HTTP hosts were found. Katana, GAU, SubJS, LinkFinder, GoWitness, GF, and Nuclei were all skipped because there is nothing for them to scan."
            }

    @staticmethod
    def _sanitize_header_items(raw: Any) -> List[str]:
        """Normalises request/response headers and redacts sensitive values."""
        items: List[str] = []
        if isinstance(raw, dict):
            raw = [f"{k}: {v}" for k, v in raw.items()]
        elif isinstance(raw, str):
            raw = [raw]
        if not isinstance(raw, list):
            return items
        for entry in raw[:60]:
            text = str(entry or "").strip()
            if not text:
                continue
            if ":" in text:
                header_key, header_val = text.split(":", 1)
                if header_key.strip().lower() in SENSITIVE_HEADER_KEYS:
                    items.append(f"{header_key.strip()}: [REDACTED]")
                    continue
            items.append(redact_text(text)[:500])
        return items

    @staticmethod
    def parse_httpx_json_line(line: str) -> Optional[Tuple[str, int]]:
        """Parses a single line of httpx -json output and returns (url, status_code)."""
        if not line or not line.strip():
            return None
        try:
            data = json.loads(line.strip())
            if not isinstance(data, dict):
                return None
            u = data.get("url") or data.get("input")
            if not u:
                return None
            sc = data.get("status_code")
            if sc is None:
                sc = data.get("status-code")
            if sc is None:
                sc = data.get("status")
            sc_int = int(sc) if sc is not None else 200
            return u.strip(), sc_int
        except Exception:
            return None

    @classmethod
    def build_historical_probe_cmd(
        cls,
        tool_path: str,
        wsl_in: str,
        rate_limit: int = 20,
        custom_headers: Optional[Dict[str, str]] = None,
        timeout: int = 8,
        is_windows: bool = False,
    ) -> List[str]:
        """
        Builds the httpx command for probing historical URLs:
          -mc 200,301,302,401,403
          -rl <rate_limit>
          -H <header>
          -timeout <timeout>
          -json -silent
        """
        cmd: List[str] = ["wsl", "-e"] if is_windows else []
        cmd.extend([
            tool_path,
            "-l", wsl_in,
            "-mc", "200,301,302,401,403",
            "-json",
            "-silent",
            "-timeout", str(timeout),
            "-rl", str(rate_limit),
        ])
        if custom_headers:
            for hk, hv in custom_headers.items():
                if hk and hv:
                    cmd.extend(["-H", f"{hk}: {hv}"])
        return cmd

    async def probe_historical_urls(
        self,
        urls: List[str],
        live_hosts: Optional[Any] = None,
        rate_limit: int = 20,
        custom_headers: Optional[Dict[str, str]] = None,
        timeout: int = 120,
        per_url_timeout: int = 8,
    ) -> AsyncGenerator[Dict[str, Any], None]:
        """
        Probes historical URLs (from GAU / Waymore) using httpx with -mc 200,301,302,401,403.
        (a) probe only URLs whose host is in the live-host set from the httpx stage; mark the others "unprobed" with reason "host not live";
        (b) a batch timeout affects only that batch: mark it unprobed and CONTINUE with the remaining batches;
        (c) scale the batch timeout with batch size and the per-URL timeout;
        (d) report the final live/dead/unprobed counts and the reason for unprobed ones.
        """
        import math
        from app.job_control import register_process, unregister_process, check_job_status

        if not urls:
            yield {
                "type": "scan_summary",
                "provider": "httpx_historical_probe",
                "status": "SKIPPED",
                "count": 0,
            }
            return

        is_windows = platform.system().lower() == "windows"
        try:
            tool_path = self.detect_tool("httpx")
        except ValueError as err:
            logger.warning("[httpx] Tool detection failed for historical probe: %s", err)
            yield {
                "type": "stage_skipped",
                "stage": "Historical URL Probing (httpx)",
                "tool": "httpx",
                "reason": f"tool_missing: {err}",
            }
            return

        clean_urls = list(dict.fromkeys(u.strip() for u in urls if u and u.strip()))

        confirmed_live: Dict[str, int] = {}
        probed_dead: List[str] = []
        unprobed: List[tuple[str, str]] = []

        # (a) Partition into probeable vs unprobed by live_hosts
        urls_to_probe: List[str] = []
        if live_hosts is not None:
            # Compare bare hostnames only (scheme, path and port removed) so a
            # live entry such as "https://host:8443/" still matches its URLs.
            live_host_set = {
                str(h).strip().lower().split("://")[-1].split("/")[0].split(":")[0]
                for h in live_hosts if h
            }
            for u in clean_urls:
                parsed = urlparse(u)
                h = (parsed.netloc or parsed.path.split("/")[0]).split(":")[0].lower()
                if h in live_host_set:
                    urls_to_probe.append(u)
                else:
                    unprobed.append((u, "host not live"))
        else:
            urls_to_probe = list(clean_urls)

        # Proportional timeout capped at 10 minutes (600s)
        total_timeout = min(600, max(timeout, int(len(urls_to_probe) * 1.5)))

        yield {
            "type": "log",
            "message": f"\n========== Probing Historical URLs (HTTPX) ==========\n"
                       f"[*] Probing {len(urls_to_probe)} historical URLs for live status (200,301,302,401,403) "
                       f"({len(unprobed)} skipped: host not live) in batches of 50 (Global timeout: {total_timeout}s)...",
        }

        batch_size = 50
        start_ts = time.time()

        for i in range(0, len(urls_to_probe), batch_size):
            elapsed = time.time() - start_ts
            remaining_global = total_timeout - elapsed
            if remaining_global <= 0:
                # Remaining URLs were never reached due to global timeout
                for rem_u in urls_to_probe[i:]:
                    unprobed.append((rem_u, "global timeout"))
                break

            batch = urls_to_probe[i:i + batch_size]
            # (c) Scale the batch timeout with batch size and the per-URL timeout
            effective_concurrency = max(1, min(rate_limit, 10))
            scaled_batch_timeout = int(math.ceil(len(batch) / effective_concurrency) * per_url_timeout) + 10
            batch_timeout = max(15, min(int(remaining_global), scaled_batch_timeout))

            temp_in = tempfile.NamedTemporaryFile(mode="w+", delete=False, suffix=".txt", encoding="utf-8")
            for u in batch:
                temp_in.write(f"{u}\n")
            temp_in.close()
            wsl_in = self.wsl_path_convert(temp_in.name) if is_windows else temp_in.name

            cmd = self.build_historical_probe_cmd(
                tool_path=tool_path,
                wsl_in=wsl_in,
                rate_limit=rate_limit,
                custom_headers=custom_headers,
                timeout=per_url_timeout,
                is_windows=is_windows,
            )

            if i == 0:
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

            batch_confirmed = {}
            batch_timed_out = False
            try:
                loop = asyncio.get_event_loop()
                await asyncio.wait_for(loop.run_in_executor(None, proc.wait), timeout=batch_timeout)

                if proc.stdout:
                    for line in proc.stdout:
                        parsed = self.parse_httpx_json_line(line)
                        if parsed:
                            u_res, sc_res = parsed
                            batch_confirmed[u_res] = sc_res
                            confirmed_live[u_res] = sc_res

                # Batch finished cleanly
                for u in batch:
                    if u not in batch_confirmed:
                        probed_dead.append(u)

            except asyncio.TimeoutError:
                batch_timed_out = True
                from app.job_control import kill_process_tree
                kill_process_tree(proc, "httpx")
                yield {
                    "type": "stage_timeout",
                    "stage": "Historical URL Probing (httpx)",
                    "tool": "httpx",
                    "reason": f"httpx historical probe batch timeout ({batch_timeout}s) exceeded",
                }
                yield {"type": "log", "message": f"[-] Historical URL probing timed out during batch {i // batch_size + 1}."}
                # Keep partial output: read lines from proc.stdout
                try:
                    if proc.stdout:
                        for line in proc.stdout:
                            parsed = self.parse_httpx_json_line(line)
                            if parsed:
                                u_res, sc_res = parsed
                                batch_confirmed[u_res] = sc_res
                                confirmed_live[u_res] = sc_res
                except Exception:
                    pass
                # (b) A batch timeout affects only that batch: mark it unprobed and CONTINUE with remaining batches
                for u in batch:
                    if u in batch_confirmed:
                        confirmed_live[u] = batch_confirmed[u]
                    else:
                        unprobed.append((u, "batch timeout"))
            finally:
                unregister_process(proc)
                try:
                    if os.path.exists(temp_in.name):
                        os.unlink(temp_in.name)
                except Exception:
                    pass

        # Emit live events
        for live_u, sc in confirmed_live.items():
            yield {
                "type": "historical_probe_event",
                "data": {
                    "url": live_u,
                    "status": "live",
                    "status_code": sc,
                },
            }

        # Emit dead assets and events (Type: historical_dead, status: dead)
        for dead_u in probed_dead:
            parsed = urlparse(dead_u)
            h = parsed.netloc.lower() or parsed.path.split("/")[0].lower()
            if ":" in h:
                h = h.split(":")[0]

            yield {
                "type": "asset",
                "data": {
                    "domain": h,
                    "type": "historical_dead",
                    "value": dead_u,
                    "status": "dead",
                    "metadata": {
                        "url": dead_u,
                        "host": h,
                        "status": "dead",
                        "source": "historical_archive",
                        "probed_with": "httpx",
                    },
                    "discovered_by": "httpx_historical_probe",
                    "sources": ["gau", "waymore"],
                },
            }
            yield {
                "type": "historical_probe_event",
                "data": {
                    "url": dead_u,
                    "status": "historical_dead",
                },
            }

        # Emit unprobed assets and events (Type: unprobed_url, status: unprobed)
        unprobed_reasons: Dict[str, int] = {}
        for unprobed_u, reason in unprobed:
            unprobed_reasons[reason] = unprobed_reasons.get(reason, 0) + 1
            parsed = urlparse(unprobed_u)
            h = parsed.netloc.lower() or parsed.path.split("/")[0].lower()
            if ":" in h:
                h = h.split(":")[0]

            yield {
                "type": "asset",
                "data": {
                    "domain": h,
                    "type": "unprobed_url",
                    "value": unprobed_u,
                    "status": "unprobed",
                    "metadata": {
                        "url": unprobed_u,
                        "host": h,
                        "status": "unprobed",
                        "source": "historical_archive",
                        "reason": reason,
                    },
                    "discovered_by": "httpx_historical_probe",
                    "sources": ["gau", "waymore"],
                },
            }
            yield {
                "type": "historical_probe_event",
                "data": {
                    "url": unprobed_u,
                    "status": "unprobed",
                    "reason": reason,
                },
            }

        # (d) Report final live/dead/unprobed counts and the reason for unprobed ones
        reason_summary = ", ".join(f"{r}: {c}" for r, c in unprobed_reasons.items()) if unprobed_reasons else "none"
        complete_msg = (
            f"[√] Historical probing complete: {len(confirmed_live)} live | {len(probed_dead)} dead | "
            f"{len(unprobed)} unprobed (reasons: {reason_summary})."
        )
        yield {
            "type": "log",
            "message": complete_msg,
        }
        yield {
            "type": "scan_summary",
            "provider": "httpx_historical_probe",
            "status": "completed",
            "total_urls": len(clean_urls),
            "probed_count": len(urls_to_probe),
            "live_count": len(confirmed_live),
            "dead_count": len(probed_dead),
            "unprobed_count": len(unprobed),
            "unprobed_reasons": unprobed_reasons,
        }

