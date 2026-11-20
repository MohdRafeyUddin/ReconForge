"""Parameter Discovery Provider (Arjun / x8)
===========================================
Executes parameter discovery on top-priority endpoints:
  - Deep mode only.
  - Probes top-priority endpoints (API endpoints, endpoints with parameters, forms).
  - Rate limits applied per tool flags.
  - Merges discovered parameters into URLs as `param_discovery` source.
  - Emits asset documents of type `param`.
  - Tool gating with tool_missing detection.
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
from urllib.parse import urlparse

from app.core.scope import is_in_scope
from app.providers.base import BaseProvider

logger = logging.getLogger("reconforge.providers.param_discovery")


class ParamDiscoveryProvider(BaseProvider):
    @property
    def name(self) -> str:
        return "arjun"

    @property
    def description(self) -> str:
        return "Discovers hidden GET and POST parameters on priority web endpoints."

    @classmethod
    def build_arjun_cmd(
        cls,
        tool_path: str,
        url: str,
        wsl_out: str,
        rate_limit: int = 10,
        custom_headers: Optional[Dict[str, str]] = None,
        timeout: int = 15,
        wordlist: Optional[str] = "small",
        is_windows: bool = False,
    ) -> List[str]:
        """
        Builds the Arjun command using verified CLI flags:
          --rate-limit <rate_limit>
          --headers <newline-separated headers>
          -T <timeout>
          -t <threads>
          -u <url>
          -oJ <wsl_out>
          -m GET
          -w <wordlist> (default: small to avoid massive 25k wordlist timeouts)
        """
        cmd: List[str] = ["wsl", "-e"] if is_windows else []
        threads = str(min(rate_limit, 5))
        cmd.extend([
            tool_path,
            "-u", url,
            "-oJ", wsl_out,
            "-t", threads,
            "--rate-limit", str(rate_limit),
            "-T", str(timeout),
            "-m", "GET",
        ])
        if wordlist:
            cmd.extend(["-w", wordlist])
        if custom_headers:
            headers_val = "\n".join(f"{k}: {v}" for k, v in custom_headers.items() if k and v)
            if headers_val:
                cmd.extend(["--headers", headers_val])
        return cmd

    @classmethod
    def build_x8_cmd(
        cls,
        tool_path: str,
        url: str,
        wsl_out: str,
        rate_limit: int = 10,
        custom_headers: Optional[Dict[str, str]] = None,
        timeout: int = 15,
        is_windows: bool = False,
    ) -> List[str]:
        """
        Builds the x8 command using real CLI flags:
          -d <delay_ms> calculated from rate limit
          -H <header>
          -u <url>
          -o <wsl_out> -O json
          --timeout <timeout>
          -W 1 -c 1
        """
        delay_ms = max(1, int(1000 / max(rate_limit, 1)))
        cmd: List[str] = ["wsl", "-e"] if is_windows else []
        cmd.extend([
            tool_path,
            "-u", url,
            "-o", wsl_out,
            "-O", "json",
            "-d", str(delay_ms),
            "-W", "1",
            "-c", "1",
            "--timeout", str(timeout),
        ])
        if custom_headers:
            for k, v in custom_headers.items():
                if k and v:
                    cmd.extend(["-H", f"{k}: {v}"])
        return cmd

    async def discover(self, seed_domains: List[str], **kwargs: Any) -> AsyncGenerator[Dict[str, Any], None]:
        async for item in self.discover_parameters(seed_domains, **kwargs):
            yield item

    async def discover_parameters(
        self,
        endpoints: List[str],
        rate_limit: int = 10,
        custom_headers: Optional[Dict[str, str]] = None,
        scope: Optional[Dict[str, List[str]]] = None,
        max_endpoints_to_probe: int = 25,
        per_host_timeout: int = 60,
        **kwargs: Any,
    ) -> AsyncGenerator[Dict[str, Any], None]:
        """
        Executes Arjun or x8 parameter discovery on priority endpoints.
        Yields logs, param_event events, url_events, and Asset documents.
        """
        if not endpoints:
            yield {
                "type": "scan_summary",
                "provider": self.name,
                "status": "SKIPPED",
                "count": 0,
                "reason": "no_priority_endpoints",
            }
            return

        is_windows = platform.system().lower() == "windows"
        
        # Check tool availability (arjun preferred, x8 as fallback)
        tool_name = "arjun"
        tool_path = None
        try:
            tool_path = self.detect_tool("arjun")
        except ValueError:
            pass
        if not tool_path:
            try:
                tool_path = self.detect_tool("x8")
                tool_name = "x8"
            except ValueError:
                pass

        if not tool_path:
            yield {
                "type": "stage_skipped",
                "stage": "Parameter Discovery (arjun)",
                "tool": "arjun",
                "reason": "tool_missing: arjun",
            }
            yield {
                "type": "log",
                "message": "[!] Tool 'arjun' is not installed in WSL. Skipping parameter discovery.",
            }
            yield {
                "type": "scan_summary",
                "provider": self.name,
                "status": "SKIPPED",
                "count": 0,
            }
            return

        # Cap the number of top-priority endpoints probed to respect rate caps
        targets = endpoints[:max_endpoints_to_probe]
        total_params_found = 0
        start_ts = time.time()

        consecutive_failures = 0
        successful_endpoints: List[str] = []
        failed_endpoints: List[str] = []
        untested_endpoints: List[str] = []

        yield {
            "type": "log",
            "message": f"\n========== Parameter Discovery ({tool_name.upper()}) ==========\n"
                       f"[*] Probing {len(targets)} priority endpoints for hidden parameters (Rate limit: {rate_limit})...",
        }

        for idx, url in enumerate(targets):
            url = url.strip()
            if not url or not is_in_scope(url, scope):
                continue

            parsed = urlparse(url)
            host = parsed.netloc.lower() or "unknown"
            if ":" in host:
                host = host.split(":")[0]

            out_tmp = tempfile.NamedTemporaryFile(suffix=".json", delete=False)
            out_tmp.close()
            wsl_out = self.wsl_path_convert(out_tmp.name) if is_windows else out_tmp.name

            # Build command using verified builders
            if tool_name == "arjun":
                cmd = self.build_arjun_cmd(
                    tool_path=tool_path,
                    url=url,
                    wsl_out=wsl_out,
                    rate_limit=rate_limit,
                    custom_headers=custom_headers,
                    wordlist=kwargs.get("wordlist", "small"),
                    is_windows=is_windows,
                )
            else:
                cmd = self.build_x8_cmd(
                    tool_path=tool_path,
                    url=url,
                    wsl_out=wsl_out,
                    rate_limit=rate_limit,
                    custom_headers=custom_headers,
                    is_windows=is_windows,
                )

            yield {"type": "log", "message": self.format_cmd_log(cmd)}

            from app.job_control import register_process, unregister_process, check_job_status
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

            timed_out = False
            try:
                loop = asyncio.get_event_loop()
                await asyncio.wait_for(loop.run_in_executor(None, proc.wait), timeout=per_host_timeout)
            except asyncio.TimeoutError:
                timed_out = True
                proc.kill()
                consecutive_failures += 1
                failed_endpoints.append(url)
                yield {
                    "type": "stage_timeout",
                    "stage": "param_discovery",
                    "tool": tool_name,
                    "reason": f"parameter discovery timeout ({per_host_timeout}s) exceeded on {url}",
                }
                yield {"type": "log", "message": f"[-] Parameter discovery timed out ({per_host_timeout}s) on {url}."}
            finally:
                unregister_process(proc)

            # Check circuit breaker on timeout
            if timed_out:
                try:
                    if os.path.exists(out_tmp.name):
                        os.unlink(out_tmp.name)
                except Exception:
                    pass

                if consecutive_failures >= 3:
                    untested_endpoints = [t.strip() for t in targets[idx + 1:] if t and t.strip()]
                    circuit_msg = (
                        f"[-] Circuit breaker triggered: {consecutive_failures} consecutive failures/timeouts in parameter discovery. "
                        f"Stopping phase. Untested endpoints ({len(untested_endpoints)}): {', '.join(untested_endpoints[:5])}"
                        f"{'...' if len(untested_endpoints) > 5 else ''}"
                    )
                    logger.error(circuit_msg)
                    yield {
                        "type": "stage_error",
                        "stage": "param_discovery",
                        "tool": tool_name,
                        "error": "Circuit breaker triggered: 3 consecutive failures/timeouts",
                        "reason": "circuit_breaker: 3 consecutive failures/timeouts",
                        "untested_endpoints": untested_endpoints,
                    }
                    yield {"type": "log", "message": circuit_msg}
                    break
                continue

            # Requirement 4: If tool exits non-zero (including 4294967295 / WSL errors),
            # discard stdout, emit stage_error, and never parse stdout of a failed process
            ret = getattr(proc, "returncode", None)
            if not isinstance(ret, int):
                if hasattr(proc, "poll") and callable(getattr(proc, "poll", None)):
                    try:
                        p_ret = proc.poll()
                        if isinstance(p_ret, int):
                            ret = p_ret
                    except Exception:
                        pass
            if not isinstance(ret, int) and hasattr(proc, "wait") and callable(getattr(proc, "wait", None)):
                try:
                    w_ret = proc.wait()
                    if isinstance(w_ret, int):
                        ret = w_ret
                except Exception:
                    pass
            if not isinstance(ret, int):
                ret = 0

            if ret != 0:
                consecutive_failures += 1
                failed_endpoints.append(url)
                err_msg = ""
                try:
                    if proc.stderr:
                        err_val = proc.stderr.read()
                        if isinstance(err_val, str):
                            err_msg = err_val
                        elif isinstance(err_val, bytes):
                            err_msg = err_val.decode("utf-8", "ignore")
                except Exception:
                    pass
                err_msg = err_msg.strip() or f"Process exited with code {ret}"
                err_snippet = err_msg[:500]
                logger.error(f"[param_discovery] Tool {tool_name} exited with non-zero code {ret} on {url}: {err_snippet}")
                yield {
                    "type": "stage_error",
                    "stage": "param_discovery",
                    "tool": tool_name,
                    "returncode": ret,
                    "error": f"Tool {tool_name} exited with code {ret}: {err_snippet}",
                    "reason": f"Tool {tool_name} exited with code {ret}: {err_snippet}",
                }
                yield {"type": "log", "message": f"[-] Stage error: {tool_name} exited with code {ret} on {url}: {err_snippet}"}
                try:
                    if os.path.exists(out_tmp.name):
                        os.unlink(out_tmp.name)
                except Exception:
                    pass

                # Circuit breaker check on exit code != 0
                if consecutive_failures >= 3:
                    untested_endpoints = [t.strip() for t in targets[idx + 1:] if t and t.strip()]
                    circuit_msg = (
                        f"[-] Circuit breaker triggered: {consecutive_failures} consecutive failures/timeouts in parameter discovery. "
                        f"Stopping phase. Untested endpoints ({len(untested_endpoints)}): {', '.join(untested_endpoints[:5])}"
                        f"{'...' if len(untested_endpoints) > 5 else ''}"
                    )
                    logger.error(circuit_msg)
                    yield {
                        "type": "stage_error",
                        "stage": "param_discovery",
                        "tool": tool_name,
                        "error": "Circuit breaker triggered: 3 consecutive failures/timeouts",
                        "reason": "circuit_breaker: 3 consecutive failures/timeouts",
                        "untested_endpoints": untested_endpoints,
                    }
                    yield {"type": "log", "message": circuit_msg}
                    break
                continue

            # Successful run on this endpoint
            consecutive_failures = 0
            successful_endpoints.append(url)

            # Parse results
            params_for_url: List[str] = []
            if os.path.exists(out_tmp.name) and os.path.getsize(out_tmp.name) > 0:
                try:
                    with open(out_tmp.name, "r", encoding="utf-8", errors="replace") as f:
                        data = json.load(f)

                    if isinstance(data, dict):
                        # Arjun format: {url: ["param1", "param2"]}
                        for u_key, plist in data.items():
                            if isinstance(plist, list):
                                params_for_url.extend([str(p).strip() for p in plist if str(p).strip()])
                    elif isinstance(data, list):
                        # x8 format: [{"param": "name"}] or ["param1"]
                        for item in data:
                            if isinstance(item, str):
                                params_for_url.append(item.strip())
                            elif isinstance(item, dict) and "param" in item:
                                params_for_url.append(str(item["param"]).strip())
                except Exception as parse_err:
                    logger.debug("[param_discovery] Error parsing output: %s", parse_err)

            try:
                if os.path.exists(out_tmp.name):
                    os.unlink(out_tmp.name)
            except Exception:
                pass

            params_for_url = list(dict.fromkeys(params_for_url))
            if params_for_url:
                total_params_found += len(params_for_url)
                yield {
                    "type": "log",
                    "message": f"[+] Discovered {len(params_for_url)} parameters on {url}: {', '.join(params_for_url)}",
                }

                for param in params_for_url:
                    # Parameterized URL for downstream vulnerability testing
                    delimiter = "&" if "?" in url else "?"
                    param_url = f"{url}{delimiter}{param}=FUZZ"

                    yield {
                        "type": "asset",
                        "data": {
                            "domain": host,
                            "type": "param",
                            "value": f"{url}?{param}",
                            "status": "live",
                            "metadata": {
                                "endpoint": url,
                                "param_name": param,
                                "parameterized_url": param_url,
                                "source": "param_discovery",
                            },
                            "discovered_by": tool_name,
                            "sources": ["param_discovery"],
                        },
                    }

                    yield {
                        "type": "param_event",
                        "data": {
                            "host": host,
                            "endpoint": url,
                            "param": param,
                            "url": param_url,
                        },
                    }

                    # Merge into URL pipeline as param_discovery source
                    yield {
                        "type": "url_event",
                        "data": {
                            "url": param_url,
                            "original_url": param_url,
                            "source": "param_discovery",
                            "sources": ["param_discovery"],
                        },
                    }

        duration = round(time.time() - start_ts, 2)
        yield {
            "type": "scan_summary",
            "provider": self.name,
            "status": "completed",
            "count": total_params_found,
            "targets_scanned": len(successful_endpoints),
            "endpoints_succeeded": len(successful_endpoints),
            "endpoints_failed": len(failed_endpoints),
            "endpoints_untested": len(untested_endpoints),
            "untested_endpoints": untested_endpoints,
            "duration_seconds": duration,
        }
        yield {
            "type": "log",
            "message": f"[√] Parameter discovery complete. Discovered: {total_params_found} params | Duration: {duration}s",
        }

