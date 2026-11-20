"""crtsh_provider.py
=================
Passive subdomain discovery using crt.sh Certificate Transparency JSON API.
"""

import asyncio
import logging
from typing import Any, AsyncGenerator, Dict, List, Set

import httpx
from app.core.scope import validate_hostname
from app.providers.base import BaseProvider

logger = logging.getLogger("reconforge.providers.crtsh")


class CrtshProvider(BaseProvider):
    @property
    def name(self) -> str:
        return "crt.sh"

    @property
    def description(self) -> str:
        return "Passive Certificate Transparency log search via crt.sh JSON endpoint."

    async def discover(self, seed_domains: List[str]) -> AsyncGenerator[Dict[str, Any], None]:
        yield {"type": "log", "message": f"[*] Starting crt.sh certificate enumeration for {len(seed_domains)} domain(s)..."}

        discovered_count = 0
        seen_hosts: Set[str] = set()

        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) ReconForge/1.0",
            "Accept": "application/json",
        }

        async with httpx.AsyncClient(timeout=25.0, headers=headers, follow_redirects=True) as client:
            for domain in seed_domains:
                clean_domain = domain.strip().lower()
                if not clean_domain:
                    continue

                url = f"https://crt.sh/?q=%.{clean_domain}&output=json"
                yield {"type": "log", "message": f"[*] crt.sh: querying {clean_domain}..."}

                data = None
                last_status = None
                last_error = None
                domain_found = 0

                for attempt in range(1, 4):
                    try:
                        resp = await client.get(url)
                        last_status = resp.status_code
                        yield {"type": "log", "message": f"[*] crt.sh returned HTTP {resp.status_code} for {clean_domain} (attempt {attempt}/3)"}

                        if resp.status_code == 200:
                            try:
                                data = resp.json()
                            except Exception as json_err:
                                data = []
                            break
                        elif resp.status_code in (500, 502, 503, 504):
                            if attempt < 3:
                                backoff = 2 ** (attempt - 1)
                                yield {"type": "log", "message": f"[!] crt.sh returned HTTP {resp.status_code} (attempt {attempt}/3), retrying in {backoff}s..."}
                                await asyncio.sleep(backoff)
                        else:
                            # 4xx or unexpected non-5xx
                            break
                    except Exception as exc:
                        last_error = exc
                        if attempt < 3:
                            backoff = 2 ** (attempt - 1)
                            yield {"type": "log", "message": f"[!] crt.sh connection/timeout on attempt {attempt}/3: {exc}. Retrying in {backoff}s..."}
                            await asyncio.sleep(backoff)
                        else:
                            logger.warning(f"crt.sh request failed for {clean_domain}: {exc}")

                # Report "request failed (status N)" separately from "0 results"
                if data is None:
                    if last_status is not None and last_status != 200:
                        yield {
                            "type": "stage_error",
                            "stage": "crtsh",
                            "tool": "crtsh",
                            "error": f"request failed (status {last_status})",
                            "reason": f"request failed (status {last_status})",
                        }
                        yield {"type": "log", "message": f"[-] crt.sh request failed (status {last_status}) for {clean_domain}"}
                    elif last_error is not None:
                        yield {
                            "type": "stage_error",
                            "stage": "crtsh",
                            "tool": "crtsh",
                            "error": "request failed (timeout/connection error)",
                            "reason": str(last_error),
                        }
                        yield {"type": "log", "message": f"[-] crt.sh request failed (timeout/connection error) for {clean_domain}: {last_error}"}
                    continue

                if not isinstance(data, list):
                    continue

                for entry in data:
                    name_value = entry.get("name_value") or entry.get("common_name") or ""
                    # Split multiple SANs on newline
                    for raw_name in str(name_value).splitlines():
                        candidate = raw_name.strip().lower()
                        if candidate.startswith("*."):
                            candidate = candidate[2:]
                        if not candidate or candidate in seen_hosts:
                            continue

                        # Strict RFC hostname validation
                        is_valid, _ = validate_hostname(candidate)
                        if not is_valid:
                            continue

                        seen_hosts.add(candidate)
                        discovered_count += 1
                        domain_found += 1
                        yield {
                            "type": "asset",
                            "data": {
                                "domain": candidate,
                                "type": "subdomain",
                                "status": "unknown",
                                "open_ports": [],
                                "metadata": {"source": "crtsh"},
                                "discovered_by": "crtsh",
                                "sources": ["crtsh"],
                            },
                        }

                if domain_found == 0:
                    yield {"type": "log", "message": f"[*] crt.sh returned 0 results for {clean_domain}."}

        yield {
            "type": "scan_summary",
            "provider": "crtsh",
            "status": "completed",
            "count": discovered_count,
        }

        if discovered_count == 0:
            yield {
                "type": "warning_event",
                "stage": "crtsh",
                "tool": "crtsh",
                "message": "[!] Tool 'crtsh' returned 0 results, possible timeout/rate-limit",
            }

        yield {"type": "log", "message": f"[√] crt.sh completed → {discovered_count} subdomains"}
