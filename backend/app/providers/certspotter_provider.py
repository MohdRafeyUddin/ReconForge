"""certspotter_provider.py
========================
Passive subdomain discovery using Cert Spotter Certificate Transparency API.
"""

import asyncio
import logging
from typing import Any, AsyncGenerator, Dict, List, Set

import httpx
from app.core.scope import validate_hostname
from app.providers.base import BaseProvider

logger = logging.getLogger("reconforge.providers.certspotter")


class CertspotterProvider(BaseProvider):
    @property
    def name(self) -> str:
        return "CertSpotter"

    @property
    def description(self) -> str:
        return "Passive Certificate Transparency monitor via CertSpotter free endpoint."

    async def discover(self, seed_domains: List[str]) -> AsyncGenerator[Dict[str, Any], None]:
        yield {"type": "log", "message": f"[*] Starting CertSpotter certificate enumeration for {len(seed_domains)} domain(s)..."}

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

                url = f"https://api.certspotter.com/v1/issuances?domain={clean_domain}&include_subdomains=true&expand=dns_names"
                yield {"type": "log", "message": f"[*] CertSpotter: querying {clean_domain}..."}

                data = None
                try:
                    resp = await client.get(url)
                    if resp.status_code == 200:
                        data = resp.json()
                    elif resp.status_code == 429:
                        yield {"type": "log", "message": f"[!] CertSpotter rate limit hit (HTTP 429) for {clean_domain}"}
                    else:
                        yield {"type": "log", "message": f"[!] CertSpotter returned HTTP {resp.status_code} for {clean_domain}"}
                except Exception as exc:
                    logger.warning(f"CertSpotter request failed for {clean_domain}: {exc}")
                    yield {"type": "log", "message": f"[-] CertSpotter connection failed for {clean_domain}: {exc}"}

                if not data or not isinstance(data, list):
                    continue

                for entry in data:
                    dns_names = entry.get("dns_names") or []
                    for raw_name in dns_names:
                        candidate = str(raw_name).strip().lower()
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
                        yield {
                            "type": "asset",
                            "data": {
                                "domain": candidate,
                                "type": "subdomain",
                                "status": "unknown",
                                "open_ports": [],
                                "metadata": {"source": "certspotter"},
                                "discovered_by": "certspotter",
                                "sources": ["certspotter"],
                            },
                        }

        yield {
            "type": "scan_summary",
            "provider": "certspotter",
            "status": "completed",
            "count": discovered_count,
        }

        if discovered_count == 0:
            yield {
                "type": "warning_event",
                "stage": "certspotter",
                "tool": "certspotter",
                "message": "[!] Tool 'certspotter' returned 0 results, possible rate-limit",
            }

        yield {"type": "log", "message": f"[√] CertSpotter completed → {discovered_count} subdomains"}


CertSpotterProvider = CertspotterProvider
