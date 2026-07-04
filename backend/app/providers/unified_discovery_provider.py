"""
UnifiedDiscoveryProvider
========================
Orchestrates the full Attack Surface Management pipeline.

Execution order
---------------
Phase 1 – Passive Discovery (concurrent)
    Subfinder | Assetfinder | Chaos | Amass (passive)
    ↓
    Merge → Deduplicate

Phase 2 – DNS Resolution
    DNSx  (A / AAAA / CNAME, wildcard filtering, NXDOMAIN filtering)
    ↓
    Resolved subdomains

Phase 3 – Subdomain Takeover
    Subzy

Phase 4 – Port Scanning
    Naabu (LIVE hosts)

Phase 5 – HTTP Probing
    HTTPX

Phase 6 – Web Crawling
    Katana

Phase 7 – URL Deduplication
    Uro

Phase 8 – URL Classification
    GF

Phase 9 – Vulnerability Scanning
    Nuclei

Design goals
------------
- Provider failures are isolated; one crash does not stop the scan.
- Every provider yields events in the standard ReconForge format:
      {"type": "log",          "message": str}
      {"type": "asset",        "data": {...}}
      {"type": "scan_summary", "provider": str, ...}
      {"type": "url_event",    "data": {...}}
      {"type": "gf_event",     "data": {...}}
- New providers can be plugged in by adding a phase call without touching
  the rest of the pipeline (see "_run_phase" helper).
- No external state is mutated; all stage results flow as local variables.
"""

import asyncio
import logging
import re
from collections import defaultdict
from typing import Any, AsyncGenerator, Dict, List

from app.providers.base import BaseProvider
from app.providers.subfinder_provider import SubfinderProvider
from app.providers.assetfinder_provider import AssetfinderProvider
from app.providers.amass_provider import AmassProvider
from app.providers.chaos_provider import ChaosProvider
from app.providers.dnsx_provider import DnsxProvider
from app.providers.subzy_provider import SubzyProvider
from app.providers.naabu_provider import NaabuProvider
from app.providers.httpx_provider import HttpxProvider
from app.providers.katana_provider import KatanaProvider
from app.providers.uro_provider import UroProvider
from app.providers.gf_provider import GfProvider
from app.providers.nuclei_provider import NucleiProvider
from app.providers.gau_provider import GauProvider
from app.providers.subjs_provider import SubjsProvider
from app.providers.linkfinder_provider import LinkfinderProvider
from app.providers.gowitness_provider import GowitnessProvider
from app.providers.dalfox_provider import DalfoxProvider
from app.providers.openredirex_provider import OpenredirexProvider
from app.providers.url_merge import merge_urls

logger = logging.getLogger("reconforge.providers.unified")


# ---------------------------------------------------------------------------
# Hostname utilities (unchanged from previous implementation)
# ---------------------------------------------------------------------------

_VALID_HOSTNAME_RE = re.compile(
    r"^(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$"
)


def _normalise(domain: str) -> str:
    """Lowercase, strip whitespace, drop leading '*.' wildcard prefixes."""
    domain = domain.strip().lower()
    while domain.startswith("*."):
        domain = domain[2:]
    return domain


def _is_valid(domain: str) -> bool:
    # Also permit localhost, local IP/host structures, URLs, and port mappings as valid
    domain_lower = domain.lower()
    if (
        "localhost" in domain_lower
        or "127.0.0.1" in domain_lower
        or ":" in domain_lower
        or domain_lower.startswith(("http://", "https://"))
    ):
        return True
    return bool(domain and _VALID_HOSTNAME_RE.match(domain))


def detect_target_type(input_str: str) -> str:
    import re
    input_str = input_str.strip()
    
    # 1. URL
    if input_str.lower().startswith(("http://", "https://")):
        return "URL"
        
    # 2. IP Address
    ip_pattern = r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$"
    if re.match(ip_pattern, input_str):
        return "IP"
        
    # 3. Hostname with Port
    host_port_pattern = r"^[^/:]+:[0-9]+$"
    if re.match(host_port_pattern, input_str):
        return "HOST_PORT"
        
    # 4. DOMAIN
    return "DOMAIN"


# ---------------------------------------------------------------------------
# UnifiedDiscoveryProvider
# ---------------------------------------------------------------------------

class UnifiedDiscoveryProvider(BaseProvider):
    """
    Orchestrates all ReconForge pipeline stages.

    Adding a future provider
    ------------------------
    1.  Import the provider class at the top of this file.
    2.  Call ``yield from self._run_phase(...)`` at the appropriate position
        inside ``discover()``.
    3.  No other changes are required.
    """

    # Phase 1 passive sub-providers (run concurrently)
    PASSIVE_PROVIDERS = [
        (SubfinderProvider(),   "subfinder"),
        (AssetfinderProvider(), "assetfinder"),
        (ChaosProvider(),       "chaos"),
        (AmassProvider(),       "amass"),
    ]

    @property
    def name(self) -> str:
        return "Unified Discovery"

    @property
    def description(self) -> str:
        return (
            "Full ASM pipeline: Passive Discovery → DNSx → Subzy → Naabu → "
            "HTTPX → Katana → Uro → GF → Nuclei."
        )

    # ------------------------------------------------------------------
    # Generic phase runner — makes future extensions trivial
    # ------------------------------------------------------------------

    async def _run_phase(
        self,
        provider: BaseProvider,
        targets: List[str],
        phase_label: str,
    ) -> AsyncGenerator[Dict[str, Any], None]:
        """
        Run a single pipeline phase, yielding all its events upstream.
        Isolates exceptions so a phase failure is non-fatal.

        Yields every event from the provider plus a phase-boundary log.
        Returns an async generator — callers must ``async for`` over it.
        """
        from app.job_control import check_job_status
        await check_job_status()

        phase_start_msg = f"\n{'='*10} {phase_label} {'='*10}"
        logger.info(phase_start_msg)
        yield {"type": "log", "message": phase_start_msg}

        try:
            async for event in provider.discover(targets):
                yield event
        except Exception as exc:
            err_msg = f"[-] {phase_label} failed: {exc}"
            logger.error(err_msg)
            yield {"type": "log", "message": f"{err_msg} (non-fatal — continuing pipeline)"}

    # ------------------------------------------------------------------
    # Main orchestration
    # ------------------------------------------------------------------

    async def discover(
        self, seed_domains: List[str], scan_mode: str = "fast"
    ) -> AsyncGenerator[Dict[str, Any], None]:

        # Target Detection
        seed = seed_domains[0] if seed_domains else ""
        target_type = detect_target_type(seed)
        is_localhost = seed.strip().lower() == "localhost"
        is_new_path = target_type in ("URL", "IP", "HOST_PORT") or is_localhost

        yield {"type": "log", "message": f"Detected target type: {target_type}"}

        provider_counts: Dict[str, int] = {}
        total_unique = 0
        subzy_vulnerable = 0
        
        dnsx_resolved = 0
        dnsx_nxdomain = 0
        dnsx_wildcards = 0

        if is_new_path:
            yield {"type": "log", "message": "Skipping Passive Discovery"}
            yield {"type": "log", "message": "Skipping DNS Resolution"}
            yield {"type": "log", "message": "Skipping Subdomain Takeover Check (Subzy)"}
            
            # Emit skipped statuses for passive sub-providers so UI shows them as SKIPPED
            for p_name in ("subfinder", "assetfinder", "chaos", "amass"):
                yield {
                    "type": "scan_summary",
                    "provider": p_name,
                    "status": "SKIPPED"
                }
            yield {
                "type": "scan_summary",
                "provider": "Discovery",
                "status": "SKIPPED"
            }
            yield {
                "type": "scan_summary",
                "provider": "DNSx",
                "status": "SKIPPED"
            }
            yield {
                "type": "scan_summary",
                "provider": "Subzy",
                "status": "SKIPPED"
            }
            
            unique_resolved = [seed]
            
            if target_type == "IP" or is_localhost:
                yield {"type": "log", "message": "Starting from Naabu"}
            else:
                yield {"type": "log", "message": "Starting from HTTPX"}

        else:
            # ================================================================
            # PHASE 1: Concurrent passive discovery
            # ================================================================

            discovered_subdomains: List[str] = []
            event_queue: asyncio.Queue = asyncio.Queue()

            async def run_passive(provider: BaseProvider, label: str) -> None:
                logger.info("[*] Launching passive provider: %s", label)
                count = 0
                try:
                    async for event in provider.discover(seed_domains):
                        if event.get("type") == "asset":
                            raw = event["data"].get("domain", "")
                            norm = _normalise(raw)
                            if _is_valid(norm):
                                await event_queue.put(("asset", norm, label))
                                discovered_subdomains.append(norm)
                                count += 1
                except Exception as exc:
                    err = f"[-] {label} failed: {exc}"
                    logger.error(err)
                    await event_queue.put(("provider_error", label, str(exc)))
                finally:
                    provider_counts[label] = count
                    logger.info("[+] %s finished → %s raw subdomains", label, count)
                    await event_queue.put(("provider_done", label, count))

            tasks = [
                asyncio.create_task(run_passive(p, lbl))
                for p, lbl in self.PASSIVE_PROVIDERS
            ]
            remaining = len(tasks)

            while remaining > 0 or not event_queue.empty():
                try:
                    item = await asyncio.wait_for(event_queue.get(), timeout=0.2)
                except asyncio.TimeoutError:
                    remaining = sum(1 for t in tasks if not t.done())
                    continue

                kind = item[0]
                if kind == "asset":
                    _, domain, source = item
                    yield {
                        "type": "asset",
                        "data": {
                            "domain": domain,
                            "type": "subdomain",
                            "status": "unknown",
                            "open_ports": [],
                            "metadata": {"source": "unified_discovery"},
                            "discovered_by": "Unified Discovery",
                            "sources": [source],
                        },
                    }
                elif kind == "provider_done":
                    _, label, count = item
                    done_msg = f"[+] {label.capitalize()} completed → {count} subdomains"
                    logger.info(done_msg)
                    yield {
                        "type": "log",
                        "message": done_msg,
                        "provider_stat": {"provider": label, "count": count},
                    }
                    yield {
                        "type": "scan_summary",
                        "provider": label.lower(),
                        "status": "completed",
                        "count": count
                    }
                    yield {"type": "log", "message": f"[√] Provider {label.lower()} completed"}
                    remaining = sum(1 for t in tasks if not t.done())
                elif kind == "provider_error":
                    _, label, error = item
                    yield {
                        "type": "log",
                        "message": f"[-] {label} encountered an error: {error}",
                    }

            await asyncio.gather(*tasks, return_exceptions=True)

            # Global deduplication after Phase 1
            unique_subdomains = sorted(set(discovered_subdomains))
            total_unique = len(unique_subdomains)

            phase1_summary = (
                f"\n[√] Passive Discovery complete.\n"
                f"    Subfinder   : {provider_counts.get('subfinder', 0)}\n"
                f"    Assetfinder : {provider_counts.get('assetfinder', 0)}\n"
                f"    Chaos       : {provider_counts.get('chaos', 0)}\n"
                f"    Amass       : {provider_counts.get('amass', 0)}\n"
                f"    ─────────────────────────\n"
                f"    Total Unique : {total_unique}"
            )
            logger.info(phase1_summary)
            yield {"type": "log", "message": phase1_summary}

            if not unique_subdomains:
                yield {"type": "log", "message": "[*] No subdomains discovered. Aborting pipeline."}
                yield {
                    "type": "scan_summary",
                    "provider_counts": provider_counts,
                    "total_unique": 0,
                    "live_hosts": 0,
                }
                return

            # ================================================================
            # PHASE 2: DNS Resolution (DNSx)
            # ================================================================

            resolved_subdomains: List[str] = []

            dnsx_provider = DnsxProvider()
            async for event in self._run_phase(dnsx_provider, unique_subdomains, "DNSx Resolution"):
                if event.get("type") == "asset":
                    asset = event.get("data", {})
                    if asset.get("status") in ("resolved", "live"):
                        domain_norm = _normalise(asset.get("domain", ""))
                        if _is_valid(domain_norm):
                            resolved_subdomains.append(domain_norm)
                elif event.get("type") == "scan_summary" and event.get("provider") == "DNSx":
                    dnsx_resolved   = event.get("resolved", 0)
                    dnsx_nxdomain   = event.get("nxdomain", 0)
                    dnsx_wildcards  = event.get("wildcards_filtered", 0)
                yield event

            yield {
                "type": "scan_summary",
                "provider": "dnsx",
                "status": "completed",
                "count": dnsx_resolved
            }
            yield {"type": "log", "message": "[√] Provider dnsx completed"}

            if not resolved_subdomains:
                # Fall back to all unique subdomains (DNSx may not be installed)
                logger.warning("[*] DNSx returned no resolved subdomains; using all unique subdomains.")
                yield {
                    "type": "log",
                    "message": (
                        "[*] DNSx returned no resolved results. "
                        "Falling back to full subdomain list for subsequent stages."
                    ),
                }
                resolved_subdomains = list(unique_subdomains)

            unique_resolved = sorted(set(resolved_subdomains))
            yield {
                "type": "log",
                "message": f"[√] DNSx: {len(unique_resolved)} resolved subdomains ready.",
            }

            # ================================================================
            # PHASE 3: Subdomain Takeover (Subzy)
            # ================================================================

            subzy_provider = SubzyProvider()
            async for event in self._run_phase(subzy_provider, unique_resolved, "Subzy Takeover Check"):
                if event.get("type") == "scan_summary" and event.get("provider") == "Subzy":
                    subzy_vulnerable = event.get("vulnerable", 0)
                yield event

            yield {
                "type": "scan_summary",
                "provider": "subzy",
                "status": "completed",
                "count": subzy_vulnerable
            }
            yield {"type": "log", "message": "[√] Provider subzy completed"}

        # ================================================================
        # PHASE 4: Port Scanning (Naabu)
        # ================================================================

        naabu_hosts_with_ports = 0
        naabu_open_ports = 0
        
        skip_naabu = is_new_path and target_type in ("URL", "HOST_PORT")

        if skip_naabu:
            yield {"type": "log", "message": "Skipping Port Scanning (Naabu)"}
            yield {
                "type": "scan_summary",
                "provider": "naabu",
                "status": "SKIPPED"
            }
            yield {"type": "log", "message": "[!] Provider naabu skipped"}
        else:
            naabu_provider = NaabuProvider()
            async for event in self._run_phase(naabu_provider, unique_resolved, "Naabu Port Scan"):
                if event.get("type") == "scan_summary":
                    naabu_hosts_with_ports = event.get("hosts_with_open_ports", 0)
                    naabu_open_ports       = event.get("open_ports", 0)
                yield event

            yield {
                "type": "scan_summary",
                "provider": "naabu",
                "status": "completed",
                "count": naabu_open_ports
            }
            yield {"type": "log", "message": "[√] Provider naabu completed"}

        # ================================================================
        # PHASE 5: HTTP Probing (HTTPX)
        # ================================================================

        live_hosts = 0
        live_host_targets: List[str] = []
        live_host_urls: List[str] = []
        host_to_live_url: Dict[str, str] = {}
        host_to_urls: Dict[str, List[str]] = defaultdict(list)

        target_label = "targets" if is_new_path else "resolved subdomains"
        httpx_start_msg = (
            f"\n========== HTTPX Probing ==========\n"
            f"[*] Launching HTTPX on {len(unique_resolved)} {target_label}..."
        )
        logger.info(httpx_start_msg)
        yield {"type": "log", "message": httpx_start_msg}

        from app.job_control import check_job_status
        await check_job_status()

        httpx_provider = HttpxProvider()
        try:
            async for event in httpx_provider.discover(unique_resolved):
                event_type = event.get("type")
                if event_type == "asset":
                    asset = event.get("data", {})
                    if asset.get("status") == "live":
                        live_hosts += 1
                        domain_norm = _normalise(asset.get("domain", ""))
                        live_host_targets.append(domain_norm)
                        url = asset.get("metadata", {}).get("url")
                        resolved_url = url if url else f"http://{asset.get('domain')}"
                        host_to_live_url[domain_norm] = resolved_url
                        live_host_urls.append(resolved_url)
                    yield event
                elif event_type in ("log", "scan_summary"):
                    yield event
        except Exception as exc:
            err_msg = f"[-] HTTPX probing failed: {exc}"
            logger.error(err_msg)
            yield {"type": "log", "message": f"{err_msg} (non-fatal — continuing pipeline)"}

        yield {
            "type": "scan_summary",
            "provider": "httpx",
            "status": "completed",
            "count": live_hosts
        }
        yield {"type": "log", "message": "[√] Provider httpx completed"}
        # PHASE 6: Concurrent crawling and discovery (Katana, GAU, SubJS, GoWitness)
        # ================================================================
        yield {"type": "log", "message": f"\n========== Crawling & Discovery ({scan_mode.upper()} MODE) =========="}

        all_katana_urls: List[str] = []
        all_gau_urls: List[str] = []
        all_js_files: List[str] = []
        
        katana_hosts_scanned = 0
        katana_urls_discovered = 0
        gowitness_screenshots = 0

        # Launch parallel tasks
        event_queue = asyncio.Queue()
        
        async def run_worker(provider, targets, label):
            try:
                async for event in provider.discover(targets):
                    await event_queue.put((label, event))
            except Exception as exc:
                logger.error(f"Concurrent worker {label} failed: {exc}", exc_info=True)
                await event_queue.put((label, {"type": "log", "message": f"[-] Worker {label} failed: {exc}"}))
            finally:
                await event_queue.put((label, "__done__"))

        # Setup targets
        unique_live_hosts = sorted({h for h in live_host_targets if _is_valid(h)})
        unique_live_urls = sorted(set(live_host_urls))

        tasks = []
        if unique_live_urls:
            tasks.append(asyncio.create_task(run_worker(KatanaProvider(), unique_live_urls, "katana")))
            tasks.append(asyncio.create_task(run_worker(GauProvider(), unique_live_hosts, "gau")))
            tasks.append(asyncio.create_task(run_worker(SubjsProvider(), unique_live_urls, "subjs")))
            if scan_mode == "deep":
                tasks.append(asyncio.create_task(run_worker(GowitnessProvider(), unique_live_urls, "gowitness")))
        else:
            yield {"type": "log", "message": "[*] No live HTTPX targets; skipping concurrent crawlers."}
            for p in ("katana", "gau", "subjs"):
                yield {"type": "scan_summary", "provider": p, "status": "SKIPPED"}
                yield {"type": "log", "message": f"[!] Provider {p} skipped"}
            if scan_mode == "deep":
                yield {"type": "scan_summary", "provider": "gowitness", "status": "SKIPPED"}
                yield {"type": "log", "message": "[!] Provider gowitness skipped"}

        active_tasks = len(tasks)

        while active_tasks > 0 or not event_queue.empty():
            try:
                label, event = await asyncio.wait_for(event_queue.get(), timeout=0.2)
            except asyncio.TimeoutError:
                active_tasks = sum(1 for t in tasks if not t.done())
                continue

            if event == "__done__":
                active_tasks = sum(1 for t in tasks if not t.done())
                if label == "katana":
                    yield {
                        "type": "scan_summary",
                        "provider": "katana",
                        "status": "completed",
                        "count": katana_urls_discovered
                    }
                    yield {"type": "log", "message": "[√] Provider katana completed"}
                elif label == "gau":
                    yield {
                        "type": "scan_summary",
                        "provider": "gau",
                        "status": "completed",
                        "count": len(all_gau_urls)
                    }
                    yield {"type": "log", "message": "[√] Provider gau completed"}
                elif label == "subjs":
                    yield {
                        "type": "scan_summary",
                        "provider": "subjs",
                        "status": "completed",
                        "count": len(all_js_files)
                    }
                    yield {"type": "log", "message": "[√] Provider subjs completed"}
                elif label == "gowitness":
                    yield {
                        "type": "scan_summary",
                        "provider": "gowitness",
                        "status": "completed",
                        "count": gowitness_screenshots
                    }
                    yield {"type": "log", "message": "[√] Provider gowitness completed"}
                continue

            # Store result lists and pass-through standard events
            if event.get("type") == "asset" and label == "katana":
                asset_data = event.get("data", {})
                k_meta = asset_data.get("metadata", {}).get("katana", {})
                k_urls = k_meta.get("urls", [])
                all_katana_urls.extend(k_urls)
            elif event.get("type") == "url_event" and label == "gau":
                all_gau_urls.append(event.get("data", {}).get("url"))
            elif event.get("type") == "js_event" and label == "subjs":
                all_js_files.append(event.get("data", {}).get("url"))
            
            if event.get("type") == "scan_summary":
                if label == "katana":
                    katana_hosts_scanned = event.get("hosts_scanned", 0)
                    katana_urls_discovered = event.get("urls_discovered", 0)
                elif label == "gowitness":
                    gowitness_screenshots = event.get("screenshots", 0)

            yield event

        await asyncio.gather(*tasks, return_exceptions=True)

        # ================================================================
        # PHASE 6B: JS Endpoint Extraction (LinkFinder)
        # ================================================================
        all_linkfinder_urls: List[str] = []
        linkfinder_endpoints = 0
        
        if all_js_files:
            linkfinder_provider = LinkfinderProvider()
            async for event in self._run_phase(linkfinder_provider, all_js_files, "LinkFinder Endpoint Extraction"):
                if event.get("type") == "url_event" and event.get("data", {}).get("source") == "linkfinder":
                    all_linkfinder_urls.append(event.get("data", {}).get("url"))
                elif event.get("type") == "scan_summary" and event.get("provider") == "LinkFinder":
                    linkfinder_endpoints = event.get("extracted_endpoints", 0)
                yield event

            yield {
                "type": "scan_summary",
                "provider": "linkfinder",
                "status": "completed",
                "count": linkfinder_endpoints
            }
            yield {"type": "log", "message": "[√] Provider linkfinder completed"}
        else:
            yield {"type": "log", "message": "[*] No JS files discovered; skipping LinkFinder."}
            yield {"type": "scan_summary", "provider": "linkfinder", "status": "SKIPPED"}
            yield {"type": "log", "message": "[!] Provider linkfinder skipped"}

        # ================================================================
        # PHASE 7: URL Merge Engine & Normalisation
        # ================================================================
        yield {"type": "log", "message": "\n========== URL Merge Engine =========="}
        
        merged_urls = merge_urls(all_katana_urls, all_gau_urls, all_linkfinder_urls, scan_mode=scan_mode)
        
        for item in merged_urls:
            yield {
                "type": "url_event",
                "data": {
                    "url": item["url"],
                    "original_url": item["url"],
                    "source": "merged",
                    "sources": item["sources"]
                }
            }
            
        merged_raw_list = [item["url"] for item in merged_urls]
        yield {"type": "log", "message": f"[√] URL Merge Engine completed. Merged {len(merged_raw_list)} URLs."}
        
        uro_normalised_urls: List[str] = []
        uro_removed = 0

        if merged_raw_list:
            uro_provider = UroProvider()
            async for event in self._run_phase(uro_provider, merged_raw_list, "Uro URL Normalisation"):
                if event.get("type") == "url_event":
                    url_data = event.get("data", {})
                    norm_url = url_data.get("url", "")
                    if norm_url:
                        uro_normalised_urls.append(norm_url)
                elif event.get("type") == "scan_summary" and event.get("provider") == "Uro":
                    uro_removed = event.get("removed", 0)
                yield event

            yield {
                "type": "scan_summary",
                "provider": "uro",
                "status": "completed",
                "count": len(uro_normalised_urls)
            }
            yield {"type": "log", "message": "[√] Provider uro completed"}
        else:
            yield {"type": "log", "message": "[*] No merged URLs; skipping Uro."}
            yield {"type": "scan_summary", "provider": "uro", "status": "SKIPPED"}
            yield {"type": "log", "message": "[!] Provider uro skipped"}

        if not uro_normalised_urls and merged_raw_list:
            uro_normalised_urls = list(dict.fromkeys(merged_raw_list))

        # ================================================================
        # PHASE 8: URL Classification (GF)
        # ================================================================
        gf_classified = 0
        ENDPOINT_SCAN_CATEGORIES = {"xss", "sqli", "ssrf", "lfi", "ssti", "idor", "redirect", "rce"}
        gf_endpoint_urls: List[str] = []
        gf_seen_endpoint_urls: set = set()
        
        gf_xss_urls: List[str] = []
        gf_redirect_urls: List[str] = []

        if uro_normalised_urls:
            gf_provider = GfProvider()
            async for event in self._run_phase(gf_provider, uro_normalised_urls, "GF Classification"):
                if event.get("type") == "scan_summary" and event.get("provider") == "GF":
                    gf_classified = event.get("urls_classified", 0)
                elif event.get("type") == "gf_event":
                    gf_data = event.get("data", {})
                    url = gf_data.get("url", "")
                    categories = set(gf_data.get("categories", []))
                    if url and categories & ENDPOINT_SCAN_CATEGORIES:
                        if url not in gf_seen_endpoint_urls:
                            gf_seen_endpoint_urls.add(url)
                            gf_endpoint_urls.append(url)
                        if "xss" in categories:
                            gf_xss_urls.append(url)
                        if "redirect" in categories:
                            gf_redirect_urls.append(url)
                yield event

            yield {
                "type": "scan_summary",
                "provider": "gf",
                "status": "completed",
                "count": gf_classified
            }
            yield {"type": "log", "message": "[√] Provider gf completed"}
        else:
            yield {"type": "log", "message": "[*] No normalised URLs; skipping GF."}
            yield {"type": "scan_summary", "provider": "gf", "status": "SKIPPED"}
            yield {"type": "log", "message": "[!] Provider gf skipped"}

        # ================================================================
        # PHASE 9: Concurrent Vulnerability Scans (Nuclei, Dalfox, OpenRedirex)
        # ================================================================
        yield {"type": "log", "message": f"\n========== Vulnerability Scanning ({scan_mode.upper()} MODE) =========="}
        
        nuclei_host_findings = 0
        nuclei_endpoint_findings = 0
        dalfox_findings = 0
        openredirex_findings = 0
        
        host_scan_targets: List[str] = list(dict.fromkeys(unique_live_urls)) if unique_live_urls else []
        
        scan_queue = asyncio.Queue()
        
        async def run_scanner(provider_func, targets, label):
            try:
                async for event in provider_func(targets):
                    await scan_queue.put((label, event))
            except Exception as exc:
                logger.error(f"Concurrent scanner {label} failed: {exc}", exc_info=True)
                await scan_queue.put((label, {"type": "log", "message": f"[-] Scanner {label} failed: {exc}"}))
            finally:
                await scan_queue.put((label, "__done__"))

        scan_tasks = []
        if host_scan_targets:
            scan_tasks.append(asyncio.create_task(run_scanner(NucleiProvider().discover_host_scan, host_scan_targets, "nuclei_host")))
        else:
            yield {"type": "scan_summary", "provider": "nuclei_host", "status": "SKIPPED"}
            yield {"type": "log", "message": "[!] Provider nuclei_host skipped"}

        if gf_endpoint_urls:
            scan_tasks.append(asyncio.create_task(run_scanner(NucleiProvider().discover_endpoint_scan, gf_endpoint_urls, "nuclei_endpoint")))
        else:
            yield {"type": "scan_summary", "provider": "nuclei_endpoint", "status": "SKIPPED"}
            yield {"type": "log", "message": "[!] Provider nuclei_endpoint skipped"}
            
        if scan_mode == "deep":
            if gf_xss_urls:
                scan_tasks.append(asyncio.create_task(run_scanner(DalfoxProvider().discover, gf_xss_urls, "dalfox")))
            else:
                yield {"type": "log", "message": "[*] No GF XSS URLs found; skipping Dalfox."}
                yield {"type": "scan_summary", "provider": "dalfox", "status": "SKIPPED"}
                yield {"type": "log", "message": "[!] Provider dalfox skipped"}
                
            if gf_redirect_urls:
                scan_tasks.append(asyncio.create_task(run_scanner(OpenredirexProvider().discover, gf_redirect_urls, "openredirex")))
            else:
                yield {"type": "log", "message": "[*] No GF Redirect URLs found; skipping OpenRedirex."}
                yield {"type": "scan_summary", "provider": "openredirex", "status": "SKIPPED"}
                yield {"type": "log", "message": "[!] Provider openredirex skipped"}
        else:
            yield {"type": "scan_summary", "provider": "dalfox", "status": "SKIPPED"}
            yield {"type": "log", "message": "[!] Provider dalfox skipped"}
            yield {"type": "scan_summary", "provider": "openredirex", "status": "SKIPPED"}
            yield {"type": "log", "message": "[!] Provider openredirex skipped"}

        active_scanners = len(scan_tasks)
        
        while active_scanners > 0 or not scan_queue.empty():
            try:
                label, event = await asyncio.wait_for(scan_queue.get(), timeout=0.2)
            except asyncio.TimeoutError:
                active_scanners = sum(1 for t in scan_tasks if not t.done())
                continue
                
            if event == "__done__":
                active_scanners = sum(1 for t in scan_tasks if not t.done())
                if label == "nuclei_host":
                    yield {
                        "type": "scan_summary",
                        "provider": "nuclei_host",
                        "status": "completed",
                        "count": nuclei_host_findings
                    }
                    yield {"type": "log", "message": "[√] Provider nuclei_host completed"}
                elif label == "nuclei_endpoint":
                    yield {
                        "type": "scan_summary",
                        "provider": "nuclei_endpoint",
                        "status": "completed",
                        "count": nuclei_endpoint_findings
                    }
                    yield {"type": "log", "message": "[√] Provider nuclei_endpoint completed"}
                elif label == "dalfox":
                    yield {
                        "type": "scan_summary",
                        "provider": "dalfox",
                        "status": "completed",
                        "count": dalfox_findings
                    }
                    yield {"type": "log", "message": "[√] Provider dalfox completed"}
                elif label == "openredirex":
                    yield {
                        "type": "scan_summary",
                        "provider": "openredirex",
                        "status": "completed",
                        "count": openredirex_findings
                    }
                    yield {"type": "log", "message": "[√] Provider openredirex completed"}
                continue
                
            if event.get("type") == "scan_summary":
                if label == "nuclei_host":
                    nuclei_host_findings = event.get("findings_found", nuclei_host_findings)
                elif label == "nuclei_endpoint":
                    nuclei_endpoint_findings = event.get("findings_found", nuclei_endpoint_findings)
                elif label == "dalfox":
                    dalfox_findings = event.get("confirmed_xss", dalfox_findings)
                elif label == "openredirex":
                    openredirex_findings = event.get("confirmed_redirects", openredirex_findings)
                    
            yield event

        await asyncio.gather(*scan_tasks, return_exceptions=True)

        nuclei_findings_count = nuclei_host_findings + nuclei_endpoint_findings
        total_security_findings = nuclei_findings_count + dalfox_findings + openredirex_findings

        if is_new_path:
            p_discovery_str = "SKIPPED"
            dnsx_str = "SKIPPED"
            subzy_str = "SKIPPED"
        else:
            p_discovery_str = f"{total_unique} unique subdomains"
            dnsx_str = f"{dnsx_resolved} | NXDOMAIN: {dnsx_nxdomain} | Wildcards: {dnsx_wildcards}"
            subzy_str = f"{subzy_vulnerable}"

        final_summary_msg = (
            f"\n{'='*10} Pipeline Complete {'='*10}\n"
            f"[√] Unified Discovery Pipeline finished.\n"
            f"    Passive Discovery  : {p_discovery_str}\n"
            f"    DNS Resolution     : {dnsx_str}\n"
            f"    Subzy              : {subzy_str}\n"
            f"    HTTPX Live Hosts   : {live_hosts}\n"
            f"    Naabu Open Ports   : {naabu_open_ports} across {naabu_hosts_with_ports} hosts\n"
            f"    Katana URLs        : {katana_urls_discovered} (crawled {katana_hosts_scanned} hosts)\n"
            f"    GAU Historical URLs: {len(all_gau_urls)}\n"
            f"    SubJS JS Files     : {len(all_js_files)}\n"
            f"    LinkFinder Endpts  : {linkfinder_endpoints}\n"
            f"    GoWitness Screenpts: {gowitness_screenshots}\n"
            f"    Uro Normalised URLs: {len(uro_normalised_urls)} (removed {uro_removed})\n"
            f"    GF Matches         : {gf_classified} | Endpoint targets: {len(gf_endpoint_urls)}\n"
            f"    Nuclei Findings    : {nuclei_findings_count} (Host: {nuclei_host_findings}, Endpoint: {nuclei_endpoint_findings})\n"
            f"    Dalfox Confirmed XSS: {dalfox_findings}\n"
            f"    OpenRedirex Redirs : {openredirex_findings}\n"
            f"    Security Findings  : {total_security_findings}"
        )
        logger.info(final_summary_msg)
        yield {"type": "log", "message": final_summary_msg}

        yield {
            "type": "scan_summary",
            "provider_counts": {
                "subfinder":   provider_counts.get("subfinder", 0),
                "assetfinder": provider_counts.get("assetfinder", 0),
                "chaos":       provider_counts.get("chaos", 0),
                "amass":       provider_counts.get("amass", 0),
            },
            "total_unique":                total_unique,
            "dnsx_resolved":               dnsx_resolved,
            "dnsx_nxdomain":               dnsx_nxdomain,
            "dnsx_wildcards_filtered":     dnsx_wildcards,
            "subzy_vulnerable":            subzy_vulnerable,
            "live_hosts":                  live_hosts,
            "naabu_hosts_with_open_ports": naabu_hosts_with_ports,
            "naabu_open_ports":            naabu_open_ports,
            "katana_hosts_scanned":        katana_hosts_scanned,
            "katana_urls_discovered":      katana_urls_discovered,
            "historical_urls":             len(all_gau_urls),
            "js_files":                    len(all_js_files),
            "extracted_endpoints":         linkfinder_endpoints,
            "screenshots":                 gowitness_screenshots,
            "uro_normalised_urls":         len(uro_normalised_urls),
            "uro_removed":                 uro_removed,
            "gf_classified":               gf_classified,
            "gf_endpoint_urls":            len(gf_endpoint_urls),
            "nuclei_host_findings":        nuclei_host_findings,
            "nuclei_endpoint_findings":    nuclei_endpoint_findings,
            "nuclei_findings_count":       nuclei_findings_count,
            "confirmed_xss":               dalfox_findings,
            "confirmed_redirects":         openredirex_findings,
            "security_findings":           total_security_findings
        }

