"""
UnifiedDiscoveryProvider
========================
Runs Subfinder, Assetfinder, Amass (passive), and Chaos concurrently against
every seed domain, then deduplicates results, normalises hostnames, and yields
a single deduplicated stream of asset events.

Each asset carries a `sources` list that records which tools discovered it so
the jobs router can merge attribution on upsert.

Provider failures are isolated — a single tool crashing will not stop the
overall scan.
"""
import asyncio
import logging
import re
from typing import AsyncGenerator, Dict, Any, List

from app.providers.base import BaseProvider
from app.providers.subfinder_provider import SubfinderProvider
from app.providers.assetfinder_provider import AssetfinderProvider
from app.providers.amass_provider import AmassProvider
from app.providers.chaos_provider import ChaosProvider
from collections import defaultdict
from app.providers.httpx_provider import HttpxProvider
from app.providers.naabu_provider import NaabuProvider
from app.providers.katana_provider import KatanaProvider
from app.providers.nuclei_provider import NucleiProvider

logger = logging.getLogger("reconforge.providers.unified")


# Simple hostname validation: must look like host.tld (no wildcards, no IPs)
_VALID_HOSTNAME_RE = re.compile(
    r"^(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$"
)


def _normalise(domain: str) -> str:
    """Lowercase, strip whitespace, drop leading '*.' wildcard prefixes."""
    domain = domain.strip().lower()
    # Strip wildcard prefix e.g. *.example.com -> example.com
    while domain.startswith("*."):
        domain = domain[2:]
    return domain


def _is_valid(domain: str) -> bool:
    return bool(domain and _VALID_HOSTNAME_RE.match(domain))


class UnifiedDiscoveryProvider(BaseProvider):
    """Orchestrates all individual subdomain providers concurrently."""

    # Ordered list of (provider_instance, provider_label)
    SUB_PROVIDERS = [
        (SubfinderProvider(), "subfinder"),
        (AssetfinderProvider(), "assetfinder"),
        (AmassProvider(), "amass"),
        (ChaosProvider(), "chaos"),
    ]

    @property
    def name(self) -> str:
        return "Unified Discovery"

    @property
    def description(self) -> str:
        return (
            "Runs Subfinder, Assetfinder, Amass (passive), and Chaos in parallel, "
            "deduplicates results, and stores unique subdomains with source attribution."
        )

    async def discover(
        self, seed_domains: List[str]
    ) -> AsyncGenerator[Dict[str, Any], None]:
        start_msg = (
            f"[*] Unified Discovery Engine starting for: {', '.join(seed_domains)}\n"
            f"    Providers: Subfinder | Assetfinder | Amass (passive) | Chaos"
        )
        logger.info(start_msg)
        yield {"type": "log", "message": start_msg}

        # ---------------------------------------------------------------
        # PHASE 1: Concurrent execution of discovery providers.
        # - Stream asset events immediately as they arrive.
        # - Collect discovered subdomains for later global dedup + HTTPX stage.
        # ---------------------------------------------------------------
        provider_counts: Dict[str, int] = {}
        discovered_subdomains: List[str] = []

        event_queue: asyncio.Queue = asyncio.Queue()  # (kind, ...)



        async def run_provider(provider: BaseProvider, label: str) -> None:
            logger.info(f"[*] Launching {label}...")
            count = 0
            try:
                async for event in provider.discover(seed_domains):
                    if event.get("type") == "asset":
                        raw = event["data"].get("domain", "")
                        normalised = _normalise(raw)
                        if _is_valid(normalised):
                            await event_queue.put(("asset", normalised, label))
                            discovered_subdomains.append(normalised)
                            count += 1

                    # Log events from individual providers are suppressed in the
                    # frontend; they still appear on the backend terminal via the
                    # provider's own logger.
            except Exception as exc:
                err = f"[-] {label} failed: {exc}"
                logger.error(err)
                await event_queue.put(("provider_error", label, str(exc)))
            finally:
                provider_counts[label] = count
                logger.info(f"[+] {label} finished → discovered {count} raw subdomains")
                await event_queue.put(("provider_done", label, count))

        # Kick off all providers concurrently
        tasks = [
            asyncio.create_task(run_provider(p, lbl))
            for p, lbl in self.SUB_PROVIDERS
        ]

        remaining_providers = len(tasks)

        while remaining_providers > 0 or not event_queue.empty():

            try:
                item = await asyncio.wait_for(event_queue.get(), timeout=0.2)
            except asyncio.TimeoutError:
                # Check if all tasks finished even if queue is silent
                remaining_providers = sum(1 for t in tasks if not t.done())
                continue

            kind = item[0]

            if kind == "asset":
                _, domain, source = item
                # PHASE 1: stream immediately, no global deduplication.
                yield {
                    "type": "asset",
                    "data": {
                        "domain": domain,
                        "type": "subdomain",
                        "status": "unknown",
                        "open_ports": [],
                        "metadata": {"source": "unified_discovery"},
                        "discovered_by": "Unified Discovery",
                        # Phase 1: single source list (no merging yet).
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
                    # Carry provider stats as extra metadata for the frontend
                    "provider_stat": {"provider": label, "count": count},
                }
                remaining_providers = sum(1 for t in tasks if not t.done())

            elif kind == "provider_error":
                _, label, error = item
                yield {
                    "type": "log",
                    "message": f"[-] {label} encountered an error: {error}",
                }

        # Await all tasks cleanly
        await asyncio.gather(*tasks, return_exceptions=True)

        # ---------------------------------------------------------------
        # Stage 1 summary: global deduplication + Stage 2 prep
        # ---------------------------------------------------------------

        unique_subdomains = sorted(set(discovered_subdomains))
        total_unique = len(unique_subdomains)

        summary_msg = (
            f"\n[√] Unified Discovery Phase 1 complete.\n"
            f"    Subfinder   : {provider_counts.get('subfinder', 0)}\n"
            f"    Assetfinder : {provider_counts.get('assetfinder', 0)}\n"
            f"    Amass       : {provider_counts.get('amass', 0)}\n"
            f"    Chaos       : {provider_counts.get('chaos', 0)}\n"
            f"    ─────────────────────────\n"
            f"    Total Unique : {total_unique}"
        )
        logger.info(summary_msg)
        yield {"type": "log", "message": summary_msg}

        # ---------------------------------------------------------------
        # PHASE 2: HTTPX probing on deduplicated subdomains
        # ---------------------------------------------------------------

        live_hosts = 0
        live_host_targets: List[str] = []
        live_host_urls: List[str] = []
        host_to_live_url: Dict[str, str] = {}
        host_to_urls = defaultdict(list)
        httpx_error = None
        naabu_error = None
        katana_error = None
        nuclei_error = None
        naabu_hosts_with_ports = 0
        naabu_open_ports = 0
        katana_hosts_scanned = 0
        katana_urls_discovered = 0
        nuclei_findings_count = 0

        if total_unique > 0:
            # Announce HTTPX phase
            httpx_start_msg = (
                f"\n========== HTTPX Probing ==========\n"
                f"[*] Launching HTTPX on {total_unique} unique subdomains..."
            )
            logger.info(httpx_start_msg)
            yield {"type": "log", "message": httpx_start_msg}

            from app.job_control import check_job_status
            await check_job_status()

            # Instantiate and run HTTPX
            httpx_provider = HttpxProvider()
            try:
                async for event in httpx_provider.discover(unique_subdomains):
                    event_type = event.get("type")

                    # Track live hosts for final summary
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
                        # Stream the asset immediately (with HTTPX metadata)
                        yield event

                    # Stream logs and other events
                    elif event_type in ("log", "scan_summary"):
                        yield event

            except Exception as exc:
                httpx_error = str(exc)
                err_msg = f"[-] HTTPX probing failed: {httpx_error}"
                logger.error(err_msg)
                yield {"type": "log", "message": err_msg}
                # Continue—don't fail the entire scan
        else:
            no_hosts_msg = "[*] No unique subdomains to probe; skipping HTTPX."
            logger.info(no_hosts_msg)
            yield {"type": "log", "message": no_hosts_msg}

        # ---------------------------------------------------------------
        # PHASE 3: Naabu open-port scanning on deduplicated LIVE hosts
        # ---------------------------------------------------------------

        unique_live_hosts = sorted({host for host in live_host_targets if _is_valid(host)})

        if unique_live_hosts:
            from app.job_control import check_job_status
            await check_job_status()

            naabu_provider = NaabuProvider()
            try:
                async for event in naabu_provider.discover(unique_live_hosts):
                    if event.get("type") == "scan_summary":
                        naabu_hosts_with_ports = event.get("hosts_with_open_ports", 0)
                        naabu_open_ports = event.get("open_ports", 0)

                    yield event

            except Exception as exc:
                naabu_error = str(exc)
                err_msg = f"[-] Naabu scanning failed: {naabu_error}"
                logger.error(err_msg)
                yield {"type": "log", "message": err_msg}
                # Open-port enrichment is non-fatal to Unified Discovery.
        elif total_unique > 0:
            no_live_msg = "[*] No LIVE hosts from HTTPX; skipping Naabu."
            logger.info(no_live_msg)
            yield {"type": "log", "message": no_live_msg}

        # ---------------------------------------------------------------
        # PHASE 4: Katana web crawling on deduplicated LIVE URLs
        # ---------------------------------------------------------------

        unique_live_urls = sorted(list(set(live_host_urls)))

        if unique_live_urls:
            from app.job_control import check_job_status
            await check_job_status()

            katana_provider = KatanaProvider()
            try:
                async for event in katana_provider.discover(unique_live_urls):
                    if event.get("type") == "scan_summary":
                        katana_hosts_scanned = event.get("hosts_scanned", 0)
                        katana_urls_discovered = event.get("urls_discovered", 0)
                    elif event.get("type") == "asset":
                        asset_data = event.get("data", {})
                        domain = _normalise(asset_data.get("domain", ""))
                        k_meta = asset_data.get("metadata", {}).get("katana", {})
                        k_urls = k_meta.get("urls", [])
                        if k_urls:
                            host_to_urls[domain].extend(k_urls)

                    yield event

            except Exception as exc:
                katana_error = str(exc)
                err_msg = f"[-] Katana crawling failed: {katana_error}"
                logger.error(err_msg)
                yield {"type": "log", "message": err_msg}
                # Crawling enrichment is non-fatal to Unified Discovery.
        elif total_unique > 0:
            no_live_msg = "[*] No LIVE URLs from HTTPX; skipping Katana."
            logger.info(no_live_msg)
            yield {"type": "log", "message": no_live_msg}

        # ---------------------------------------------------------------
        # PHASE 5: Nuclei scanning on deduplicated target URLs
        # ---------------------------------------------------------------
        nuclei_targets = []
        for host in unique_live_hosts:
            host_urls = host_to_urls.get(host, [])
            if not host_urls:
                live_url = host_to_live_url.get(host)
                if live_url:
                    host_urls = [live_url]
                else:
                    host_urls = [f"http://{host}"]
            nuclei_targets.extend(host_urls)

        unique_nuclei_targets = sorted(list(set(nuclei_targets)))

        if unique_nuclei_targets:
            from app.job_control import check_job_status
            await check_job_status()

            nuclei_provider = NucleiProvider()
            try:
                async for event in nuclei_provider.discover(unique_nuclei_targets):
                    if event.get("type") == "scan_summary":
                        nuclei_findings_count = event.get("findings_found", 0)
                    yield event
            except Exception as exc:
                nuclei_error = str(exc)
                err_msg = f"[-] Nuclei scanning failed: {nuclei_error}"
                logger.error(err_msg)
                yield {"type": "log", "message": err_msg}
                # Nuclei scanning is non-fatal to Unified Discovery.
        elif total_unique > 0:
            no_live_msg = "[*] No LIVE URLs from HTTPX or Katana; skipping Nuclei."
            logger.info(no_live_msg)
            yield {"type": "log", "message": no_live_msg}

        # ---------------------------------------------------------------
        # Final summary: combined results
        # ---------------------------------------------------------------

        final_summary_msg = (
            f"\n========== Pipeline Complete ==========\n"
            f"[√] Unified Discovery Pipeline finished.\n"
            f"    Discovery Results  : {total_unique} unique subdomains\n"
            f"    HTTPX Results      : {live_hosts} live hosts\n"
            f"    Naabu Results      : {naabu_open_ports} open ports across {naabu_hosts_with_ports} hosts\n"
            f"    Katana Results     : {katana_urls_discovered} URLs discovered across {katana_hosts_scanned} hosts\n"
            f"    Nuclei Results     : {nuclei_findings_count} findings discovered across {len(unique_nuclei_targets)} URLs"
        )
        if httpx_error:
            final_summary_msg += f"\n    ⚠️  HTTPX Error    : {httpx_error} (non-fatal)"
        if naabu_error:
            final_summary_msg += f"\n    Naabu Error       : {naabu_error} (non-fatal)"
        if katana_error:
            final_summary_msg += f"\n    Katana Error      : {katana_error} (non-fatal)"
        if nuclei_error:
            final_summary_msg += f"\n    Nuclei Error      : {nuclei_error} (non-fatal)"
        logger.info(final_summary_msg)
        yield {"type": "log", "message": final_summary_msg}

        yield {
            "type": "scan_summary",
            "provider_counts": {
                "subfinder": provider_counts.get("subfinder", 0),
                "assetfinder": provider_counts.get("assetfinder", 0),
                "amass": provider_counts.get("amass", 0),
                "chaos": provider_counts.get("chaos", 0),
            },
            "total_unique": total_unique,
            "live_hosts": live_hosts,
            "naabu_hosts_with_open_ports": naabu_hosts_with_ports,
            "naabu_open_ports": naabu_open_ports,
            "katana_hosts_scanned": katana_hosts_scanned,
            "katana_urls_discovered": katana_urls_discovered,
            "nuclei_findings_count": nuclei_findings_count,
        }
