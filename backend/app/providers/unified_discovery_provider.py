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
from typing import AsyncGenerator, Dict, Any, List, Set

from app.providers.base import BaseProvider
from app.providers.subfinder_provider import SubfinderProvider
from app.providers.assetfinder_provider import AssetfinderProvider
from app.providers.amass_provider import AmassProvider
from app.providers.chaos_provider import ChaosProvider

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
        # Collect all raw results from every provider concurrently.
        # results_map: domain -> set(source_labels)
        # ---------------------------------------------------------------
        results_map: Dict[str, Set[str]] = {}   # domain -> set of sources
        provider_counts: Dict[str, int] = {}    # label -> count

        # We use an asyncio.Queue to let provider coroutines push events while
        # we centralise dedup logic here.
        event_queue: asyncio.Queue = asyncio.Queue()

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
                if domain not in results_map:
                    results_map[domain] = set()
                results_map[domain].add(source)

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
        # Emit deduplicated asset events
        # ---------------------------------------------------------------
        total_unique = len(results_map)
        summary_msg = (
            f"\n[√] Unified Discovery complete.\n"
            f"    Subfinder   : {provider_counts.get('subfinder', 0)}\n"
            f"    Assetfinder : {provider_counts.get('assetfinder', 0)}\n"
            f"    Amass       : {provider_counts.get('amass', 0)}\n"
            f"    Chaos       : {provider_counts.get('chaos', 0)}\n"
            f"    ─────────────────────────\n"
            f"    Total Unique : {total_unique}"
        )
        logger.info(summary_msg)
        yield {"type": "log", "message": summary_msg}

        for domain, sources in sorted(results_map.items()):
            sources_list = sorted(sources)
            yield {
                "type": "asset",
                "data": {
                    "domain": domain,
                    "type": "subdomain",
                    "status": "unknown",
                    "open_ports": [],
                    "metadata": {"source": "unified_discovery"},
                    "discovered_by": "Unified Discovery",
                    # Extra field used by jobs.py for source attribution upsert
                    "sources": sources_list,
                },
            }

        yield {
            "type": "scan_summary",
            "provider_counts": {
                "subfinder": provider_counts.get("subfinder", 0),
                "assetfinder": provider_counts.get("assetfinder", 0),
                "amass": provider_counts.get("amass", 0),
                "chaos": provider_counts.get("chaos", 0),
            },
            "total_unique": total_unique,
        }
