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
    return bool(domain and _VALID_HOSTNAME_RE.match(domain))


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
        self, seed_domains: List[str]
    ) -> AsyncGenerator[Dict[str, Any], None]:

        start_msg = (
            f"[*] Unified Discovery Engine starting for: {', '.join(seed_domains)}\n"
            f"    Pipeline: Passive → DNSx → Subzy → Naabu → HTTPX → Katana → Uro → GF → Nuclei"
        )
        logger.info(start_msg)
        yield {"type": "log", "message": start_msg}

        # ================================================================
        # PHASE 1: Concurrent passive discovery
        # ================================================================

        provider_counts: Dict[str, int] = {}
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
        dnsx_resolved = 0
        dnsx_nxdomain = 0
        dnsx_wildcards = 0

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

        subzy_vulnerable = 0
        subzy_provider = SubzyProvider()
        async for event in self._run_phase(subzy_provider, unique_resolved, "Subzy Takeover Check"):
            if event.get("type") == "scan_summary" and event.get("provider") == "Subzy":
                subzy_vulnerable = event.get("vulnerable", 0)
            yield event

        # ================================================================
        # PHASE 4: Port Scanning (Naabu)
        # ================================================================

        naabu_hosts_with_ports = 0
        naabu_open_ports = 0
        naabu_provider = NaabuProvider()
        async for event in self._run_phase(naabu_provider, unique_resolved, "Naabu Port Scan"):
            if event.get("type") == "scan_summary":
                naabu_hosts_with_ports = event.get("hosts_with_open_ports", 0)
                naabu_open_ports       = event.get("open_ports", 0)
            yield event

        # ================================================================
        # PHASE 5: HTTP Probing (HTTPX)
        # ================================================================

        live_hosts = 0
        live_host_targets: List[str] = []
        live_host_urls: List[str] = []
        host_to_live_url: Dict[str, str] = {}
        host_to_urls: Dict[str, List[str]] = defaultdict(list)

        httpx_start_msg = (
            f"\n========== HTTPX Probing ==========\n"
            f"[*] Launching HTTPX on {len(unique_resolved)} resolved subdomains..."
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

        unique_live_hosts = sorted({h for h in live_host_targets if _is_valid(h)})
        unique_live_urls  = sorted(set(live_host_urls))

        # ================================================================
        # PHASE 6: Web Crawling (Katana)
        # ================================================================

        katana_hosts_scanned  = 0
        katana_urls_discovered = 0
        all_katana_urls: List[str] = []

        if unique_live_urls:
            katana_provider = KatanaProvider()
            async for event in self._run_phase(katana_provider, unique_live_urls, "Katana Web Crawl"):
                if event.get("type") == "scan_summary":
                    katana_hosts_scanned   = event.get("hosts_scanned", 0)
                    katana_urls_discovered = event.get("urls_discovered", 0)
                elif event.get("type") == "asset":
                    asset_data = event.get("data", {})
                    domain = _normalise(asset_data.get("domain", ""))
                    k_meta = asset_data.get("metadata", {}).get("katana", {})
                    k_urls = k_meta.get("urls", [])
                    if k_urls:
                        host_to_urls[domain].extend(k_urls)
                        all_katana_urls.extend(k_urls)
                yield event
        elif unique_resolved:
            yield {"type": "log", "message": "[*] No LIVE URLs from HTTPX; skipping Katana."}

        # ================================================================
        # PHASE 7: URL Deduplication (Uro)
        # ================================================================

        uro_normalised_urls: List[str] = []
        uro_removed = 0

        if all_katana_urls:
            uro_provider = UroProvider()
            async for event in self._run_phase(uro_provider, all_katana_urls, "Uro URL Normalisation"):
                if event.get("type") == "url_event":
                    url_data = event.get("data", {})
                    norm_url = url_data.get("url", "")
                    if norm_url:
                        uro_normalised_urls.append(norm_url)
                elif event.get("type") == "scan_summary" and event.get("provider") == "Uro":
                    uro_removed = event.get("removed", 0)
                yield event
        elif unique_live_urls:
            yield {"type": "log", "message": "[*] No Katana URLs; skipping Uro."}

        # If Uro produced no output (not installed), fall back to raw Katana URLs
        if not uro_normalised_urls and all_katana_urls:
            reason = getattr(uro_provider, "last_run_status", "unknown")
            if reason == "executable_not_found":
                reason_str = "Uro executable not found"
            elif reason == "zero_urls":
                reason_str = "Uro returned zero URLs"
            elif reason.startswith("non_zero_exit_code_"):
                code = reason.replace("non_zero_exit_code_", "")
                reason_str = f"Uro exited with non-zero code: {code}"
            else:
                reason_str = f"Uro failed with status: {reason}"

            logger.warning("[*] Uro yielded no normalised URLs (%s); falling back to raw Katana URLs.", reason_str)
            yield {
                "type": "log",
                "message": f"[*] Uro yielded no normalised URLs ({reason_str}). Using raw Katana URLs for GF and Nuclei.",
            }
            uro_normalised_urls = list(dict.fromkeys(all_katana_urls))

        # ================================================================
        # PHASE 8: URL Classification (GF)
        # ================================================================

        gf_classified = 0

        if uro_normalised_urls:
            gf_provider = GfProvider()
            async for event in self._run_phase(gf_provider, uro_normalised_urls, "GF Classification"):
                if event.get("type") == "scan_summary" and event.get("provider") == "GF":
                    gf_classified = event.get("urls_classified", 0)
                yield event
        elif unique_live_urls:
            yield {"type": "log", "message": "[*] No normalised URLs; skipping GF."}

        # ================================================================
        # PHASE 9: Vulnerability Scanning (Nuclei)
        # ================================================================

        # Build Nuclei target list: prefer Uro-normalised URLs; fall back to
        # live-host URLs so Nuclei always has at least something to scan.
        nuclei_targets: List[str] = []
        if uro_normalised_urls:
            nuclei_targets = list(dict.fromkeys(uro_normalised_urls))
        else:
            for host in unique_live_hosts:
                host_urls = host_to_urls.get(host, [])
                if not host_urls:
                    live_url = host_to_live_url.get(host)
                    host_urls = [live_url] if live_url else [f"http://{host}"]
                nuclei_targets.extend(host_urls)
            nuclei_targets = list(dict.fromkeys(nuclei_targets))

        nuclei_findings_count = 0

        if nuclei_targets:
            nuclei_provider = NucleiProvider()
            async for event in self._run_phase(nuclei_provider, nuclei_targets, "Nuclei Vulnerability Scan"):
                if event.get("type") == "scan_summary":
                    nuclei_findings_count = event.get("findings_found", 0)
                yield event
        elif unique_resolved:
            yield {"type": "log", "message": "[*] No URLs for Nuclei; skipping."}

        # ================================================================
        # Final summary
        # ================================================================

        final_summary_msg = (
            f"\n{'='*10} Pipeline Complete {'='*10}\n"
            f"[√] Unified Discovery Pipeline finished.\n"
            f"    Passive Discovery : {total_unique} unique subdomains\n"
            f"    DNSx Resolved     : {dnsx_resolved} | NXDOMAIN: {dnsx_nxdomain} | Wildcards: {dnsx_wildcards}\n"
            f"    Subzy Vulnerable  : {subzy_vulnerable}\n"
            f"    HTTPX Live Hosts  : {live_hosts}\n"
            f"    Naabu Open Ports  : {naabu_open_ports} across {naabu_hosts_with_ports} hosts\n"
            f"    Katana URLs       : {katana_urls_discovered} across {katana_hosts_scanned} hosts\n"
            f"    Uro Normalised    : {len(uro_normalised_urls)} (removed {uro_removed})\n"
            f"    GF Classified     : {gf_classified} URLs\n"
            f"    Nuclei Findings   : {nuclei_findings_count}"
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
            "total_unique":              total_unique,
            "dnsx_resolved":             dnsx_resolved,
            "dnsx_nxdomain":             dnsx_nxdomain,
            "dnsx_wildcards_filtered":   dnsx_wildcards,
            "subzy_vulnerable":          subzy_vulnerable,
            "live_hosts":                live_hosts,
            "naabu_hosts_with_open_ports": naabu_hosts_with_ports,
            "naabu_open_ports":          naabu_open_ports,
            "katana_hosts_scanned":      katana_hosts_scanned,
            "katana_urls_discovered":    katana_urls_discovered,
            "uro_normalised_urls":       len(uro_normalised_urls),
            "uro_removed":               uro_removed,
            "gf_classified":             gf_classified,
            "nuclei_findings_count":     nuclei_findings_count,
        }
