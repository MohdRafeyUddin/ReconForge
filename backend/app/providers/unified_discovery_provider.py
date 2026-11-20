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

Phase 7D – Visual Verification
    GoWitness (host roots + prioritized live URLs)

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
import platform
import re
import time
from collections import defaultdict
from typing import Any, AsyncGenerator, Callable, Dict, List, Optional, Tuple
from urllib.parse import urlparse

from app.core.scan_options import (
    normalize_phase_switches,
    phase_switch_enabled,
    phase_time_cap,
)

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
from app.providers.ffuf_provider import FfufProvider
from app.providers.api_surface_provider import ApiSurfaceProvider
from app.providers.param_discovery_provider import ParamDiscoveryProvider
from app.providers.waymore_provider import WaymoreProvider
from app.providers.url_merge import select_screenshot_targets
from app.providers.crtsh_provider import CrtshProvider
from app.providers.certspotter_provider import CertspotterProvider
from app.providers.dns_bruteforce_provider import DnsBruteforceProvider
from app.providers.root_expansion_provider import RootExpansionProvider
from app.providers.takeover_crosscheck_provider import TakeoverCrossCheckProvider
from app.providers.js_analysis_provider import JsAnalysisProvider
from app.providers.secrets_provider import SecretsProvider
from app.providers.cloud_enum_provider import CloudEnumProvider
from app.providers.wpscan_provider import WpscanProvider
from app.services.oast import OASTSession
from app.core.phase8_config import get_phase8_config
from app.core.provider_keys import sync_subfinder_config_to_wsl
from app.providers.url_merge import merge_urls
from app.core.scope import filter_scope, is_in_scope, is_ip_in_scope, validate_hostname, is_disallowed_ip, get_root_domain
from app.core.tools import is_tool_available, get_tool_status

logger = logging.getLogger("reconforge.providers.unified")

# Phase 8.6 — detected technology → targeted Nuclei tag
TECH_TAG_MAP: Dict[str, str] = {
    "jenkins": "jenkins",
    "grafana": "grafana",
    "kibana": "kibana",
    "elasticsearch": "elasticsearch",
    "gitlab": "gitlab",
    "jira": "jira",
    "confluence": "confluence",
    "wordpress": "wordpress",
    "tomcat": "tomcat",
    "phpmyadmin": "phpmyadmin",
    "drupal": "drupal",
    "joomla": "joomla",
    "spring": "springboot",
    "laravel": "laravel",
    "graphql": "graphql",
    "swagger": "swagger",
    "openapi": "swagger",
}


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
        (CrtshProvider(),       "crtsh"),
        (CertspotterProvider(), "certspotter"),
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

    async def _capped_events(
        self,
        factory: Callable[[], AsyncGenerator[Dict[str, Any], None]],
        phase: str,
        tool: str,
        cap_seconds: int,
    ) -> AsyncGenerator[Dict[str, Any], None]:
        """Streams a phase while enforcing a hard time cap.

        The provider runs in its own task so the cap can cancel it and
        hard-kill only subprocesses started while this phase was active.
        """
        from app.job_control import current_phase, kill_phase_processes

        queue: asyncio.Queue = asyncio.Queue()

        async def producer() -> None:
            token = current_phase.set(phase)
            try:
                async for ev in factory():
                    if ev and isinstance(ev, dict):
                        await queue.put(("event", ev))
            except Exception as exc:  # provider failures are non-fatal
                await queue.put(("error", exc))
            finally:
                current_phase.reset(token)
                await queue.put(("done", None))

        task = asyncio.create_task(producer())
        deadline = time.monotonic() + max(1, int(cap_seconds))
        try:
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    killed = kill_phase_processes(phase)
                    reason = f"time cap ({cap_seconds}s) exceeded; killed {killed} process(es)"
                    yield {"type": "stage_timeout", "stage": phase, "tool": tool, "reason": reason}
                    yield {"type": "log", "message": f"[-] {phase} {reason}. Partial results kept."}
                    break
                try:
                    kind, payload = await asyncio.wait_for(queue.get(), timeout=remaining)
                except asyncio.TimeoutError:
                    continue
                if kind == "done":
                    break
                if kind == "error":
                    yield {
                        "type": "stage_error",
                        "stage": phase,
                        "tool": tool,
                        "reason": str(payload),
                        "error": str(payload),
                    }
                    yield {"type": "log", "message": f"[-] {phase} failed: {payload} (non-fatal)"}
                    continue
                yield payload
        finally:
            if not task.done():
                task.cancel()
            await asyncio.gather(task, return_exceptions=True)

    async def _run_phase(
        self,
        provider: BaseProvider,
        targets: List[str],
        phase_label: str,
        time_cap_seconds: Optional[int] = None,
        tool_name: Optional[str] = None,
        **kwargs: Any,
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
            if time_cap_seconds:
                async for event in self._capped_events(
                    lambda: provider.discover(targets, **kwargs),
                    phase_label,
                    tool_name or provider.name,
                    time_cap_seconds,
                ):
                    yield event
            else:
                async for event in provider.discover(targets, **kwargs):
                    if event and isinstance(event, dict):
                        yield event
        except Exception as exc:
            err_msg = f"[-] {phase_label} failed: {exc}"
            logger.error(err_msg)
            yield {"type": "log", "message": f"{err_msg} (non-fatal — continuing pipeline)"}

    # ------------------------------------------------------------------
    # Main orchestration
    # ------------------------------------------------------------------

    async def discover(
        self,
        seed_domains: List[str],
        scan_mode: str = "fast",
        project_config: Optional[Dict[str, Any]] = None,
    ) -> AsyncGenerator[Dict[str, Any], None]:

        # Seed domain normalization (e.g. *.example.com -> example.com)
        from app.core.scope import normalize_seed_domain
        normalized_seeds = []
        for s in (seed_domains or []):
            norm_s = normalize_seed_domain(s)
            if norm_s and norm_s not in normalized_seeds:
                normalized_seeds.append(norm_s)
        if not normalized_seeds and seed_domains:
            normalized_seeds = [s.strip().lstrip("*.").strip() for s in seed_domains if s.strip()]
        seed_domains = normalized_seeds

        # Target Detection
        seed = seed_domains[0] if seed_domains else ""
        target_type = detect_target_type(seed)
        is_localhost = seed.strip().lower() == "localhost"
        is_new_path = target_type in ("URL", "IP", "HOST_PORT") or is_localhost

        yield {"type": "log", "message": f"Detected target type: {target_type}"}

        # Stage 1 — one full scan, expensive phases gated per project.
        project_config = project_config or {}
        phase_switches = normalize_phase_switches(project_config.get("phase_switches"))
        dns_bruteforce_enabled = phase_switch_enabled(phase_switches, "dns_bruteforce")
        # Automatic content/param/port/screenshot phases: no per-run selection.
        # Time caps and project rate limits still apply.
        waymore_enabled = True
        ffuf_enabled = True
        param_discovery_enabled = True
        wide_port_scan_enabled = True
        active_scanners_enabled = phase_switch_enabled(phase_switches, "active_scanners")
        screenshots_enabled = True

        def timing(phase: str, started: float) -> Dict[str, Any]:
            return {
                "type": "phase_timing",
                "phase": phase,
                "duration_seconds": round(time.monotonic() - started, 2),
            }

        # Scope, Rate Limits, and Custom Headers Configuration
        scope_config = project_config.get("scope") or {"in_scope": [], "out_of_scope": []}
        rate_limits_cfg = project_config.get("rate_limits") or {}
        custom_headers_cfg = project_config.get("custom_headers") or {}
        scan_profile = project_config.get("scan_profile", "recon") or "recon"
        phase8_cfg = get_phase8_config(project_config)

        # Requirement 4: Setting assume_tools_installed (default true)
        from app.config import settings
        assume_tools_cfg = (project_config or {}).get("assume_tools_installed")
        if assume_tools_cfg is None:
            assume_tools_installed = getattr(settings, "ASSUME_TOOLS_INSTALLED", True)
        else:
            assume_tools_installed = bool(assume_tools_cfg)

        # Synchronize Subfinder API keys to WSL if configured
        sync_subfinder_config_to_wsl()

        def is_available(tool_name: str) -> bool:
            """When assume_tools_installed is true, skips pre-scan availability gate."""
            if tool_name in ("crtsh", "certspotter"):
                return True
            if assume_tools_installed:
                return True
            return is_tool_available(tool_name)

        DEFAULT_TOOL_RPS = {"httpx": 20, "katana": 10, "nuclei": 10, "naabu": 300, "ffuf": 20, "arjun": 10}
        global_rps = int(rate_limits_cfg.get("global_rps") or 10)
        per_tool_rps = rate_limits_cfg.get("per_tool") or {}

        def get_tool_rl(tool_name: str) -> int:
            if tool_name in per_tool_rps and per_tool_rps[tool_name]:
                return int(per_tool_rps[tool_name])
            if not per_tool_rps and "global_rps" not in rate_limits_cfg and tool_name in DEFAULT_TOOL_RPS:
                return DEFAULT_TOOL_RPS[tool_name]
            return global_rps

        def check_and_filter_scope(targets: List[str], phase_name: str) -> Tuple[List[str], List[Dict[str, Any]]]:
            kept, dropped = filter_scope(targets, scope_config)
            events = []
            if dropped:
                sample_str = ", ".join(dropped[:5])
                if len(dropped) > 5:
                    sample_str += f" and {len(dropped) - 5} more"
                log_msg = f"[!] [Scope Filter] {phase_name}: Dropped {len(dropped)} out-of-scope targets (sample: {sample_str})"
                events.append({"type": "log", "message": log_msg})
                events.append({
                    "type": "scope_filtered",
                    "phase": phase_name,
                    "dropped_count": len(dropped),
                    "remaining_count": len(kept),
                    "sample_dropped": dropped[:5],
                })
            return kept, events

        # Emit scope status warning if scope is unconfigured
        has_scope = bool((scope_config.get("in_scope") or []) or (scope_config.get("out_of_scope") or []))
        if not has_scope:
            warn_msg = "[!] WARNING: Scope is not configured for this project. All discovered targets will be scanned."
            yield {"type": "log", "message": warn_msg}
            yield {
                "type": "scope_warning",
                "message": "Scope is not configured for this project. All discovered targets will be scanned.",
            }
        else:
            in_count = len(scope_config.get("in_scope") or [])
            out_count = len(scope_config.get("out_of_scope") or [])
            yield {
                "type": "log",
                "message": f"[*] Scope Engine initialized: {in_count} in-scope rules, {out_count} out-of-scope rules.",
            }

        provider_counts: Dict[str, int] = {}
        total_unique = 0
        subzy_vulnerable = 0
        
        dnsx_resolved = 0
        dnsx_nxdomain = 0
        dnsx_wildcards = 0

        # Phase 8 counters (initialised for every target type)
        cloud_buckets_found = 0
        js_analysis_endpoints = 0
        secrets_found = 0
        oast_interactions = 0
        tech_routing_findings = 0
        wpscan_findings = 0
        js_analysis_files: List[Dict[str, Any]] = []
        graphql_urls: List[str] = []

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
            phase1_started = time.monotonic()
            discovered_subdomains: List[str] = []
            event_queue: asyncio.Queue = asyncio.Queue()

            async def run_passive(provider: BaseProvider, label: str) -> None:
                logger.info("[*] Launching passive provider: %s", label)
                count = 0
                provider_timeout_s = 600 if label == "amass" else 300
                try:
                    async def _run():
                        nonlocal count
                        async for event in provider.discover(seed_domains):
                            if event.get("type") == "asset":
                                raw = event["data"].get("domain", "")
                                norm = _normalise(raw)
                                if _is_valid(norm):
                                    await event_queue.put(("asset", norm, label))
                                    discovered_subdomains.append(norm)
                                    count += 1
                            elif event.get("type") == "log":
                                await event_queue.put(("log", event.get("message", ""), label))
                            elif event.get("type") in ("stage_error", "stage_skipped", "stage_timeout", "warning_event"):
                                await event_queue.put(("event", event, label))

                    await asyncio.wait_for(_run(), timeout=provider_timeout_s)
                except asyncio.TimeoutError:
                    warn_t = f"[!] Tool '{label}' timed out after {provider_timeout_s}s; keeping {count} partial results."
                    logger.warning(warn_t)
                    await event_queue.put(("log", warn_t, label))
                    await event_queue.put(("stage_timeout", label, warn_t))
                except (asyncio.CancelledError, KeyboardInterrupt):
                    logger.warning(f"[-] {label} was killed/cancelled.")
                    await event_queue.put(("stage_killed", label, f"{label} killed"))
                    raise
                except Exception as exc:
                    err = f"[-] {label} failed: {exc}"
                    logger.error(err)
                    await event_queue.put(("provider_error", label, str(exc)))
                finally:
                    provider_counts[label] = count
                    if count == 0:
                        warn_zero = f"[!] Tool '{label}' returned 0 results, possible failure/timeout"
                        logger.warning(warn_zero)
                        await event_queue.put(("log", warn_zero, label))
                        await event_queue.put(("warning_event", label, "returned 0 results, possible failure/timeout"))
                    logger.info("[+] %s finished → %s raw subdomains", label, count)
                    await event_queue.put(("provider_done", label, count))

            tasks = []
            missing_passive = []
            for p, lbl in self.PASSIVE_PROVIDERS:
                if not is_available(lbl):
                    missing_passive.append(lbl)
                    yield {"type": "log", "message": f"[!] Tool '{lbl}' is not installed in WSL. Skipping."}
                    yield {
                        "type": "stage_skipped",
                        "stage": f"Passive Discovery ({lbl})",
                        "tool": lbl,
                        "reason": f"tool_missing: {lbl}",
                    }
                    yield {
                        "type": "scan_summary",
                        "provider": lbl,
                        "status": "SKIPPED",
                        "count": 0,
                    }
                    provider_counts[lbl] = 0
                else:
                    tasks.append(asyncio.create_task(run_passive(p, lbl)))

            # If ALL passive tools are missing, emit a clear warning event naming them
            if len(missing_passive) == len(self.PASSIVE_PROVIDERS):
                names_str = ", ".join(missing_passive)
                warn_msg = f"[!] WARNING: All passive discovery tools ({names_str}) are missing or uninstalled. Proceeding directly with seed root domain(s)."
                logger.warning(warn_msg)
                yield {"type": "log", "message": warn_msg}
                yield {
                    "type": "warning_event",
                    "warning": "all_passive_tools_missing",
                    "missing_tools": missing_passive,
                    "message": warn_msg,
                }

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
                elif kind == "log":
                    _, msg, label = item
                    yield {"type": "log", "message": msg}
                elif kind == "event":
                    _, ev, label = item
                    yield ev
                elif kind == "warning_event":
                    _, label, msg = item
                    yield {
                        "type": "warning_event",
                        "stage": label,
                        "tool": label,
                        "message": f"[!] Tool '{label}' returned 0 results, possible failure/timeout",
                    }
                elif kind == "stage_timeout":
                    _, label, reason = item
                    yield {
                        "type": "stage_timeout",
                        "stage": f"Passive Discovery ({label})",
                        "tool": label,
                        "reason": reason,
                    }
                elif kind == "stage_killed":
                    _, label, reason = item
                    yield {
                        "type": "stage_error",
                        "stage": f"Passive Discovery ({label})",
                        "tool": label,
                        "reason": f"tool_killed: {reason}",
                        "message": reason,
                    }
                elif kind == "provider_error":
                    _, label, error = item
                    yield {
                        "type": "stage_error",
                        "stage": f"Passive Discovery ({label})",
                        "tool": label,
                        "message": f"[-] {label} encountered an error: {error}",
                    }
                    yield {
                        "type": "log",
                        "message": f"[-] {label} encountered an error: {error}",
                    }

            await asyncio.gather(*tasks, return_exceptions=True)

            # ALWAYS include the seed root domain in the target list after Phase 1 (subject to the scope check)
            for s in seed_domains:
                if _is_valid(s):
                    discovered_subdomains.append(s)
                    yield {
                        "type": "asset",
                        "data": {
                            "domain": s,
                            "type": "subdomain",
                            "status": "unknown",
                            "open_ports": [],
                            "metadata": {"source": "seed_domain"},
                            "discovered_by": "Unified Discovery",
                            "sources": ["seed"],
                        },
                    }

            # Global deduplication after Phase 1
            unique_subdomains = sorted(set(discovered_subdomains))
            total_unique = len(unique_subdomains)

            phase1_summary = (
                f"\n[√] Passive Discovery complete.\n"
                f"    Subfinder   : {provider_counts.get('subfinder', 0)}\n"
                f"    Assetfinder : {provider_counts.get('assetfinder', 0)}\n"
                f"    Chaos       : {provider_counts.get('chaos', 0)}\n"
                f"    Amass       : {provider_counts.get('amass', 0)}\n"
                f"    crt.sh      : {provider_counts.get('crtsh', 0)}\n"
                f"    CertSpotter : {provider_counts.get('certspotter', 0)}\n"
                f"    ─────────────────────────\n"
                f"    Total Unique : {total_unique}"
            )
            logger.info(phase1_summary)
            yield {"type": "log", "message": phase1_summary}
            yield timing("passive_discovery", phase1_started)

            if not unique_subdomains:
                yield {"type": "log", "message": "[*] No subdomains discovered. Aborting pipeline."}
                yield {
                    "type": "scan_summary",
                    "provider_counts": provider_counts,
                    "total_unique": 0,
                    "live_hosts": 0,
                }
                return

            # Apply scope filter after Phase 1 merge (before DNS Brute Force / DNSx)
            unique_subdomains, scope_events = check_and_filter_scope(unique_subdomains, "Phase 1: Passive Discovery Merge")
            for ev in scope_events:
                yield ev
            if not unique_subdomains:
                yield {"type": "log", "message": "[*] All subdomains were filtered out of scope after Phase 1. Aborting pipeline."}
                yield {
                    "type": "scan_summary",
                    "provider_counts": provider_counts,
                    "total_unique": 0,
                    "live_hosts": 0,
                }
                return

            # ================================================================
            # PHASE 1.5: DNS Brute Force + Permutations (switch-gated)
            # ================================================================
            if not dns_bruteforce_enabled:
                yield {
                    "type": "stage_skipped",
                    "stage": "DNS Brute Force & Permutations",
                    "tool": "puredns",
                    "reason": "switch: dns_bruteforce disabled",
                }
                yield {"type": "log", "message": "[!] DNS Brute Force & Permutations disabled by project switch."}
            else:
                dns_bf_started = time.monotonic()
                yield {"type": "log", "message": "========== DNS Brute Force & Permutations =========="}
                dns_bf_provider = DnsBruteforceProvider(
                    wordlist_path=(project_config.get("wordlists") or {}).get("dns_bruteforce"),
                    resolvers_path=(project_config.get("wordlists") or {}).get("resolvers"),
                    max_permutations=int(project_config.get("max_permutations") or 50000),
                    rate_limit=get_tool_rl("dns_bruteforce"),
                    scope_config=scope_config,
                )
                async for event in self._capped_events(
                    lambda: dns_bf_provider.run_bruteforce(seed_domains, unique_subdomains),
                    "dns_bruteforce",
                    "dns_bruteforce",
                    phase_time_cap(phase_switches, "dns_bruteforce"),
                ):
                    if event.get("type") == "asset":
                        cand_d = (event.get("data") or {}).get("domain")
                        if cand_d and cand_d not in unique_subdomains:
                            unique_subdomains.append(cand_d)
                    yield event

                # Re-apply scope filter after brute force additions
                unique_subdomains, bf_scope_events = check_and_filter_scope(unique_subdomains, "Phase 1.5: DNS Brute Force Merge")
                for ev in bf_scope_events:
                    yield ev
                yield timing("dns_bruteforce", dns_bf_started)

            # ================================================================
            # PHASE 2: DNS Resolution (DNSx)
            # ================================================================
            dns_resolution_started = time.monotonic()
            dns_resolution_executed = False

            # Requirement 4: Validate hostnames before DNS
            valid_subdomains_before_dns = []
            for sub in unique_subdomains:
                is_val, val_reason = validate_hostname(sub)
                if is_val:
                    valid_subdomains_before_dns.append(sub)
                else:
                    yield {"type": "log", "message": f"[-] Invalid hostname dropped before DNS: {sub} ({val_reason})"}
            unique_subdomains = valid_subdomains_before_dns

            resolved_subdomains: List[str] = []
            dns_cnames: Dict[str, List[str]] = {}

            if not is_available("dnsx"):
                yield {"type": "log", "message": "[!] Tool 'dnsx' is not installed in WSL. Skipping DNS resolution."}
                yield {
                    "type": "stage_skipped",
                    "stage": "DNS Resolution (dnsx)",
                    "tool": "dnsx",
                    "reason": "tool_missing: dnsx",
                }
                yield {
                    "type": "scan_summary",
                    "provider": "dnsx",
                    "status": "SKIPPED",
                    "count": 0,
                }
                resolved_subdomains = list(unique_subdomains)
            else:
                dns_resolution_executed = True
                dnsx_provider = DnsxProvider()
                async for event in self._run_phase(dnsx_provider, unique_subdomains, "DNSx Resolution"):
                    if event.get("type") == "asset":
                        asset = event.get("data") or {}
                        if asset.get("status") in ("resolved", "live"):
                            domain_norm = _normalise(asset.get("domain", ""))
                            cnames = ((asset.get("metadata") or {}).get("dns") or {}).get("cname", [])
                            if cnames:
                                dns_cnames[domain_norm] = cnames

                            # Requirement 3: After DNS resolution, ALWAYS drop hosts whose IPs
                            # are loopback, RFC1918, link-local, CGNAT or cloud-metadata ranges,
                            # regardless of scope config, and log the reason.
                            resolved_ip = asset.get("resolved_ip")
                            is_disallowed, bad_reason = is_disallowed_ip(resolved_ip)
                            if is_disallowed:
                                drop_msg = f"[-] Dropped host '{domain_norm}': resolved IP {resolved_ip} in disallowed range ({bad_reason})"
                                logger.warning(drop_msg)
                                yield {"type": "log", "message": drop_msg}
                                continue

                            # Verify resolved IP against scope rules (CIDR/IP out-of-scope check)
                            if resolved_ip and not is_ip_in_scope(resolved_ip, scope_config):
                                drop_msg = f"[-] Scope Filter: Dropping '{domain_norm}' (resolved IP {resolved_ip} is out of scope)"
                                logger.info(drop_msg)
                                yield {"type": "log", "message": drop_msg}
                                yield {
                                    "type": "scope_filtered",
                                    "stage": "Phase 2: DNSx IP Scope Check",
                                    "dropped_count": 1,
                                    "kept_count": len(resolved_subdomains),
                                    "samples": [f"{domain_norm} ({resolved_ip})"],
                                }
                                continue
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
                    abort_msg = "[-] DNS resolution yielded no resolvable hosts. Aborting pipeline."
                    logger.warning(abort_msg)
                    yield {"type": "log", "message": abort_msg}
                    yield {
                        "type": "scan_summary",
                        "provider": "dnsx",
                        "status": "completed",
                        "reason": "no_resolvable_hosts",
                        "live_hosts": 0,
                    }
                    return

            unique_resolved = sorted(set(resolved_subdomains))
            # Scope filter after DNSx
            unique_resolved, scope_events = check_and_filter_scope(unique_resolved, "Phase 2: DNS Resolution")
            for ev in scope_events:
                yield ev
            yield {
                "type": "log",
                "message": f"[√] DNSx: {len(unique_resolved)} resolved subdomains ready.",
            }
            if dns_resolution_executed:
                yield timing("dns_resolution", dns_resolution_started)

            # ================================================================
            # OPT-IN: Root Domain Expansion (Suggestions only)
            # ================================================================
            enable_root_exp = bool((project_config or {}).get("enable_root_expansion", False))
            if enable_root_exp:
                yield {"type": "log", "message": "========== Root Domain Expansion (Opt-in) =========="}
                root_exp = RootExpansionProvider(
                    project_id=str((project_config or {}).get("project_id") or ""),
                    known_seeds=seed_domains,
                )
                async for event in root_exp.expand_roots(seed_domains, []):
                    yield event
            else:
                yield {
                    "type": "stage_skipped",
                    "stage": "Root Expansion",
                    "reason": "opt_in_disabled",
                }

            # ================================================================
            # SUB-PHASE 2B: Cloud Bucket Enumeration (Phase 8.3, opt-in, deep only)
            # ================================================================
            cloud_provider = CloudEnumProvider()
            async for event in cloud_provider.enumerate(
                seed_domains,
                scan_mode=scan_mode,
                project_config=project_config,
                scope=scope_config,
            ):
                if event.get("type") == "scan_summary" and event.get("provider") == "cloud_enum":
                    cloud_buckets_found = event.get("count", 0)
                yield event

            # ================================================================
            # PHASE 3: Subdomain Takeover Cross-Check (Subzy + Nuclei + dnsReaper)
            # ================================================================
            takeover_started = time.monotonic()
            if unique_resolved:
                takeover_checker = TakeoverCrossCheckProvider(cnames_map=dns_cnames)
                async for event in takeover_checker.check_takeovers(unique_resolved):
                    if event.get("type") == "scan_summary" and event.get("provider") == "takeover_crosscheck":
                        subzy_vulnerable = event.get("vulnerable", 0)
                    yield event

                yield {
                    "type": "scan_summary",
                    "provider": "subzy",
                    "status": "completed",
                    "count": subzy_vulnerable,
                }
                yield {"type": "log", "message": "[√] Provider subzy completed"}
                yield timing("takeover_crosscheck", takeover_started)
            else:
                yield {
                    "type": "stage_skipped",
                    "stage": "Subdomain Takeover Cross-Check",
                    "tool": "subzy",
                    "reason": "no_eligible_hosts",
                }
                yield {"type": "scan_summary", "provider": "subzy", "status": "SKIPPED", "count": 0, "reason": "no_eligible_hosts"}

        # ================================================================
        # PHASE 4: Port Scanning (Naabu)
        #   Baseline is always top-1000; the wide switch upgrades to port_range.
        # ================================================================
        port_scan_started = time.monotonic()

        naabu_hosts_with_ports = 0
        naabu_open_ports = 0
        
        skip_naabu = is_new_path and target_type in ("URL", "HOST_PORT")

        if skip_naabu:
            yield {"type": "log", "message": "Skipping Port Scanning (Naabu)"}
            yield {
                "type": "stage_skipped",
                "stage": "Port Scanning (naabu)",
                "tool": "naabu",
                "reason": "no_eligible_targets",
            }
            yield {
                "type": "scan_summary",
                "provider": "naabu",
                "status": "SKIPPED",
                "reason": "no_eligible_targets",
            }
            yield {"type": "log", "message": "[!] Provider naabu skipped"}
        elif not is_available("naabu"):
            yield {"type": "log", "message": "[!] Tool 'naabu' is not installed in WSL. Skipping port scan."}
            yield {
                "type": "stage_skipped",
                "stage": "Port Scanning (naabu)",
                "tool": "naabu",
                "reason": "tool_missing: naabu",
            }
            yield {
                "type": "scan_summary",
                "provider": "naabu",
                "status": "SKIPPED",
                "count": 0,
                "reason": "tool_missing: naabu",
            }
            yield {"type": "log", "message": "[!] Provider naabu skipped"}
        else:
            # Filter scope before Naabu
            unique_resolved, scope_events = check_and_filter_scope(unique_resolved, "Phase 4: Naabu Port Scan")
            for ev in scope_events:
                yield ev

            # Identify hosts behind CDNs to exclude from wide port scans
            cdn_excluded_hosts = {}
            if wide_port_scan_enabled:
                for h, cnames in dns_cnames.items():
                    cname_str = " ".join(cnames).lower()
                    for cdn_name, pattern in [
                        ("Cloudflare", "cloudflare"),
                        ("CloudFront", "cloudfront"),
                        ("Akamai", "akamai"),
                        ("Fastly", "fastly"),
                        ("Imperva", "incap"),
                        ("Sucuri", "sucuri"),
                    ]:
                        if pattern in cname_str:
                            cdn_excluded_hosts[h] = f"Host has {cdn_name} CNAME ({cnames[0]}) - wide port scan skipped to protect IP reputation"
                            break

            if unique_resolved:
                naabu_provider = NaabuProvider()
                async for event in self._run_phase(
                    naabu_provider,
                    unique_resolved,
                    "Naabu Port Scan",
                    time_cap_seconds=phase_time_cap(phase_switches, "wide_port_scan") if wide_port_scan_enabled else None,
                    tool_name="naabu",
                    rate_limit=get_tool_rl("naabu"),
                    scan_mode="deep" if wide_port_scan_enabled else "fast",
                    port_range=project_config.get("port_range") if wide_port_scan_enabled else None,
                    cdn_excluded_hosts=cdn_excluded_hosts,
                    nmap_options=project_config.get("nmap_options"),
                ):
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
                yield timing("port_scanning", port_scan_started)
            else:
                yield {"type": "log", "message": "[*] No targets in scope for Naabu."}
                yield {
                    "type": "stage_skipped",
                    "stage": "Port Scanning (naabu)",
                    "tool": "naabu",
                    "reason": "no_eligible_targets",
                }
                yield {"type": "scan_summary", "provider": "naabu", "status": "SKIPPED", "count": 0, "reason": "no_eligible_targets"}

        # ================================================================
        # PHASE 5: HTTP Probing (HTTPX)
        # ================================================================
        http_probing_started = time.monotonic()

        live_hosts = 0
        live_host_targets: List[str] = []
        live_host_urls: List[str] = []
        host_to_live_url: Dict[str, str] = {}
        host_to_urls: Dict[str, List[str]] = defaultdict(list)
        all_live_assets: List[Dict[str, Any]] = []

        # Scope filter before HTTPX
        unique_resolved, scope_events = check_and_filter_scope(unique_resolved, "Phase 5: HTTPX Probing")
        for ev in scope_events:
            yield ev

        target_label = "targets" if is_new_path else "resolved subdomains"
        httpx_start_msg = (
            f"\n========== HTTPX Probing ==========\n"
            f"[*] Launching HTTPX on {len(unique_resolved)} {target_label}..."
        )
        logger.info(httpx_start_msg)
        yield {"type": "log", "message": httpx_start_msg}

        from app.job_control import check_job_status
        await check_job_status()

        http_probing_executed = False
        if not unique_resolved:
            yield {"type": "log", "message": "[*] No in-scope targets for HTTP probing."}
            yield {
                "type": "stage_skipped",
                "stage": "HTTP Probing (httpx)",
                "tool": "httpx",
                "reason": "no_eligible_targets",
            }
            yield {
                "type": "scan_summary",
                "provider": "httpx",
                "status": "SKIPPED",
                "count": 0,
                "reason": "no_eligible_targets",
            }
            yield {"type": "log", "message": "[!] Provider httpx skipped"}
        elif not is_available("httpx"):
            yield {"type": "log", "message": "[!] Tool 'httpx' is not installed in WSL. Skipping HTTP probing."}
            yield {
                "type": "stage_skipped",
                "stage": "HTTP Probing (httpx)",
                "tool": "httpx",
                "reason": "tool_missing: httpx",
            }
            yield {
                "type": "scan_summary",
                "provider": "httpx",
                "status": "SKIPPED",
                "count": 0,
                "reason": "tool_missing: httpx",
            }
            yield {"type": "log", "message": "[!] Provider httpx skipped"}
        else:
            http_probing_executed = True
            httpx_provider = HttpxProvider()
            try:
                async for event in httpx_provider.discover(
                    unique_resolved,
                    rate_limit=get_tool_rl("httpx"),
                    custom_headers=custom_headers_cfg,
                    scope=scope_config,
                    project_id=(project_config or {}).get("project_id"),
                    response_body_max_kb=int((project_config or {}).get("response_body_max_kb") or 500),
                ):
                    event_type = event.get("type")
                    if event_type == "asset":
                        asset = event.get("data") or {}
                        meta = asset.get("metadata") or {}
                        final_url = meta.get("url")
                        redirect_target = meta.get("redirect_location")
                        domain_raw = asset.get("domain", "")
                        if scope_config and (
                            (final_url and not is_in_scope(final_url, scope_config))
                            or (domain_raw and not is_in_scope(domain_raw, scope_config))
                            or (redirect_target and not is_in_scope(redirect_target, scope_config))
                        ):
                            logger.info(f"[*] Dropping out-of-scope HTTPX redirect asset: {domain_raw} -> {final_url}")
                            continue

                        if asset.get("status") == "live":
                            live_hosts += 1
                            domain_norm = _normalise(domain_raw)
                            live_host_targets.append(domain_norm)
                            resolved_url = final_url if final_url else f"http://{domain_raw}"
                            host_to_live_url[domain_norm] = resolved_url
                            live_host_urls.append(resolved_url)
                            all_live_assets.append(asset)
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

        if http_probing_executed:
            yield timing("http_probing", http_probing_started)

        # ================================================================
        # PHASE 5B: Host Clustering & WAF Detection
        # ================================================================
        yield {"type": "log", "message": f"\n========== Host Clustering & WAF Analysis =========="}

        from app.services.clustering import cluster_live_hosts
        from app.providers.wafw00f_provider import Wafw00fProvider

        clustering_cfg = (project_config or {}).get("clustering") or {}
        scan_all_members = bool(clustering_cfg.get("scan_all_cluster_members", False))

        cluster_res = cluster_live_hosts(all_live_assets, scan_all_members=scan_all_members)

        yield {
            "type": "cluster_summary",
            "provider": "clustering",
            "total_hosts": cluster_res["summary"]["total_hosts"],
            "cluster_count": cluster_res["summary"]["cluster_count"],
            "representative_count": cluster_res["summary"]["representative_count"],
            "skipped_member_count": cluster_res["summary"]["skipped_member_count"],
            "scan_all_members_enabled": scan_all_members,
        }

        # Yield updated asset events for cluster members that have skip reasons so UI displays them
        for skipped in cluster_res["skipped_members"]:
            yield {"type": "asset", "data": skipped}
            yield {
                "type": "log",
                "message": f"[*] [Cluster Member] {skipped.get('domain')} marked duplicate of '{skipped.get('cluster_representative_host')}'. Heavy probing skipped."
            }

        rep_domains = {r.get("domain") for r in cluster_res["representatives"] if r.get("domain")}
        if not scan_all_members and cluster_res["skipped_members"]:
            yield {
                "type": "log",
                "message": (
                    f"[*] Clustering active: {len(rep_domains)} representative host(s) selected for deep crawling/probing. "
                    f"{len(cluster_res['skipped_members'])} duplicate host(s) skipped from heavy scans "
                    f"(Toggle 'Scan All Cluster Members' to scan all)."
                ),
            }

        # WAF Detection & Rate reduction tracking
        waf_detected_hosts = set()
        for a in all_live_assets:
            if not a:
                continue
            if (a.get("cdn_waf") or {}).get("is_waf"):
                if a.get("domain"):
                    waf_detected_hosts.add(a.get("domain"))

        if is_available("wafw00f"):
            wafw00f_targets = [u for u in live_host_urls if any(d in u for d in rep_domains)][:15]
            if wafw00f_targets:
                waf_provider = Wafw00fProvider()
                async for event in self._run_phase(waf_provider, wafw00f_targets, "WAF Detection (wafw00f)"):
                    if not event or not isinstance(event, dict):
                        continue
                    if event.get("type") == "asset":
                        waf_data = event.get("data") or {}
                        if waf_data.get("domain"):
                            waf_detected_hosts.add(waf_data["domain"])
                    yield event
        else:
            yield {"type": "stage_skipped", "stage": "WAF Detection (wafw00f)", "tool": "wafw00f", "reason": "tool_missing: wafw00f"}
            yield {"type": "log", "message": "[!] Tool 'wafw00f' is not installed in WSL. Skipping WAF fingerprinting."}

        # All in-scope live hosts are used automatically for crawling, content,
        # parameter, port and screenshot phases. Clustering still provides
        # metadata, but no longer restricts tool targets.
        active_candidate_hosts = live_host_targets

        unique_live_hosts = sorted({h for h in active_candidate_hosts if _is_valid(h)})
        unique_live_urls = sorted({host_to_live_url[h] for h in unique_live_hosts if h in host_to_live_url})

        # ================================================================
        # SUB-PHASE 5B: Priority Content & API Discovery (FFUF + API Surface)
        # ================================================================
        all_ffuf_urls: List[str] = []
        all_api_spec_urls: List[str] = []
        ffuf_paths_discovered = 0
        api_specs_discovered = 0
        graphql_endpoints_discovered = 0

        # FFUF and API probes run automatically on every in-scope live host.
        priority_targets = [
            host_to_live_url[h]
            for h in sorted(set(live_host_targets))
            if h in host_to_live_url
        ]
        priority_targets, scope_ev_p = check_and_filter_scope(priority_targets, "Sub-phase 5B: Content/API Discovery")
        for ev in scope_ev_p:
            yield ev

        if priority_targets:
            # 1. FFUF Content Discovery (switch-gated)
            if not ffuf_enabled:
                yield {
                    "type": "stage_skipped",
                    "stage": "Content Discovery (ffuf)",
                    "tool": "ffuf",
                    "reason": "switch: ffuf disabled",
                }
                yield {"type": "log", "message": "[!] FFUF content discovery disabled by project switch."}
                yield {"type": "scan_summary", "provider": "ffuf", "status": "SKIPPED", "count": 0}
            elif not is_available("ffuf") and not is_available("feroxbuster"):
                yield {"type": "log", "message": "[!] Tool 'ffuf' / 'feroxbuster' is not installed in WSL. Skipping content discovery."}
                yield {"type": "stage_skipped", "stage": "Content Discovery (ffuf)", "tool": "ffuf", "reason": "tool_missing: ffuf"}
                yield {"type": "scan_summary", "provider": "ffuf", "status": "SKIPPED", "count": 0}
            else:
                content_discovery_started = time.monotonic()
                ffuf_prov = FfufProvider()
                detected_tech_map = {
                    (a or {}).get("domain"): ((a or {}).get("metadata") or {}).get("technologies") or ((a or {}).get("metadata") or {}).get("tech") or []
                    for a in all_live_assets if a
                }
                wl_cfg = project_config.get("wordlists") or {}
                custom_wl = wl_cfg.get("content") or wl_cfg.get("ffuf")
                ffuf_options = dict(project_config.get("ffuf_options") or {})
                ffuf_options["enabled"] = True
                async for event in self._run_phase(
                    ffuf_prov,
                    priority_targets,
                    "FFUF Content Discovery",
                    time_cap_seconds=phase_time_cap(phase_switches, "ffuf"),
                    tool_name="ffuf",
                    scan_mode="fast",
                    rate_limit=get_tool_rl("ffuf"),
                    custom_headers=custom_headers_cfg,
                    scope=scope_config,
                    wordlist_path=custom_wl,
                    waf_detected_hosts=waf_detected_hosts,
                    detected_tech_per_host=detected_tech_map,
                    ffuf_options=ffuf_options,
                ):
                    if not event or not isinstance(event, dict):
                        continue
                    if event.get("type") == "content_path_event":
                        u = (event.get("data") or {}).get("url")
                        if u:
                            all_ffuf_urls.append(u)
                    elif event.get("type") == "scan_summary" and event.get("provider") == "ffuf":
                        ffuf_paths_discovered = event.get("count", 0)
                    yield event
                yield timing("content_discovery", content_discovery_started)

            # 2. API Surface & GraphQL Probing
            api_prov = ApiSurfaceProvider()
            async for event in self._run_phase(
                api_prov,
                priority_targets,
                "API Surface & GraphQL Detection",
                custom_headers=custom_headers_cfg,
                scope=scope_config,
            ):
                if not event or not isinstance(event, dict):
                    continue
                if event.get("type") == "url_event" and (event.get("data") or {}).get("source") == "api_spec":
                    u = (event.get("data") or {}).get("url")
                    if u:
                        all_api_spec_urls.append(u)
                elif event.get("type") == "api_spec_event":
                    api_specs_discovered += 1
                elif event.get("type") == "graphql_event":
                    graphql_endpoints_discovered += 1
                    gql_url = (event.get("data") or {}).get("url")
                    if gql_url:
                        graphql_urls.append(gql_url)
                yield event
        else:
            yield {"type": "log", "message": "[*] No priority targets for FFUF / API surface probing."}
            yield {"type": "scan_summary", "provider": "ffuf", "status": "SKIPPED", "count": 0, "reason": "no_priority_targets"}
            yield {"type": "scan_summary", "provider": "api_surface", "status": "SKIPPED", "count": 0, "reason": "no_priority_targets"}

        # Store response bodies for the live content/API hits we just found.
        # Bounded and filtered by status/content type; failures are non-fatal.
        if (all_ffuf_urls or all_api_spec_urls) and project_config.get("project_id"):
            body_urls = list(dict.fromkeys([*all_ffuf_urls, *all_api_spec_urls]))
            if body_urls:
                auto_limit = max(1, min(int(project_config.get("body_storage_auto_limit") or 30), 100))
                yield {
                    "type": "log",
                    "message": f"[*] Fetching response bodies for up to {auto_limit} discovered content/API URL(s)...",
                }
                try:
                    from app.services.body_fetch import auto_store_bodies

                    store_res = await auto_store_bodies(
                        str(project_config.get("project_id")),
                        body_urls,
                        scope=scope_config,
                        max_kb=int(project_config.get("response_body_max_kb") or 500),
                        limit=auto_limit,
                        concurrency=3,
                        timeout=12,
                    )
                    yield {
                        "type": "log",
                        "message": (
                            f"[+] Body storage: {store_res.get('stored', 0)} stored, "
                            f"{store_res.get('skipped', 0)} skipped, "
                            f"{store_res.get('failed', 0)} failed "
                            f"(of {store_res.get('requested', 0)})."
                        ),
                    }
                except Exception as body_exc:
                    logger.error("[-] Automatic body storage failed: %s", body_exc)
                    yield {
                        "type": "log",
                        "message": f"[!] Automatic body storage failed: {body_exc} (non-fatal)",
                    }

        # Scope filter before crawlers
        unique_live_hosts, scope_ev_h = check_and_filter_scope(unique_live_hosts, "Phase 6: Crawlers (Hosts)")
        for ev in scope_ev_h:
            yield ev
        unique_live_urls, scope_ev_u = check_and_filter_scope(unique_live_urls, "Phase 6: Crawlers (URLs)")
        for ev in scope_ev_u:
            yield ev

        tasks = []
        event_queue = asyncio.Queue()
        all_katana_urls: List[str] = []
        all_gau_urls: List[str] = []
        all_waymore_urls: List[str] = []
        all_js_files: List[str] = []
        katana_hosts_scanned = 0
        katana_urls_discovered = 0
        gowitness_screenshots = 0

        async def run_worker(
            provider: BaseProvider,
            target_list: List[str],
            label: str,
            time_cap_seconds: Optional[int] = None,
            **kwargs: Any,
        ) -> None:
            try:
                if time_cap_seconds:
                    async for ev in self._capped_events(
                        lambda: provider.discover(target_list, **kwargs),
                        label,
                        label,
                        time_cap_seconds,
                    ):
                        await event_queue.put((label, ev))
                else:
                    async for ev in provider.discover(target_list, **kwargs):
                        await event_queue.put((label, ev))
            except Exception as exc:
                logger.error(f"[-] {label} worker failed: {exc}")
                await event_queue.put((label, {"type": "log", "message": f"[-] {label} worker failed: {exc}"}))
            finally:
                await event_queue.put((label, "__done__"))

        crawlers_started = time.monotonic()

        if unique_live_urls:
            # Katana
            if not is_available("katana"):
                yield {"type": "log", "message": "[!] Tool 'katana' is not installed in WSL. Skipping web crawl."}
                yield {"type": "stage_skipped", "stage": "Web Crawling (katana)", "tool": "katana", "reason": "tool_missing: katana"}
                yield {"type": "scan_summary", "provider": "katana", "status": "SKIPPED", "count": 0}
            else:
                tasks.append(asyncio.create_task(run_worker(
                    KatanaProvider(),
                    unique_live_urls,
                    "katana",
                    rate_limit=get_tool_rl("katana"),
                    custom_headers=custom_headers_cfg,
                    scope=scope_config,
                )))

            # GAU
            if not is_available("gau"):
                yield {"type": "log", "message": "[!] Tool 'gau' is not installed in WSL. Skipping historical URLs."}
                yield {"type": "stage_skipped", "stage": "Historical URLs (gau)", "tool": "gau", "reason": "tool_missing: gau"}
                yield {"type": "scan_summary", "provider": "gau", "status": "SKIPPED", "count": 0}
            else:
                tasks.append(asyncio.create_task(run_worker(GauProvider(), unique_live_hosts, "gau")))

            # Waymore (optional historical supplement to GAU, switch-gated)
            if not waymore_enabled:
                yield {"type": "log", "message": "[!] Waymore supplement disabled by project switch."}
                yield {"type": "stage_skipped", "stage": "Historical URLs (waymore)", "tool": "waymore", "reason": "switch: waymore disabled"}
                yield {"type": "scan_summary", "provider": "waymore", "status": "SKIPPED", "count": 0}
            elif not is_available("waymore"):
                yield {"type": "log", "message": "[!] Tool 'waymore' is not installed in WSL. Skipping Waymore supplement."}
                yield {"type": "stage_skipped", "stage": "Historical URLs (waymore)", "tool": "waymore", "reason": "tool_missing: waymore"}
                yield {"type": "scan_summary", "provider": "waymore", "status": "SKIPPED", "count": 0}
            else:
                tasks.append(asyncio.create_task(run_worker(
                    WaymoreProvider(),
                    unique_live_hosts,
                    "waymore",
                    time_cap_seconds=phase_time_cap(phase_switches, "waymore"),
                    scope=scope_config,
                    project_id=project_config.get("project_id"),
                )))

            # SubJS
            if not is_available("subjs"):
                yield {"type": "log", "message": "[!] Tool 'subjs' is not installed in WSL. Skipping JS discovery."}
                yield {"type": "stage_skipped", "stage": "JS Discovery (subjs)", "tool": "subjs", "reason": "tool_missing: subjs"}
                yield {"type": "scan_summary", "provider": "subjs", "status": "SKIPPED", "count": 0}
            else:
                tasks.append(asyncio.create_task(run_worker(SubjsProvider(), unique_live_urls, "subjs")))
        else:
            yield {"type": "log", "message": "[*] No live HTTPX targets; skipping concurrent crawlers."}
            for p in ("katana", "gau", "waymore", "subjs"):
                yield {"type": "scan_summary", "provider": p, "status": "SKIPPED", "reason": "no_live_hosts"}
                yield {"type": "log", "message": f"[!] Provider {p} skipped"}

        crawlers_executed = len(tasks) > 0
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
                elif label == "waymore":
                    yield {
                        "type": "scan_summary",
                        "provider": "waymore",
                        "status": "completed",
                        "count": len(all_waymore_urls)
                    }
                    yield {"type": "log", "message": "[√] Provider waymore completed"}
                elif label == "subjs":
                    yield {
                        "type": "scan_summary",
                        "provider": "subjs",
                        "status": "completed",
                        "count": len(all_js_files)
                    }
                    yield {"type": "log", "message": "[√] Provider subjs completed"}
                continue

            # Store result lists and pass-through standard events
            if event.get("type") == "asset" and label == "katana":
                asset_data = event.get("data") or {}
                k_meta = (asset_data.get("metadata") or {}).get("katana") or {}
                k_urls = k_meta.get("urls", [])
                all_katana_urls.extend(k_urls)
                k_js = k_meta.get("js_files", [])
                all_js_files.extend(k_js)
            elif event.get("type") == "url_event" and label == "gau":
                u = (event.get("data") or {}).get("url")
                if u:
                    all_gau_urls.append(u)
            elif event.get("type") == "url_event" and label == "waymore":
                u = (event.get("data") or {}).get("url")
                if u:
                    all_waymore_urls.append(u)
            elif event.get("type") == "js_event" and label == "subjs":
                u = (event.get("data") or {}).get("url")
                if u:
                    all_js_files.append(u)

            if event.get("type") == "scan_summary":
                if label == "katana":
                    katana_hosts_scanned = event.get("hosts_scanned", 0)
                    katana_urls_discovered = event.get("urls_discovered", 0)

            yield event

        await asyncio.gather(*tasks, return_exceptions=True)
        if crawlers_executed:
            yield timing("crawlers", crawlers_started)

        # ================================================================
        # PHASE 6B: JS Analysis (Phase 8.1)
        #   SHA-256 hashing + source maps + jsluice/xnLinkFinder (LinkFinder fallback)
        # ================================================================
        all_linkfinder_urls: List[str] = []
        js_endpoint_parents: List[Tuple[str, str]] = []
        linkfinder_endpoints = 0
        js_analysis_started = time.monotonic()

        # Deduplicate and scope-filter JavaScript URLs before analysis.
        all_js_files = list(dict.fromkeys(u.strip() for u in all_js_files if u and u.strip()))
        all_js_files, scope_ev_js = check_and_filter_scope(all_js_files, "Phase 6B: JS Analysis")
        for ev in scope_ev_js:
            yield ev

        js_analysis_executed = bool(all_js_files) and bool(
            (phase8_cfg.get("js_analysis") or {}).get("enabled", True)
        )

        if all_js_files:
            js_provider = JsAnalysisProvider()
            async for event in js_provider.analyze(
                all_js_files,
                scan_mode=scan_mode,
                rate_limit=get_tool_rl("httpx"),
                custom_headers=custom_headers_cfg,
                project_config=project_config,
                scope=scope_config,
            ):
                if not event or not isinstance(event, dict):
                    continue
                etype = event.get("type")
                if etype == "url_event":
                    e_data = event.get("data") or {}
                    endpoint_url = e_data.get("url")
                    source = e_data.get("source")
                    if endpoint_url and source in ("js_analysis", "linkfinder", "jsluice", "xnlinkfinder"):
                        all_linkfinder_urls.append(endpoint_url)
                        try:
                            js_source_host = (
                                urlparse(str(e_data.get("js_file") or "")).hostname or ""
                            ).lower()
                        except Exception:
                            js_source_host = ""
                        if js_source_host:
                            js_endpoint_parents.append((endpoint_url, js_source_host))
                    yield event
                elif etype == "js_event":
                    jd = event.get("data") or {}
                    if jd.get("body_path"):
                        js_analysis_files.append({
                            "path": jd.get("body_path"),
                            "url": jd.get("url") or "",
                            "host": jd.get("host") or "",
                            "source": jd.get("kind") or "js",
                        })
                    yield event
                elif etype == "scan_summary" and event.get("provider") == "js_analysis":
                    js_analysis_endpoints = event.get("endpoints_extracted", js_analysis_endpoints)
                    yield event
                else:
                    yield event
            linkfinder_endpoints = js_analysis_endpoints
        else:
            yield {"type": "log", "message": "[*] No JS files discovered; skipping JS analysis."}
            yield {"type": "scan_summary", "provider": "js_analysis", "status": "SKIPPED", "count": 0, "reason": "no_js_urls"}
            yield {"type": "scan_summary", "provider": "linkfinder", "status": "SKIPPED", "count": 0, "extracted_endpoints": 0}
            yield {"type": "log", "message": "[!] Provider js_analysis skipped"}
        if js_analysis_executed:
            yield timing("js_analysis", js_analysis_started)

        # ================================================================
        # PHASE 7: URL Merge Engine & Normalisation
        # ================================================================
        url_merge_started = time.monotonic()
        yield {"type": "log", "message": "\n========== URL Merge Engine =========="}
        
        merged_urls = merge_urls(
            all_katana_urls,
            all_gau_urls,
            all_linkfinder_urls,
            scan_mode=scan_mode,
            per_host_cap=(project_config or {}).get("per_host_url_cap"),
            waymore_urls=all_waymore_urls,
            ffuf_urls=all_ffuf_urls,
            api_spec_urls=all_api_spec_urls,
        )
        
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
        
        # Scope filter before Uro
        merged_raw_list, scope_ev_uro = check_and_filter_scope(merged_raw_list, "Phase 7: Uro Input URLs")
        for ev in scope_ev_uro:
            yield ev

        uro_normalised_urls: List[str] = []
        uro_removed = 0

        if merged_raw_list:
            if not is_available("uro"):
                yield {"type": "log", "message": "[!] Tool 'uro' is not installed in WSL. Skipping URL normalisation."}
                yield {"type": "stage_skipped", "stage": "URL Normalisation (uro)", "tool": "uro", "reason": "tool_missing: uro"}
                yield {"type": "scan_summary", "provider": "uro", "status": "SKIPPED", "count": 0}
                yield {"type": "log", "message": "[!] Provider uro skipped"}
                uro_normalised_urls = list(dict.fromkeys(merged_raw_list))
            else:
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
            yield {"type": "scan_summary", "provider": "uro", "status": "SKIPPED", "reason": "no_urls"}
            yield {"type": "log", "message": "[!] Provider uro skipped"}

        if not uro_normalised_urls and merged_raw_list:
            uro_normalised_urls = list(dict.fromkeys(merged_raw_list))
        if merged_raw_list:
            yield timing("url_merge", url_merge_started)

        # ================================================================
        # HISTORICAL URL PROBING (HTTPX -mc 200,301,302,401,403)
        # ================================================================
        all_historical_raw = set(all_gau_urls) | set(all_waymore_urls)
        live_crawled_raw = set(all_katana_urls) | set(all_ffuf_urls) | set(all_api_spec_urls) | set(all_linkfinder_urls)
        historical_to_probe = [u for u in uro_normalised_urls if u in all_historical_raw and u not in live_crawled_raw]

        if historical_to_probe:
            dead_historical_urls = set()
            httpx_probe_prov = HttpxProvider()
            try:
                async for ev in httpx_probe_prov.probe_historical_urls(
                    historical_to_probe,
                    live_hosts=set(live_host_targets),
                    rate_limit=get_tool_rl("httpx"),
                    custom_headers=custom_headers_cfg,
                ):
                    if ev.get("type") == "historical_probe_event":
                        p_data = ev.get("data", {})
                        if p_data.get("status") == "historical_dead":
                            dead_historical_urls.add(p_data.get("url"))
                    yield ev
            except Exception as h_exc:
                logger.error(f"[-] Historical URL probing failed: {h_exc}")
                yield {"type": "log", "message": f"[-] Historical URL probing failed: {h_exc} (non-fatal)"}

            # Filter dead historical URLs out of downstream scans
            uro_normalised_urls = [u for u in uro_normalised_urls if u not in dead_historical_urls]

        # ================================================================
        # CLOUD URL CLASSIFICATION
        #   Detects S3/R2/GCS/Azure storage, CloudFront, EC2, App Engine,
        #   Cloud Run, Azure App Service, etc. in the discovered URL set.
        # ================================================================
        cloud_screenshot_urls: List[str] = []
        project_id_value = str(project_config.get("project_id") or "")
        if project_id_value:
            cloud_parents: Dict[str, set] = {}

            def note_cloud_url(candidate_url: Any, parent_host: str = "") -> None:
                url = str(candidate_url or "").strip()
                if not url:
                    return
                cloud_parents.setdefault(url, set())
                if parent_host:
                    cloud_parents[url].add(parent_host.lower())

            for live_asset in all_live_assets:
                if not live_asset:
                    continue
                live_host = str(live_asset.get("domain") or "").lower()
                katana_meta = (live_asset.get("metadata") or {}).get("katana") or {}
                for key in ("urls", "endpoints", "js_files"):
                    for candidate in katana_meta.get(key) or []:
                        note_cloud_url(candidate, live_host)
            for endpoint_url, parent_host in js_endpoint_parents:
                note_cloud_url(endpoint_url, parent_host)
            for candidate in uro_normalised_urls:
                note_cloud_url(candidate)

            try:
                from app.services.cloud_classify import classify_and_store

                cloud_res = await classify_and_store(
                    project_id_value,
                    cloud_parents,
                    limit=1000,
                )
                if cloud_res.get("total"):
                    provider_str = ", ".join(
                        f"{provider}:{count}"
                        for provider, count in sorted(
                            (cloud_res.get("by_provider") or {}).items()
                        )
                    )
                    yield {
                        "type": "log",
                        "message": (
                            f"[+] Cloud URL classification: {cloud_res.get('total')} "
                            f"cloud resource URL(s) detected"
                            + (f" ({provider_str})" if provider_str else "")
                            + "."
                        ),
                    }
                    import os as _os
                    from app.providers.url_merge import SCREENSHOT_SKIP_EXTENSIONS

                    cloud_screenshot_urls = [
                        url
                        for url in cloud_res.get("urls") or []
                        if _os.path.splitext(urlparse(url).path.lower())[1]
                        not in SCREENSHOT_SKIP_EXTENSIONS
                    ][:25]
            except Exception as cloud_exc:
                logger.error("[-] Cloud URL classification failed: %s", cloud_exc)
                yield {
                    "type": "log",
                    "message": f"[!] Cloud URL classification failed: {cloud_exc} (non-fatal)",
                }

            try:
                from app.services.api_classify import classify_api_and_store

                api_res = await classify_api_and_store(
                    project_id_value,
                    cloud_parents,
                    limit=2000,
                )
                if api_res.get("total"):
                    type_str = ", ".join(
                        f"{api_type}:{count}"
                        for api_type, count in sorted(
                            (api_res.get("by_type") or {}).items()
                        )
                    )
                    yield {
                        "type": "log",
                        "message": (
                            f"[+] API endpoint classification: {api_res.get('total')} "
                            f"API URL(s) detected"
                            + (f" ({type_str})" if type_str else "")
                            + "."
                        ),
                    }
            except Exception as api_exc:
                logger.error("[-] API URL classification failed: %s", api_exc)
                yield {
                    "type": "log",
                    "message": f"[!] API URL classification failed: {api_exc} (non-fatal)",
                }

        # ================================================================
        # PHASE 7D: Visual Verification (GoWitness)
        #   Runs after URL merge/uro so screenshots cover the highest-value
        #   live URLs, not only the live host roots captured by HTTPX.
        # ================================================================
        screenshot_started = time.monotonic()
        screenshot_executed = False
        if not screenshots_enabled:
            yield {"type": "log", "message": "[!] GoWitness screenshots disabled by project switch."}
            yield {"type": "stage_skipped", "stage": "Screenshots (gowitness)", "tool": "gowitness", "reason": "switch: screenshots disabled"}
            yield {"type": "scan_summary", "provider": "gowitness", "status": "SKIPPED", "count": 0}
        elif not is_available("gowitness"):
            yield {"type": "log", "message": "[!] Tool 'gowitness' is not installed in WSL. Skipping screenshots."}
            yield {"type": "stage_skipped", "stage": "Screenshots (gowitness)", "tool": "gowitness", "reason": "tool_missing: gowitness"}
            yield {"type": "scan_summary", "provider": "gowitness", "status": "SKIPPED", "count": 0}
        else:
            screenshot_cfg = project_config.get("screenshot_options") or {}
            try:
                screenshot_max_urls = max(1, min(int(screenshot_cfg.get("max_urls", 50) or 50), 500))
            except (TypeError, ValueError):
                screenshot_max_urls = 50
            try:
                screenshot_max_per_host = max(0, min(int(screenshot_cfg.get("max_urls_per_host", 5)), 50))
            except (TypeError, ValueError):
                screenshot_max_per_host = 5

            # Cloud service URLs are treated as guaranteed roots so their
            # screenshots are captured even when the normal per-host cap
            # would otherwise drop them.
            screenshot_roots = list(dict.fromkeys(
                [*unique_live_urls, *cloud_screenshot_urls]
            ))
            screenshot_targets = select_screenshot_targets(
                screenshot_roots,
                uro_normalised_urls,
                max_urls=screenshot_max_urls,
                max_per_host_extras=screenshot_max_per_host,
            )
            screenshot_targets, scope_ev_shot = check_and_filter_scope(
                screenshot_targets, "Phase 7D: Screenshots"
            )
            for ev in scope_ev_shot:
                yield ev

            if not screenshot_targets:
                yield {"type": "log", "message": "[*] No live URLs available; skipping screenshots."}
                yield {
                    "type": "scan_summary",
                    "provider": "gowitness",
                    "status": "SKIPPED",
                    "reason": "no_live_hosts_upstream",
                    "count": 0,
                }
            else:
                screenshot_executed = True
                live_url_set = set(unique_live_urls)
                root_count = sum(1 for u in screenshot_targets if u in live_url_set)
                yield {
                    "type": "log",
                    "message": (
                        f"[*] Screenshot scope: {len(screenshot_targets)} URL(s) "
                        f"({root_count} live host root(s), "
                        f"{len(screenshot_targets) - root_count} prioritized URL(s))."
                    ),
                }
                page_hashes: Dict[str, str] = {}
                for live_asset in all_live_assets:
                    if not live_asset:
                        continue
                    live_meta = live_asset.get("metadata") or {}
                    live_hash = live_meta.get("body_hash") or (live_asset.get("fingerprint") or {}).get("body_hash")
                    if not live_hash:
                        continue
                    live_host = str(live_asset.get("domain") or "").lower()
                    live_url = str(live_meta.get("url") or "")
                    if live_host:
                        page_hashes[live_host] = live_hash
                    if live_url:
                        page_hashes[live_url] = live_hash
                async for event in self._run_phase(
                    GowitnessProvider(),
                    screenshot_targets,
                    "Screenshots (GoWitness)",
                    time_cap_seconds=phase_time_cap(phase_switches, "screenshots"),
                    tool_name="gowitness",
                    project_id=project_config.get("project_id"),
                    rate_limit=get_tool_rl("gowitness"),
                    per_url_timeout=int(screenshot_cfg.get("per_url_timeout_seconds", 60) or 60),
                    concurrency=int(screenshot_cfg.get("concurrency", 3) or 3),
                    page_hashes=page_hashes,
                ):
                    if event.get("type") == "scan_summary" and event.get("provider") == "gowitness":
                        gowitness_screenshots = event.get("screenshots", event.get("count", 0)) or 0
                    yield event
        if screenshot_executed:
            yield timing("screenshots", screenshot_started)

        # ================================================================
        # PHASE 7C: Secret Scanning (Phase 8.2)
        #   Scans only stored in-scope response/JS bodies; values are masked.
        # ================================================================
        secrets_provider = SecretsProvider()
        async for event in secrets_provider.scan(
            seed_domains,
            scan_mode=scan_mode,
            project_config=project_config,
            extra_files=js_analysis_files,
            scope=scope_config,
        ):
            if event.get("type") == "scan_summary" and event.get("provider") == "secrets":
                secrets_found = event.get("count", 0)
            yield event

        # ================================================================
        # SUB-PHASE 6C: Parameter Discovery (Arjun / x8 - switch-gated)
        # ================================================================
        all_param_urls: List[str] = []
        params_discovered = 0
        if not param_discovery_enabled:
            yield {"type": "log", "message": "[!] Parameter discovery disabled by project switch."}
            yield {"type": "stage_skipped", "stage": "Parameter Discovery (arjun)", "tool": "arjun", "reason": "switch: param_discovery disabled"}
            yield {"type": "scan_summary", "provider": "arjun", "status": "SKIPPED", "count": 0}
        elif uro_normalised_urls:
            param_discovery_started = time.monotonic()
            from app.providers.url_merge import get_url_priority
            sorted_candidates = sorted(
                uro_normalised_urls,
                key=lambda u: (get_url_priority(u), len(u), u)
            )
            param_targets = sorted_candidates[:25]
            param_targets, scope_ev_param = check_and_filter_scope(param_targets, "Sub-phase 6C: Parameter Discovery")
            for ev in scope_ev_param:
                yield ev

            param_executed = False
            if is_available("arjun") or is_available("x8"):
                param_executed = True
                param_provider = ParamDiscoveryProvider()
                async for event in self._run_phase(
                    param_provider,
                    param_targets,
                    "Parameter Discovery",
                    time_cap_seconds=phase_time_cap(phase_switches, "param_discovery"),
                    tool_name="arjun",
                    rate_limit=get_tool_rl("arjun"),
                    custom_headers=custom_headers_cfg,
                    scope=scope_config,
                ):
                    if not event or not isinstance(event, dict):
                        continue
                    if event.get("type") == "url_event" and (event.get("data") or {}).get("source") == "param_discovery":
                        param_u = (event.get("data") or {}).get("url")
                        if param_u:
                            all_param_urls.append(param_u)
                    elif event.get("type") == "scan_summary" and event.get("provider") in ("arjun", "x8"):
                        params_discovered = event.get("count", 0)
                    yield event

                # Append discovered parameterized URLs for GF and vulnerability scanners
                for pu in all_param_urls:
                    if pu not in uro_normalised_urls:
                        uro_normalised_urls.append(pu)
            else:
                yield {"type": "log", "message": "[!] Tool 'arjun' / 'x8' is not installed in WSL. Skipping parameter discovery."}
                yield {"type": "stage_skipped", "stage": "Parameter Discovery (arjun)", "tool": "arjun", "reason": "tool_missing: arjun"}
                yield {"type": "scan_summary", "provider": "arjun", "status": "SKIPPED", "count": 0}
            if param_executed:
                yield timing("param_discovery", param_discovery_started)
        else:
            yield {
                "type": "stage_skipped",
                "stage": "Parameter Discovery (arjun)",
                "tool": "arjun",
                "reason": "no_eligible_urls",
            }
            yield {"type": "scan_summary", "provider": "arjun", "status": "SKIPPED", "count": 0, "reason": "no_eligible_urls"}

        # ================================================================
        # PHASE 8: URL Classification (GF)
        # ================================================================
        gf_started = time.monotonic()
        gf_executed = False
        gf_classified = 0
        ENDPOINT_SCAN_CATEGORIES = {"xss", "sqli", "ssrf", "lfi", "ssti", "idor", "redirect", "rce"}
        gf_endpoint_urls: List[str] = []
        gf_seen_endpoint_urls: set = set()
        
        gf_xss_urls: List[str] = []
        gf_redirect_urls: List[str] = []

        if uro_normalised_urls:
            if not is_available("gf"):
                yield {"type": "log", "message": "[!] Tool 'gf' is not installed in WSL. Skipping URL classification."}
                yield {"type": "stage_skipped", "stage": "URL Classification (gf)", "tool": "gf", "reason": "tool_missing: gf"}
                yield {"type": "scan_summary", "provider": "gf", "status": "SKIPPED", "count": 0}
                yield {"type": "log", "message": "[!] Provider gf skipped"}
                gf_endpoint_urls = list(uro_normalised_urls)
            else:
                gf_executed = True
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
            yield {"type": "scan_summary", "provider": "gf", "status": "SKIPPED", "reason": "no_urls"}
            yield {"type": "log", "message": "[!] Provider gf skipped"}
        if gf_executed:
            yield timing("gf", gf_started)

        # ================================================================
        # PHASE 9: Concurrent Vulnerability Scans (Nuclei, Dalfox, OpenRedirex)
        # ================================================================
        vuln_scan_started = time.monotonic()
        yield {"type": "log", "message": "\n========== Vulnerability Scanning =========="}
        
        nuclei_host_findings = 0
        nuclei_endpoint_findings = 0
        dalfox_findings = 0
        openredirex_findings = 0
        
        host_scan_targets: List[str] = list(dict.fromkeys(unique_live_urls)) if unique_live_urls else []
        
        # Scope filters before Phase 9 active scans
        host_scan_targets, scope_ev_h = check_and_filter_scope(host_scan_targets, "Phase 9: Nuclei Host Targets")
        for ev in scope_ev_h:
            yield ev
        gf_endpoint_urls, scope_ev_e = check_and_filter_scope(gf_endpoint_urls, "Phase 9: Nuclei Endpoint Targets")
        for ev in scope_ev_e:
            yield ev
        gf_xss_urls, scope_ev_x = check_and_filter_scope(gf_xss_urls, "Phase 9: Dalfox Targets")
        for ev in scope_ev_x:
            yield ev
        gf_redirect_urls, scope_ev_r = check_and_filter_scope(gf_redirect_urls, "Phase 9: OpenRedirex Targets")
        for ev in scope_ev_r:
            yield ev

        # ================================================================
        # PHASE 9A: Nuclei options, template maintenance & optional OAST
        # ================================================================
        nuclei_options = phase8_cfg.get("nuclei_options") or {}
        auto_scan_enabled = bool(nuclei_options.get("auto_scan", False))
        template_dir = str(nuclei_options.get("custom_templates_dir") or "").strip()
        if template_dir and platform.system().lower() == "windows" and re.match(r"^[A-Za-z]:[\\/]", template_dir):
            try:
                template_dir = BaseProvider.wsl_path_convert(template_dir)
            except Exception:
                pass

        oast_cfg = phase8_cfg.get("oast") or {}
        oast_session: Optional[OASTSession] = None
        oast_server = str(oast_cfg.get("server") or "").strip()
        if "://" in oast_server:
            oast_server = urlparse(oast_server).netloc
        oast_token = str(oast_cfg.get("token") or "")
        oast_callback_url = ""

        if scan_profile != "recon" and bool(oast_cfg.get("enabled", False)):
            interactsh_path = OASTSession.resolve_tool()
            if not interactsh_path:
                yield {"type": "log", "message": "[!] OAST enabled but interactsh-client is not installed. Continuing without blind callbacks."}
                yield {
                    "type": "stage_skipped",
                    "stage": "OAST (interactsh)",
                    "tool": "interactsh",
                    "reason": "tool_missing: interactsh",
                }
            else:
                oast_session = OASTSession(oast_cfg, interactsh_path)
                started = await oast_session.start(
                    startup_timeout=int(oast_cfg.get("startup_timeout_seconds", 20) or 20)
                )
                if started and oast_session.enabled:
                    oast_callback_url = oast_session.oast_url
                    if not oast_server and oast_session.server:
                        oast_server = oast_session.server
                    yield {
                        "type": "log",
                        "message": (
                            f"[*] OAST active: callback domain {oast_session.domain}. "
                            f"Dalfox -b enabled; Nuclei -iserver " + (oast_server or "default") + "."
                        ),
                    }
                    yield {"type": "scan_summary", "provider": "oast", "status": "started", "domain": oast_session.domain}
                else:
                    yield {"type": "log", "message": "[-] OAST client did not produce a callback domain; continuing without blind callbacks (non-fatal)."}
                    oast_session.stop()
                    oast_session = None
        elif scan_profile == "recon":
            yield {
                "type": "stage_skipped",
                "stage": "OAST (interactsh)",
                "tool": "interactsh",
                "reason": "profile: recon",
            }
        else:
            yield {"type": "log", "message": "[*] OAST disabled for this project."}

        if scan_profile != "recon" and bool(nuclei_options.get("update_templates", False)):
            if is_tool_available("nuclei"):
                async for event in NucleiProvider().update_templates():
                    yield event
            else:
                yield {
                    "type": "stage_skipped",
                    "stage": "Nuclei Template Update",
                    "tool": "nuclei",
                    "reason": "tool_missing: nuclei",
                }

        scan_queue = asyncio.Queue()
        
        async def run_scanner(provider_func, targets, label, time_cap_seconds=None, **kwargs):
            from app.job_control import current_phase, kill_phase_processes
            phase_label = f"scanner:{label}"

            async def _run():
                token = current_phase.set(phase_label)
                try:
                    async for event in provider_func(targets, **kwargs):
                        await scan_queue.put((label, event))
                finally:
                    current_phase.reset(token)

            task = asyncio.create_task(_run())
            try:
                if time_cap_seconds:
                    _, pending = await asyncio.wait({task}, timeout=time_cap_seconds)
                    if task in pending:
                        killed = kill_phase_processes(phase_label)
                        task.cancel()
                        await asyncio.gather(task, return_exceptions=True)
                        reason = f"time cap ({time_cap_seconds}s) exceeded; killed {killed} process(es)"
                        await scan_queue.put((label, {
                            "type": "stage_timeout",
                            "stage": phase_label,
                            "tool": label,
                            "reason": reason,
                        }))
                else:
                    await task
            except Exception as exc:
                logger.error(f"Concurrent scanner {label} failed: {exc}", exc_info=True)
                await scan_queue.put((label, {"type": "log", "message": f"[-] Scanner {label} failed: {exc}"}))
            finally:
                if not task.done():
                    task.cancel()
                    await asyncio.gather(task, return_exceptions=True)
                await scan_queue.put((label, "__done__"))

        scan_tasks = []

        # Per-phase switch + scan profile both gate active scanners.
        if not active_scanners_enabled:
            if scan_profile == "recon":
                skip_reason = "profile: recon"
                yield {"type": "log", "message": "[*] Scan profile: 'recon' active. Skipping active vulnerability passes (Nuclei Host, Nuclei Endpoint, Dalfox, OpenRedirex)."}
            else:
                skip_reason = "switch: active_scanners disabled"
                yield {"type": "log", "message": "[*] Active scanners disabled by project switch (Nuclei, Dalfox, OpenRedirex)."}
            for stage_name, tool_name in (
                ("Host Vulnerability Scan (nuclei)", "nuclei_host"),
                ("Endpoint Vulnerability Scan (nuclei)", "nuclei_endpoint"),
                ("XSS Scanning (dalfox)", "dalfox"),
                ("Open Redirect Scanning (openredirex)", "openredirex"),
            ):
                yield {
                    "type": "stage_skipped",
                    "stage": stage_name,
                    "tool": tool_name,
                    "reason": skip_reason,
                }
                yield {"type": "log", "message": f"[!] Provider {tool_name} skipped ({skip_reason})"}
            for provider_label in ("nuclei_host", "nuclei_endpoint", "dalfox", "openredirex"):
                yield {
                    "type": "scan_summary",
                    "provider": provider_label,
                    "status": "SKIPPED",
                    "count": 0,
                    "reason": skip_reason,
                }
        elif scan_profile == "recon":
            yield {"type": "log", "message": "[*] Scan profile: 'recon' active. Skipping active vulnerability passes (Nuclei Host, Nuclei Endpoint, Dalfox, OpenRedirex)."}
            yield {
                "type": "stage_skipped",
                "stage": "Host Vulnerability Scan (nuclei)",
                "tool": "nuclei_host",
                "reason": "profile: recon",
            }
            yield {
                "type": "stage_skipped",
                "stage": "Endpoint Vulnerability Scan (nuclei)",
                "tool": "nuclei_endpoint",
                "reason": "profile: recon",
            }
            yield {
                "type": "stage_skipped",
                "stage": "XSS Scanning (dalfox)",
                "tool": "dalfox",
                "reason": "profile: recon",
            }
            yield {
                "type": "stage_skipped",
                "stage": "Open Redirect Scanning (openredirex)",
                "tool": "openredirex",
                "reason": "profile: recon",
            }
            yield {"type": "scan_summary", "provider": "nuclei_host", "status": "SKIPPED", "count": 0, "reason": "profile: recon"}
            yield {"type": "scan_summary", "provider": "nuclei_endpoint", "status": "SKIPPED", "count": 0, "reason": "profile: recon"}
            yield {"type": "scan_summary", "provider": "dalfox", "status": "SKIPPED", "count": 0, "reason": "profile: recon"}
            yield {"type": "scan_summary", "provider": "openredirex", "status": "SKIPPED", "count": 0, "reason": "profile: recon"}
            yield {"type": "log", "message": "[!] Provider nuclei_host skipped (profile: recon)"}
            yield {"type": "log", "message": "[!] Provider nuclei_endpoint skipped (profile: recon)"}
            yield {"type": "log", "message": "[!] Provider dalfox skipped (profile: recon)"}
            yield {"type": "log", "message": "[!] Provider openredirex skipped (profile: recon)"}
        else:
            # Profile: "recon_validation" (Runs active vulnerability validation)
            # Nuclei Scans
            if not is_available("nuclei"):
                yield {"type": "log", "message": "[!] Tool 'nuclei' is not installed in WSL. Skipping vulnerability scans."}
                yield {"type": "stage_skipped", "stage": "Host Vulnerability Scan (nuclei)", "tool": "nuclei", "reason": "tool_missing: nuclei"}
                yield {"type": "stage_skipped", "stage": "Endpoint Vulnerability Scan (nuclei)", "tool": "nuclei", "reason": "tool_missing: nuclei"}
                yield {"type": "scan_summary", "provider": "nuclei_host", "status": "SKIPPED", "count": 0}
                yield {"type": "scan_summary", "provider": "nuclei_endpoint", "status": "SKIPPED", "count": 0}
                yield {"type": "log", "message": "[!] Provider nuclei_host skipped"}
                yield {"type": "log", "message": "[!] Provider nuclei_endpoint skipped"}
            else:
                # Auto-reduce rate limit for WAF-protected targets
                nuclei_rl = min(get_tool_rl("nuclei"), 5) if waf_detected_hosts else get_tool_rl("nuclei")
                if waf_detected_hosts:
                    yield {"type": "log", "message": f"[*] WAF protection detected on targets. Auto-reducing Nuclei rate limit to {nuclei_rl} rps."}

                if host_scan_targets:
                    scan_tasks.append(asyncio.create_task(run_scanner(
                        NucleiProvider().discover_host_scan,
                        host_scan_targets,
                        "nuclei_host",
                        time_cap_seconds=phase_time_cap(phase_switches, "active_scanners"),
                        rate_limit=nuclei_rl,
                        custom_headers=custom_headers_cfg,
                        oast_server=oast_server or None,
                        oast_token=oast_token or None,
                        template_dir=template_dir or None,
                        auto_scan=auto_scan_enabled,
                    )))
                else:
                    yield {"type": "scan_summary", "provider": "nuclei_host", "status": "SKIPPED"}
                    yield {"type": "log", "message": "[!] Provider nuclei_host skipped"}

                if gf_endpoint_urls:
                    scan_tasks.append(asyncio.create_task(run_scanner(
                        NucleiProvider().discover_endpoint_scan,
                        gf_endpoint_urls,
                        "nuclei_endpoint",
                        time_cap_seconds=phase_time_cap(phase_switches, "active_scanners"),
                        rate_limit=nuclei_rl,
                        custom_headers=custom_headers_cfg,
                        oast_server=oast_server or None,
                        oast_token=oast_token or None,
                        template_dir=template_dir or None,
                    )))
                else:
                    yield {"type": "scan_summary", "provider": "nuclei_endpoint", "status": "SKIPPED"}
                    yield {"type": "log", "message": "[!] Provider nuclei_endpoint skipped"}
                
            if active_scanners_enabled:
                # Dalfox
                dalfox_rl = min(get_tool_rl("dalfox"), 5) if waf_detected_hosts else get_tool_rl("dalfox")
                if not is_available("dalfox"):
                    yield {"type": "log", "message": "[!] Tool 'dalfox' is not installed in WSL. Skipping Dalfox scan."}
                    yield {"type": "stage_skipped", "stage": "XSS Scanning (dalfox)", "tool": "dalfox", "reason": "tool_missing: dalfox"}
                    yield {"type": "scan_summary", "provider": "dalfox", "status": "SKIPPED", "count": 0}
                    yield {"type": "log", "message": "[!] Provider dalfox skipped"}
                elif gf_xss_urls:
                    scan_tasks.append(asyncio.create_task(run_scanner(
                        DalfoxProvider().discover,
                        gf_xss_urls,
                        "dalfox",
                        time_cap_seconds=phase_time_cap(phase_switches, "active_scanners"),
                        rate_limit=dalfox_rl,
                        custom_headers=custom_headers_cfg,
                        oast_url=oast_callback_url or None,
                    )))
                else:
                    yield {"type": "log", "message": "[*] No GF XSS URLs found; skipping Dalfox."}
                    yield {"type": "scan_summary", "provider": "dalfox", "status": "SKIPPED"}
                    yield {"type": "log", "message": "[!] Provider dalfox skipped"}
                    
                # OpenRedirex
                if not is_available("openredirex"):
                    yield {"type": "log", "message": "[!] Tool 'openredirex' is not installed in WSL. Skipping OpenRedirex scan."}
                    yield {"type": "stage_skipped", "stage": "Open Redirect Scanning (openredirex)", "tool": "openredirex", "reason": "tool_missing: openredirex"}
                    yield {"type": "scan_summary", "provider": "openredirex", "status": "SKIPPED", "count": 0}
                    yield {"type": "log", "message": "[!] Provider openredirex skipped"}
                elif gf_redirect_urls:
                    scan_tasks.append(asyncio.create_task(run_scanner(
                        OpenredirexProvider().discover,
                        gf_redirect_urls,
                        "openredirex",
                        time_cap_seconds=phase_time_cap(phase_switches, "active_scanners"),
                        rate_limit=get_tool_rl("openredirex"),
                        custom_headers=custom_headers_cfg,
                    )))
                else:
                    yield {"type": "log", "message": "[*] No GF Redirect URLs found; skipping OpenRedirex."}
                    yield {"type": "scan_summary", "provider": "openredirex", "status": "SKIPPED"}
                    yield {"type": "log", "message": "[!] Provider openredirex skipped"}
            else:
                yield {"type": "scan_summary", "provider": "dalfox", "status": "SKIPPED"}
                yield {"type": "log", "message": "[!] Provider dalfox skipped"}
                yield {"type": "scan_summary", "provider": "openredirex", "status": "SKIPPED"}
                yield {"type": "log", "message": "[!] Provider openredirex skipped"}

        vuln_scan_executed = len(scan_tasks) > 0
        active_scanners = len(scan_tasks)
        oast_candidate_hosts = {str(h or "").strip().lower() for h in live_host_targets if h}
        oast_candidate_hosts.update(
            (urlparse(u).hostname or "").lower() for u in gf_xss_urls if u
        )
        oast_candidate_hosts.discard("")

        while active_scanners > 0 or not scan_queue.empty():
            # Drain correlated OAST interactions while scanners are running.
            if oast_session:
                for interaction in oast_session.drain_interactions():
                    oast_event = OASTSession.interaction_to_finding(
                        interaction, scope_config, oast_candidate_hosts
                    )
                    if oast_event:
                        oast_interactions += 1
                        yield oast_event
                    else:
                        logger.info("[oast] Ignored uncorrelated/out-of-scope interaction")
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

        # Final OAST drain + shutdown
        if oast_session:
            for interaction in oast_session.drain_interactions():
                oast_event = OASTSession.interaction_to_finding(
                    interaction, scope_config, oast_candidate_hosts
                )
                if oast_event:
                    oast_interactions += 1
                    yield oast_event
                else:
                    logger.info("[oast] Ignored uncorrelated/out-of-scope interaction")
            oast_session.stop()
            oast_session = None
            yield {
                "type": "scan_summary",
                "provider": "oast",
                "status": "completed",
                "count": oast_interactions,
            }
        if vuln_scan_executed:
            yield timing("vulnerability_scan", vuln_scan_started)

        # ================================================================
        # PHASE 9B: Tech-Aware Routing (Phase 8.6)
        # ================================================================
        tech_routing_started = time.monotonic()
        tech_routing_executed = False
        tech_routing_cfg = phase8_cfg.get("tech_routing") or {}
        if active_scanners_enabled and scan_profile != "recon" and bool(tech_routing_cfg.get("enabled", True)):
            max_per_tech = int(tech_routing_cfg.get("max_hosts_per_tech", 25) or 25)
            tech_targets: Dict[str, List[str]] = defaultdict(list)
            wordpress_urls: List[str] = []

            for asset in all_live_assets:
                if not asset:
                    continue
                host_key = (asset.get("domain") or "").lower().strip()
                asset_url = (asset.get("metadata") or {}).get("url") or host_to_live_url.get(host_key) or ""
                if not host_key or not asset_url:
                    continue
                if scope_config and not is_in_scope(asset_url, scope_config):
                    continue
                techs_raw = ((asset.get("metadata") or {}).get("technologies")
                             or (asset.get("metadata") or {}).get("tech") or [])
                if isinstance(techs_raw, str):
                    techs_raw = [techs_raw]
                tech_blob = " ".join(str(t) for t in techs_raw).lower()
                for tech_key, tag in TECH_TAG_MAP.items():
                    if tech_key in tech_blob:
                        if len(tech_targets[tag]) < max_per_tech and asset_url not in tech_targets[tag]:
                            tech_targets[tag].append(asset_url)
                if "wordpress" in tech_blob and asset_url not in wordpress_urls:
                    wordpress_urls.append(asset_url)

            for gql_url in graphql_urls:
                if not gql_url or (scope_config and not is_in_scope(gql_url, scope_config)):
                    continue
                parsed_gql = urlparse(gql_url)
                gql_base = f"{parsed_gql.scheme}://{parsed_gql.netloc}" if parsed_gql.netloc else gql_url
                if len(tech_targets["graphql"]) < max_per_tech and gql_base not in tech_targets["graphql"]:
                    tech_targets["graphql"].append(gql_base)

            if tech_targets:
                if is_tool_available("nuclei"):
                    tech_routing_executed = True
                    tech_nuclei = NucleiProvider()
                    async for event in self._capped_events(
                        lambda: tech_nuclei.discover_tech_scan(
                            dict(tech_targets),
                            rate_limit=get_tool_rl("nuclei"),
                            custom_headers=custom_headers_cfg,
                            oast_server=oast_server or None,
                            oast_token=oast_token or None,
                            template_dir=template_dir or None,
                            auto_scan=auto_scan_enabled,
                        ),
                        "tech_routing",
                        "nuclei",
                        phase_time_cap(phase_switches, "active_scanners"),
                    ):
                        if event.get("type") == "scan_summary" and event.get("provider") == "nuclei_tech":
                            tech_routing_findings = event.get("count", 0)
                        yield event
                else:
                    yield {
                        "type": "stage_skipped",
                        "stage": "Tech-Aware Routing (nuclei tags)",
                        "tool": "nuclei",
                        "reason": "tool_missing: nuclei",
                    }
            else:
                yield {"type": "log", "message": "[*] Tech-aware routing: no matching technologies detected."}
                yield {"type": "scan_summary", "provider": "nuclei_tech", "status": "SKIPPED", "count": 0, "reason": "no_tech_targets"}

            if wordpress_urls:
                tech_routing_executed = True
                wp_provider = WpscanProvider()
                async for event in self._capped_events(
                    lambda: wp_provider.scan(
                        wordpress_urls[:max_per_tech],
                        rate_limit=get_tool_rl("nuclei"),
                        max_hosts=max_per_tech,
                        project_config=project_config,
                    ),
                    "tech_routing",
                    "wpscan",
                    phase_time_cap(phase_switches, "active_scanners"),
                ):
                    if event.get("type") == "scan_summary" and event.get("provider") == "wpscan":
                        wpscan_findings = event.get("count", 0)
                    yield event
        else:
            if scan_profile == "recon":
                reason = "profile: recon"
            elif not active_scanners_enabled:
                reason = "switch: active_scanners disabled"
            else:
                reason = "disabled"
            yield {
                "type": "stage_skipped",
                "stage": "Tech-Aware Routing (nuclei tags)",
                "tool": "nuclei",
                "reason": reason,
            }
            yield {
                "type": "stage_skipped",
                "stage": "Tech Routing (wpscan)",
                "tool": "wpscan",
                "reason": reason,
            }
        if tech_routing_executed:
            yield timing("tech_routing", tech_routing_started)

        nuclei_findings_count = nuclei_host_findings + nuclei_endpoint_findings
        total_security_findings = (
            nuclei_findings_count + dalfox_findings + openredirex_findings
            + tech_routing_findings + wpscan_findings + oast_interactions
        )

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
            f"    FFUF Content Paths : {ffuf_paths_discovered}\n"
            f"    API Specs Found    : {api_specs_discovered}\n"
            f"    GraphQL Endpoints  : {graphql_endpoints_discovered}\n"
            f"    Discovered Params  : {params_discovered}\n"
            f"    Naabu Open Ports   : {naabu_open_ports} across {naabu_hosts_with_ports} hosts\n"
            f"    Katana URLs        : {katana_urls_discovered} (crawled {katana_hosts_scanned} hosts)\n"
            f"    GAU Historical URLs: {len(all_gau_urls)}\n"
            f"    Waymore Hist. URLs : {len(all_waymore_urls)}\n"
            f"    SubJS JS Files     : {len(all_js_files)}\n"
            f"    JS Analysis Endpts : {js_analysis_endpoints} (files hashed: {len(js_analysis_files)})\n"
            f"    Secret Candidates  : {secrets_found}\n"
            f"    Cloud Buckets      : {cloud_buckets_found}\n"
            f"    GoWitness Screenpts: {gowitness_screenshots}\n"
            f"    Uro Normalised URLs: {len(uro_normalised_urls)} (removed {uro_removed})\n"
            f"    GF Matches         : {gf_classified} | Endpoint targets: {len(gf_endpoint_urls)}\n"
            f"    Nuclei Findings    : {nuclei_findings_count} (Host: {nuclei_host_findings}, Endpoint: {nuclei_endpoint_findings})\n"
            f"    Tech Routing Finds : {tech_routing_findings} (WPScan: {wpscan_findings})\n"
            f"    OAST Interactions  : {oast_interactions}\n"
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
            "ffuf_paths_discovered":       ffuf_paths_discovered,
            "api_specs_discovered":        api_specs_discovered,
            "graphql_endpoints_discovered": graphql_endpoints_discovered,
            "params_discovered":           params_discovered,
            "naabu_hosts_with_open_ports": naabu_hosts_with_ports,
            "naabu_open_ports":            naabu_open_ports,
            "katana_hosts_scanned":        katana_hosts_scanned,
            "katana_urls_discovered":      katana_urls_discovered,
            "historical_urls":             len(all_gau_urls),
            "waymore_urls":                len(all_waymore_urls),
            "js_files":                    len(all_js_files),
            "js_files_hashed":             len(js_analysis_files),
            "js_analysis_endpoints":       js_analysis_endpoints,
            "extracted_endpoints":         linkfinder_endpoints,
            "secret_candidates":           secrets_found,
            "cloud_buckets_found":         cloud_buckets_found,
            "oast_interactions":           oast_interactions,
            "tech_routing_findings":       tech_routing_findings,
            "wpscan_findings":             wpscan_findings,
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

