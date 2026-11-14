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
from typing import Any, AsyncGenerator, Dict, List, Optional, Tuple

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
from app.providers.crtsh_provider import CrtshProvider
from app.providers.certspotter_provider import CertspotterProvider
from app.providers.dns_bruteforce_provider import DnsBruteforceProvider
from app.providers.root_expansion_provider import RootExpansionProvider
from app.providers.takeover_crosscheck_provider import TakeoverCrossCheckProvider
from app.core.provider_keys import sync_subfinder_config_to_wsl
from app.providers.url_merge import merge_urls
from app.core.scope import filter_scope, is_in_scope, is_ip_in_scope, validate_hostname, is_disallowed_ip, get_root_domain
from app.core.tools import is_tool_available, get_tool_status

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

    async def _run_phase(
        self,
        provider: BaseProvider,
        targets: List[str],
        phase_label: str,
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
            async for event in provider.discover(targets, **kwargs):
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

        # Scope, Rate Limits, and Custom Headers Configuration
        scope_config = (project_config or {}).get("scope") or {"in_scope": [], "out_of_scope": []}
        rate_limits_cfg = (project_config or {}).get("rate_limits") or {}
        custom_headers_cfg = (project_config or {}).get("custom_headers") or {}
        scan_profile = (project_config or {}).get("scan_profile", "recon") or "recon"

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
            # PHASE 1.5: DNS Brute Force + Permutations (Deep mode only)
            # ================================================================
            if scan_mode == "fast":
                yield {
                    "type": "stage_skipped",
                    "stage": "DNS Brute Force & Permutations",
                    "tool": "puredns",
                    "reason": "deep mode only",
                }
                yield {"type": "log", "message": "[!] DNS Brute Force & Permutations skipped (deep mode only)."}
            else:
                yield {"type": "log", "message": "========== DNS Brute Force & Permutations (Deep Mode) =========="}
                dns_bf_provider = DnsBruteforceProvider(
                    wordlist_path=((project_config or {}).get("wordlists") or {}).get("dns_bruteforce"),
                    resolvers_path=((project_config or {}).get("wordlists") or {}).get("resolvers"),
                    max_permutations=int((project_config or {}).get("max_permutations") or 50000),
                    rate_limit=get_tool_rl("dns_bruteforce"),
                    scope_config=scope_config,
                )
                async for event in dns_bf_provider.run_bruteforce(seed_domains, unique_subdomains):
                    if event.get("type") == "asset":
                        cand_d = event.get("data", {}).get("domain")
                        if cand_d and cand_d not in unique_subdomains:
                            unique_subdomains.append(cand_d)
                    yield event

                # Re-apply scope filter after brute force additions
                unique_subdomains, bf_scope_events = check_and_filter_scope(unique_subdomains, "Phase 1.5: DNS Brute Force Merge")
                for ev in bf_scope_events:
                    yield ev

            # ================================================================
            # PHASE 2: DNS Resolution (DNSx)
            # ================================================================

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
                dnsx_provider = DnsxProvider()
                async for event in self._run_phase(dnsx_provider, unique_subdomains, "DNSx Resolution"):
                    if event.get("type") == "asset":
                        asset = event.get("data", {})
                        if asset.get("status") in ("resolved", "live"):
                            domain_norm = _normalise(asset.get("domain", ""))
                            cnames = (asset.get("metadata", {}).get("dns") or {}).get("cname", [])
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
            # PHASE 3: Subdomain Takeover Cross-Check (Subzy + Nuclei + dnsReaper)
            # ================================================================
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
            }
            yield {"type": "log", "message": "[!] Provider naabu skipped"}
        else:
            # Filter scope before Naabu
            unique_resolved, scope_events = check_and_filter_scope(unique_resolved, "Phase 4: Naabu Port Scan")
            for ev in scope_events:
                yield ev

            # Identify hosts behind CDNs to exclude from wide port scans in deep mode
            cdn_excluded_hosts = {}
            if scan_mode == "deep":
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
                    rate_limit=get_tool_rl("naabu"),
                    scan_mode=scan_mode,
                    port_range=(project_config or {}).get("port_range"),
                    cdn_excluded_hosts=cdn_excluded_hosts,
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
            else:
                yield {"type": "log", "message": "[*] No targets in scope for Naabu."}
                yield {"type": "scan_summary", "provider": "naabu", "status": "completed", "count": 0}

        # ================================================================
        # PHASE 5: HTTP Probing (HTTPX)
        # ================================================================

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

        if not is_available("httpx"):
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
            }
            yield {"type": "log", "message": "[!] Provider httpx skipped"}
        else:
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
                        asset = event.get("data", {})
                        final_url = asset.get("metadata", {}).get("url")
                        redirect_target = asset.get("metadata", {}).get("redirect_location")
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
            if (a.get("cdn_waf") or {}).get("is_waf"):
                waf_detected_hosts.add(a.get("domain"))

        if is_available("wafw00f"):
            wafw00f_targets = [u for u in live_host_urls if any(d in u for d in rep_domains)][:15]
            if wafw00f_targets:
                waf_provider = Wafw00fProvider()
                async for event in self._run_phase(waf_provider, wafw00f_targets, "WAF Detection (wafw00f)"):
                    if event.get("type") == "asset":
                        waf_data = event.get("data", {})
                        if waf_data.get("domain"):
                            waf_detected_hosts.add(waf_data["domain"])
                    yield event
        else:
            yield {"type": "stage_skipped", "stage": "WAF Detection (wafw00f)", "tool": "wafw00f", "reason": "tool_missing: wafw00f"}
            yield {"type": "log", "message": "[!] Tool 'wafw00f' is not installed in WSL. Skipping WAF fingerprinting."}

        # Setup targets: if scan_all_members is False, filter downstream targets to representative hosts
        if scan_all_members:
            active_candidate_hosts = live_host_targets
        else:
            active_candidate_hosts = [h for h in live_host_targets if h in rep_domains] if rep_domains else live_host_targets

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

        # ffuf/feroxbuster and API probes run ONLY on priority hosts:
        # (representatives from clustering, plus interesting 401/403 hosts)
        priority_hosts_set = set(rep_domains)
        for a in all_live_assets:
            m = a.get("metadata") or {}
            sc = a.get("status_code") or m.get("status_code")
            if a.get("is_interesting") or sc in (401, 403):
                priority_hosts_set.add(a.get("domain"))

        priority_targets = [host_to_live_url[h] for h in priority_hosts_set if h in host_to_live_url]
        priority_targets, scope_ev_p = check_and_filter_scope(priority_targets, "Sub-phase 5B: Priority Hosts (FFUF/API)")
        for ev in scope_ev_p:
            yield ev

        if priority_targets:
            # 1. FFUF Content Discovery
            if not is_available("ffuf") and not is_available("feroxbuster"):
                yield {"type": "log", "message": "[!] Tool 'ffuf' / 'feroxbuster' is not installed in WSL. Skipping content discovery."}
                yield {"type": "stage_skipped", "stage": "Content Discovery (ffuf)", "tool": "ffuf", "reason": "tool_missing: ffuf"}
                yield {"type": "scan_summary", "provider": "ffuf", "status": "SKIPPED", "count": 0}
            else:
                ffuf_prov = FfufProvider()
                detected_tech_map = {
                    a.get("domain"): (a.get("metadata") or {}).get("technologies") or (a.get("metadata") or {}).get("tech") or []
                    for a in all_live_assets
                }
                custom_wl = (project_config or {}).get("wordlists", {}).get("content") or (project_config or {}).get("wordlists", {}).get("ffuf")
                async for event in self._run_phase(
                    ffuf_prov,
                    priority_targets,
                    "FFUF Content Discovery",
                    scan_mode=scan_mode,
                    rate_limit=get_tool_rl("ffuf"),
                    custom_headers=custom_headers_cfg,
                    scope=scope_config,
                    wordlist_path=custom_wl,
                    waf_detected_hosts=waf_detected_hosts,
                    detected_tech_per_host=detected_tech_map,
                ):
                    if event.get("type") == "content_path_event":
                        u = event.get("data", {}).get("url")
                        if u:
                            all_ffuf_urls.append(u)
                    elif event.get("type") == "scan_summary" and event.get("provider") == "ffuf":
                        ffuf_paths_discovered = event.get("count", 0)
                    yield event

            # 2. API Surface & GraphQL Probing
            api_prov = ApiSurfaceProvider()
            async for event in self._run_phase(
                api_prov,
                priority_targets,
                "API Surface & GraphQL Detection",
                custom_headers=custom_headers_cfg,
                scope=scope_config,
            ):
                if event.get("type") == "url_event" and event.get("data", {}).get("source") == "api_spec":
                    u = event.get("data", {}).get("url")
                    if u:
                        all_api_spec_urls.append(u)
                elif event.get("type") == "api_spec_event":
                    api_specs_discovered += 1
                elif event.get("type") == "graphql_event":
                    graphql_endpoints_discovered += 1
                yield event
        else:
            yield {"type": "log", "message": "[*] No priority targets for FFUF / API surface probing."}
            yield {"type": "scan_summary", "provider": "ffuf", "status": "SKIPPED", "count": 0}
            yield {"type": "scan_summary", "provider": "api_surface", "status": "SKIPPED", "count": 0}

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

        async def run_worker(provider: BaseProvider, target_list: List[str], label: str, **kwargs: Any) -> None:
            try:
                async for ev in provider.discover(target_list, **kwargs):
                    await event_queue.put((label, ev))
            except Exception as exc:
                logger.error(f"[-] {label} worker failed: {exc}")
                await event_queue.put((label, {"type": "log", "message": f"[-] {label} worker failed: {exc}"}))
            finally:
                await event_queue.put((label, "__done__"))

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

            # Waymore (optional historical supplement to GAU)
            if not is_available("waymore"):
                yield {"type": "log", "message": "[!] Tool 'waymore' is not installed in WSL. Skipping Waymore supplement."}
                yield {"type": "stage_skipped", "stage": "Historical URLs (waymore)", "tool": "waymore", "reason": "tool_missing: waymore"}
                yield {"type": "scan_summary", "provider": "waymore", "status": "SKIPPED", "count": 0}
            else:
                tasks.append(asyncio.create_task(run_worker(WaymoreProvider(), unique_live_hosts, "waymore", scope=scope_config)))

            # SubJS
            if not is_available("subjs"):
                yield {"type": "log", "message": "[!] Tool 'subjs' is not installed in WSL. Skipping JS discovery."}
                yield {"type": "stage_skipped", "stage": "JS Discovery (subjs)", "tool": "subjs", "reason": "tool_missing: subjs"}
                yield {"type": "scan_summary", "provider": "subjs", "status": "SKIPPED", "count": 0}
            else:
                tasks.append(asyncio.create_task(run_worker(SubjsProvider(), unique_live_urls, "subjs")))

            # GoWitness (deep mode)
            if scan_mode == "deep":
                if not is_available("gowitness"):
                    yield {"type": "log", "message": "[!] Tool 'gowitness' is not installed in WSL. Skipping screenshots."}
                    yield {"type": "stage_skipped", "stage": "Screenshots (gowitness)", "tool": "gowitness", "reason": "tool_missing: gowitness"}
                    yield {"type": "scan_summary", "provider": "gowitness", "status": "SKIPPED", "count": 0}
                else:
                    tasks.append(asyncio.create_task(run_worker(GowitnessProvider(), unique_live_urls, "gowitness")))
        else:
            yield {"type": "log", "message": "[*] No live HTTPX targets; skipping concurrent crawlers."}
            for p in ("katana", "gau", "waymore", "subjs"):
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
                k_js = k_meta.get("js_files", [])
                all_js_files.extend(k_js)
            elif event.get("type") == "url_event" and label == "gau":
                all_gau_urls.append(event.get("data", {}).get("url"))
            elif event.get("type") == "url_event" and label == "waymore":
                all_waymore_urls.append(event.get("data", {}).get("url"))
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
        
        # Deduplicate and filter all JS files (from Katana and SubJS) through is_in_scope BEFORE LinkFinder runs
        all_js_files = list(dict.fromkeys(u.strip() for u in all_js_files if u and u.strip()))
        all_js_files, scope_ev_js = check_and_filter_scope(all_js_files, "Phase 6B: JS Endpoint Extraction (LinkFinder)")
        for ev in scope_ev_js:
            yield ev

        if all_js_files:
            if not is_available("linkfinder"):
                yield {"type": "log", "message": "[!] Tool 'linkfinder' is not installed in WSL. Skipping JS endpoint extraction."}
                yield {"type": "stage_skipped", "stage": "JS Endpoint Extraction (linkfinder)", "tool": "linkfinder", "reason": "tool_missing: linkfinder"}
                yield {"type": "scan_summary", "provider": "linkfinder", "status": "SKIPPED", "count": 0}
                yield {"type": "log", "message": "[!] Provider linkfinder skipped"}
            else:
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
            yield {"type": "scan_summary", "provider": "uro", "status": "SKIPPED"}
            yield {"type": "log", "message": "[!] Provider uro skipped"}

        if not uro_normalised_urls and merged_raw_list:
            uro_normalised_urls = list(dict.fromkeys(merged_raw_list))

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
        # SUB-PHASE 6C: Parameter Discovery (Arjun / x8 - DEEP MODE ONLY)
        # ================================================================
        all_param_urls: List[str] = []
        params_discovered = 0
        if scan_mode == "deep" and uro_normalised_urls:
            from app.providers.url_merge import get_url_priority
            sorted_candidates = sorted(
                uro_normalised_urls,
                key=lambda u: (get_url_priority(u), len(u), u)
            )
            param_targets = sorted_candidates[:25]
            param_targets, scope_ev_param = check_and_filter_scope(param_targets, "Sub-phase 6C: Parameter Discovery")
            for ev in scope_ev_param:
                yield ev

            if is_available("arjun") or is_available("x8"):
                param_provider = ParamDiscoveryProvider()
                async for event in self._run_phase(
                    param_provider,
                    param_targets,
                    "Parameter Discovery (Deep Mode)",
                    rate_limit=get_tool_rl("arjun"),
                    custom_headers=custom_headers_cfg,
                    scope=scope_config,
                ):
                    if event.get("type") == "url_event" and event.get("data", {}).get("source") == "param_discovery":
                        param_u = event.get("data", {}).get("url")
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
            if not is_available("gf"):
                yield {"type": "log", "message": "[!] Tool 'gf' is not installed in WSL. Skipping URL classification."}
                yield {"type": "stage_skipped", "stage": "URL Classification (gf)", "tool": "gf", "reason": "tool_missing: gf"}
                yield {"type": "scan_summary", "provider": "gf", "status": "SKIPPED", "count": 0}
                yield {"type": "log", "message": "[!] Provider gf skipped"}
                gf_endpoint_urls = list(uro_normalised_urls)
            else:
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

        scan_queue = asyncio.Queue()
        
        async def run_scanner(provider_func, targets, label, **kwargs):
            try:
                async for event in provider_func(targets, **kwargs):
                    await scan_queue.put((label, event))
            except Exception as exc:
                logger.error(f"Concurrent scanner {label} failed: {exc}", exc_info=True)
                await scan_queue.put((label, {"type": "log", "message": f"[-] Scanner {label} failed: {exc}"}))
            finally:
                await scan_queue.put((label, "__done__"))

        scan_tasks = []

        # Requirement 5: Scan profiles ("recon" vs "recon_validation")
        if scan_profile == "recon":
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
                        rate_limit=nuclei_rl,
                        custom_headers=custom_headers_cfg,
                    )))
                else:
                    yield {"type": "scan_summary", "provider": "nuclei_host", "status": "SKIPPED"}
                    yield {"type": "log", "message": "[!] Provider nuclei_host skipped"}

                if gf_endpoint_urls:
                    scan_tasks.append(asyncio.create_task(run_scanner(
                        NucleiProvider().discover_endpoint_scan,
                        gf_endpoint_urls,
                        "nuclei_endpoint",
                        rate_limit=nuclei_rl,
                        custom_headers=custom_headers_cfg,
                    )))
                else:
                    yield {"type": "scan_summary", "provider": "nuclei_endpoint", "status": "SKIPPED"}
                    yield {"type": "log", "message": "[!] Provider nuclei_endpoint skipped"}
                
            if scan_mode == "deep":
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
                        rate_limit=dalfox_rl,
                        custom_headers=custom_headers_cfg,
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
            f"    FFUF Content Paths : {ffuf_paths_discovered}\n"
            f"    API Specs Found    : {api_specs_discovered}\n"
            f"    GraphQL Endpoints  : {graphql_endpoints_discovered}\n"
            f"    Discovered Params  : {params_discovered}\n"
            f"    Naabu Open Ports   : {naabu_open_ports} across {naabu_hosts_with_ports} hosts\n"
            f"    Katana URLs        : {katana_urls_discovered} (crawled {katana_hosts_scanned} hosts)\n"
            f"    GAU Historical URLs: {len(all_gau_urls)}\n"
            f"    Waymore Hist. URLs : {len(all_waymore_urls)}\n"
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

