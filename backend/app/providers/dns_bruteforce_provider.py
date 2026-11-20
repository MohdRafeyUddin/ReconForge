"""dns_bruteforce_provider.py
==========================
Deep-mode DNS brute forcing and permutation generation with wildcard filtering.
Uses puredns (preferred) or shuffledns with resolvers, falling back to dnsx.
"""

import asyncio
import json
import logging
import os
import platform
import subprocess
import tempfile
import time
from typing import Any, AsyncGenerator, Dict, List, Optional, Set, Tuple

from app.core.scope import filter_scope, is_disallowed_ip, is_in_scope, validate_hostname
from app.core.tools import get_tool_path, is_tool_available
from app.job_control import check_job_status, register_process, unregister_process
from app.providers.base import BaseProvider

logger = logging.getLogger("reconforge.providers.dns_bruteforce")

DEFAULT_SUBDOMAIN_WORDLIST = [
    "www", "mail", "remote", "blog", "webmail", "server", "ns1", "ns2",
    "smtp", "secure", "vpn", "api", "dev", "staging", "stg", "test",
    "portal", "admin", "app", "corp", "internal", "gateway", "auth",
    "login", "sso", "git", "gitlab", "github", "jenkins", "jira",
    "confluence", "status", "monitor", "grafana", "kibana", "elastic",
    "db", "database", "sql", "mysql", "postgres", "redis", "cpanel",
    "autodiscover", "sip", "voip", "chat", "cloud", "aws", "azure",
    "static", "assets", "media", "cdn", "shop", "store", "pay",
    "billing", "beta", "demo", "uat", "stage", "preview", "sandbox",
]

PUBLIC_FALLBACK_RESOLVERS = [
    "1.1.1.1",
    "1.0.0.1",
    "8.8.8.8",
    "8.8.4.4",
    "9.9.9.9",
    "149.112.112.112",
    "208.67.222.222",
    "208.67.220.220",
]


class DnsBruteforceProvider(BaseProvider):
    def __init__(
        self,
        wordlist_path: Optional[str] = None,
        resolvers_path: Optional[str] = None,
        max_permutations: int = 50000,
        rate_limit: Optional[int] = None,
        scope_config: Optional[Dict[str, Any]] = None,
    ):
        self.wordlist_path = wordlist_path
        self.resolvers_path = resolvers_path
        self.max_permutations = max_permutations or 50000
        self.rate_limit = rate_limit
        self.scope_config = scope_config or {}

    @property
    def name(self) -> str:
        return "DNS Brute Force"

    @property
    def description(self) -> str:
        return "Active DNS brute forcing and permutation generation with wildcard filtering (Deep mode only)."

    @staticmethod
    def _to_wsl_path(path: str) -> str:
        drive, rest = os.path.splitdrive(os.path.abspath(path))
        drive_letter = drive.rstrip(":").lower()
        return f"/mnt/{drive_letter}{rest.replace('\\', '/')}"

    async def generate_permutations(
        self,
        subdomains: List[str],
        limit: int,
    ) -> List[str]:
        """Runs alterx in WSL over passive subdomains, falling back to rule-based generation."""
        if not subdomains:
            return []

        alterx_bin = get_tool_path("alterx")
        is_windows = platform.system().lower() == "windows"

        if alterx_bin:
            try:
                with tempfile.NamedTemporaryFile("w", delete=False, suffix=".txt", encoding="utf-8") as tf:
                    tf.write("\n".join(subdomains) + "\n")
                    subs_path = tf.name

                wsl_input = self._to_wsl_path(subs_path) if is_windows else subs_path
                cmd = (
                    ["wsl", "-e", alterx_bin, "-l", wsl_input, "-limit", str(limit), "-silent"]
                    if is_windows
                    else [alterx_bin, "-l", wsl_input, "-limit", str(limit), "-silent"]
                )

                proc = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                )
                register_process(proc)
                try:
                    stdout, _ = proc.communicate(timeout=60)
                finally:
                    unregister_process(proc)
                    try:
                        os.unlink(subs_path)
                    except OSError:
                        pass

                results = []
                for line in stdout.splitlines():
                    cand = line.strip().lower()
                    if cand and len(results) < limit:
                        is_val, _ = validate_hostname(cand)
                        if is_val:
                            results.append(cand)
                if results:
                    return results
            except Exception as exc:
                logger.warning(f"alterx generation failed, falling back to rule-based: {exc}")

        # Built-in permutation fallback
        permutations: Set[str] = set()
        modifiers = ["dev", "test", "stage", "stg", "prod", "uat", "admin", "api", "v1", "v2", "app"]
        for sub in subdomains[:200]:
            parts = sub.split(".")
            if len(parts) >= 3:
                prefix = parts[0]
                root = ".".join(parts[1:])
                for mod in modifiers:
                    permutations.add(f"{prefix}-{mod}.{root}")
                    permutations.add(f"{mod}-{prefix}.{root}")
                    permutations.add(f"{prefix}{mod}.{root}")
                    if len(permutations) >= limit:
                        break
            if len(permutations) >= limit:
                break
        return list(permutations)[:limit]

    async def discover(self, seed_domains: List[str]) -> AsyncGenerator[Dict[str, Any], None]:
        # Implementation called through run_bruteforce with passive subdomains
        async for ev in self.run_bruteforce(seed_domains, []):
            yield ev

    async def run_bruteforce(
        self,
        seed_domains: List[str],
        passive_subdomains: List[str],
    ) -> AsyncGenerator[Dict[str, Any], None]:
        yield {"type": "log", "message": "[*] Starting DNS Brute Force & Permutation pipeline (Deep Mode)..."}

        # 1. Prepare candidates list
        candidates: Set[str] = set()

        # Generate standard brute-force words
        words = list(DEFAULT_SUBDOMAIN_WORDLIST)
        for s in seed_domains:
            clean_s = s.strip().lower()
            if not clean_s:
                continue
            for w in words:
                cand = f"{w}.{clean_s}"
                is_val, _ = validate_hostname(cand)
                if is_val:
                    candidates.add(cand)

        # Generate permutations from passive subdomains
        if passive_subdomains:
            yield {"type": "log", "message": f"[*] Generating subdomain permutations over {len(passive_subdomains)} passive targets..."}
            perms = await self.generate_permutations(passive_subdomains, self.max_permutations)
            yield {"type": "log", "message": f"[+] Generated {len(perms)} permutation candidates (capped at {self.max_permutations})"}
            candidates.update(perms)

        # 2. Strict scope filtering BEFORE resolution
        in_scope_candidates = []
        for cand in candidates:
            if is_in_scope(cand, self.scope_config):
                in_scope_candidates.append(cand)

        yield {"type": "log", "message": f"[*] Total in-scope candidates to resolve: {len(in_scope_candidates)}"}
        if not in_scope_candidates:
            yield {"type": "log", "message": "[*] No in-scope brute force candidates to resolve."}
            yield {
                "type": "scan_summary",
                "provider": "dns_bruteforce",
                "status": "completed",
                "count": 0,
            }
            return

        # 3. Prepare resolvers and wordlist files
        with tempfile.NamedTemporaryFile("w", delete=False, suffix=".txt", encoding="utf-8") as rf:
            rf.write("\n".join(PUBLIC_FALLBACK_RESOLVERS) + "\n")
            resolvers_file = rf.name

        with tempfile.NamedTemporaryFile("w", delete=False, suffix=".txt", encoding="utf-8") as cf:
            cf.write("\n".join(in_scope_candidates) + "\n")
            candidates_file = cf.name

        is_windows = platform.system().lower() == "windows"
        wsl_resolvers = self._to_wsl_path(resolvers_file) if is_windows else resolvers_file
        wsl_candidates = self._to_wsl_path(candidates_file) if is_windows else candidates_file

        puredns_bin = get_tool_path("puredns")
        shuffledns_bin = get_tool_path("shuffledns")
        dnsx_bin = get_tool_path("dnsx")

        resolved_assets: Dict[str, Dict[str, Any]] = {}

        try:
            if puredns_bin:
                yield {"type": "log", "message": f"[*] Resolving with PureDNS (wildcard detection enabled)..."}
                cmd = [
                    "wsl", "-e", puredns_bin, "resolve", wsl_candidates,
                    "-r", wsl_resolvers, "--wildcard-batch", "1000",
                ] if is_windows else [
                    puredns_bin, "resolve", wsl_candidates,
                    "-r", wsl_resolvers, "--wildcard-batch", "1000",
                ]
                if self.rate_limit and self.rate_limit > 0:
                    cmd.extend(["-q", str(self.rate_limit)])

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
                try:
                    stdout, stderr = proc.communicate(timeout=180)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    yield {"type": "stage_timeout", "stage": "DNS Brute Force", "tool": "puredns", "reason": "timeout"}
                    stdout, stderr = "", ""
                finally:
                    unregister_process(proc)

                if proc.returncode == 0 and stdout:
                    for line in stdout.splitlines():
                        host = line.strip().lower()
                        is_val, _ = validate_hostname(host)
                        if is_val and host not in resolved_assets:
                            resolved_assets[host] = {
                                "domain": host,
                                "type": "subdomain",
                                "status": "resolved",
                                "open_ports": [],
                                "metadata": {"source": "puredns_bruteforce"},
                                "discovered_by": "puredns",
                                "sources": ["puredns"],
                            }

            elif shuffledns_bin:
                yield {"type": "log", "message": f"[*] PureDNS not found, resolving with ShuffleDNS..."}
                first_domain = seed_domains[0] if seed_domains else "target"
                cmd = [
                    "wsl", "-e", shuffledns_bin, "-list", wsl_candidates,
                    "-r", wsl_resolvers, "-d", first_domain, "-silent",
                ] if is_windows else [
                    shuffledns_bin, "-list", wsl_candidates,
                    "-r", wsl_resolvers, "-d", first_domain, "-silent",
                ]
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
                try:
                    stdout, stderr = proc.communicate(timeout=180)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    yield {"type": "stage_timeout", "stage": "DNS Brute Force", "tool": "shuffledns", "reason": "timeout"}
                    stdout, stderr = "", ""
                finally:
                    unregister_process(proc)

                if proc.returncode == 0 and stdout:
                    for line in stdout.splitlines():
                        host = line.strip().lower()
                        is_val, _ = validate_hostname(host)
                        if is_val and host not in resolved_assets:
                            resolved_assets[host] = {
                                "domain": host,
                                "type": "subdomain",
                                "status": "resolved",
                                "open_ports": [],
                                "metadata": {"source": "shuffledns_bruteforce"},
                                "discovered_by": "shuffledns",
                                "sources": ["shuffledns"],
                            }

            elif dnsx_bin:
                yield {"type": "log", "message": f"[*] Resolving candidates with DNSx fallback..."}
                cmd = [
                    "wsl", "-e", dnsx_bin, "-l", wsl_candidates,
                    "-a", "-aaaa", "-cname", "-json", "-silent",
                ] if is_windows else [
                    dnsx_bin, "-l", wsl_candidates,
                    "-a", "-aaaa", "-cname", "-json", "-silent",
                ]
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
                try:
                    stdout, stderr = proc.communicate(timeout=180)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    yield {"type": "stage_timeout", "stage": "DNS Brute Force", "tool": "dnsx", "reason": "timeout"}
                    stdout, stderr = "", ""
                finally:
                    unregister_process(proc)

                if proc.returncode == 0 and stdout:
                    for line in stdout.splitlines():
                        text = line.strip()
                        if not text:
                            continue
                        try:
                            item = json.loads(text)
                            host = (item.get("host") or "").strip().lower()
                            is_val, _ = validate_hostname(host)
                            if is_val and host not in resolved_assets:
                                a_recs = item.get("a", [])
                                # Drop disallowed IPs
                                if any(is_disallowed_ip(ip)[0] for ip in a_recs):
                                    continue
                                resolved_assets[host] = {
                                    "domain": host,
                                    "type": "subdomain",
                                    "status": "resolved",
                                    "open_ports": [],
                                    "metadata": {
                                        "source": "dnsx_bruteforce",
                                        "dnsx": {
                                            "a": a_recs,
                                            "aaaa": item.get("aaaa", []),
                                            "cname": item.get("cname", []),
                                            "resolved_at": int(time.time()),
                                        },
                                    },
                                    "discovered_by": "dnsx",
                                    "sources": ["dnsx_bruteforce"],
                                }
                        except Exception:
                            continue

            # Yield resolved assets
            for host, asset_data in resolved_assets.items():
                yield {
                    "type": "asset",
                    "data": asset_data,
                }

            count = len(resolved_assets)
            yield {
                "type": "scan_summary",
                "provider": "dns_bruteforce",
                "status": "completed",
                "count": count,
            }
            yield {"type": "log", "message": f"[√] DNS Brute Force & Permutations completed → {count} verified host(s)"}

        finally:
            for fpath in (resolvers_file, candidates_file):
                try:
                    os.unlink(fpath)
                except OSError:
                    pass


DNSBruteForceProvider = DnsBruteforceProvider
