"""root_expansion_provider.py
==========================
Root domain expansion (opt-in, suggestions only).
Uses asnmap, dnsx -ptr, and amass intel to discover related root domains and ASNs.
Results are saved strictly as suggestions (never automatically scanned).
"""

import asyncio
import json
import logging
import os
import platform
import subprocess
import tempfile
import time
from typing import Any, AsyncGenerator, Dict, List, Optional, Set

from app.core.scope import get_root_domain, validate_hostname
from app.core.tools import get_tool_path, is_tool_available
from app.job_control import check_job_status, register_process, unregister_process
from app.providers.base import BaseProvider

logger = logging.getLogger("reconforge.providers.root_expansion")


class RootExpansionProvider(BaseProvider):
    def __init__(self, project_id: str, known_seeds: List[str]):
        self.project_id = project_id
        self.known_seeds = set(s.strip().lower() for s in known_seeds if s)

    @property
    def name(self) -> str:
        return "Root Expansion"

    @property
    def description(self) -> str:
        return "Discovers related root domains, ASNs, and CIDR blocks as suggestions."

    @staticmethod
    def _to_wsl_path(path: str) -> str:
        drive, rest = os.path.splitdrive(os.path.abspath(path))
        drive_letter = drive.rstrip(":").lower()
        return f"/mnt/{drive_letter}{rest.replace('\\', '/')}"

    async def discover(self, seed_domains: List[str]) -> AsyncGenerator[Dict[str, Any], None]:
        async for ev in self.expand_roots(seed_domains, []):
            yield ev

    async def expand_roots(
        self,
        seed_domains: List[str],
        resolved_ips: List[str],
    ) -> AsyncGenerator[Dict[str, Any], None]:
        yield {"type": "log", "message": "[*] Starting Root-Domain Expansion (Suggestions only)..."}

        is_windows = platform.system().lower() == "windows"
        suggested_roots: Dict[str, Dict[str, Any]] = {}
        asns_found: Set[str] = set()
        cidrs_found: Set[str] = set()

        asnmap_bin = get_tool_path("asnmap")
        dnsx_bin = get_tool_path("dnsx")
        amass_bin = get_tool_path("amass")

        # 1. ASNMap Discovery
        if asnmap_bin and seed_domains:
            for s in seed_domains[:5]:
                clean_s = s.strip().lower()
                yield {"type": "log", "message": f"[*] Querying ASN & CIDR mapping for {clean_s} via asnmap..."}
                cmd = ["wsl", "-e", asnmap_bin, "-d", clean_s, "-json", "-silent"] if is_windows else [asnmap_bin, "-d", clean_s, "-json", "-silent"]
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
                    stdout, _ = proc.communicate(timeout=60)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    stdout = ""
                finally:
                    unregister_process(proc)

                for line in stdout.splitlines():
                    text = line.strip()
                    if not text:
                        continue
                    try:
                        rec = json.loads(text)
                        asn = str(rec.get("as_number") or rec.get("asn") or "")
                        org = str(rec.get("as_name") or rec.get("org") or "")
                        cidr = str(rec.get("ip") or rec.get("cidr") or "")
                        if asn:
                            asns_found.add(f"AS{asn} ({org})")
                        if cidr and "/" in cidr:
                            cidrs_found.add(cidr)
                    except Exception:
                        continue

            if asns_found:
                yield {"type": "log", "message": f"[+] Discovered ASNs: {', '.join(list(asns_found)[:3])}"}

        # 2. Reverse DNS PTR on target IPs
        if dnsx_bin and resolved_ips:
            yield {"type": "log", "message": f"[*] Performing reverse DNS PTR lookups on {min(len(resolved_ips), 50)} IP(s)..."}
            with tempfile.NamedTemporaryFile("w", delete=False, suffix=".txt", encoding="utf-8") as tf:
                tf.write("\n".join(resolved_ips[:50]) + "\n")
                ips_file = tf.name

            wsl_ips = self._to_wsl_path(ips_file) if is_windows else ips_file
            try:
                cmd = ["wsl", "-e", dnsx_bin, "-l", wsl_ips, "-ptr", "-resp", "-json", "-silent"] if is_windows else [dnsx_bin, "-l", wsl_ips, "-ptr", "-resp", "-json", "-silent"]
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
                    stdout, _ = proc.communicate(timeout=60)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    stdout = ""
                finally:
                    unregister_process(proc)

                for line in stdout.splitlines():
                    text = line.strip()
                    if not text:
                        continue
                    try:
                        rec = json.loads(text)
                        ptr_records = rec.get("ptr", [])
                        for ptr in ptr_records:
                            ptr_clean = ptr.strip().lower().rstrip(".")
                            is_val, _ = validate_hostname(ptr_clean)
                            if is_val:
                                root = get_root_domain(ptr_clean)
                                if root and root not in self.known_seeds and root not in suggested_roots:
                                    suggested_roots[root] = {
                                        "source": "dnsx_ptr",
                                        "evidence": f"Reverse DNS of IP {rec.get('host')}: {ptr_clean}",
                                        "asn": list(asns_found)[:2],
                                        "cidr": list(cidrs_found)[:2],
                                    }
                    except Exception:
                        continue
            finally:
                try:
                    os.unlink(ips_file)
                except OSError:
                    pass

        # 3. Amass Intel for related root domains
        if amass_bin and seed_domains:
            primary_seed = seed_domains[0]
            yield {"type": "log", "message": f"[*] Running Amass Intel on {primary_seed}..."}
            cmd = ["wsl", "-e", amass_bin, "intel", "-d", primary_seed, "-whois"] if is_windows else [amass_bin, "intel", "-d", primary_seed, "-whois"]
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
                stdout, _ = proc.communicate(timeout=90)
            except subprocess.TimeoutExpired:
                proc.kill()
                stdout = ""
            finally:
                unregister_process(proc)

            for line in stdout.splitlines():
                candidate = line.strip().lower().rstrip(".")
                is_val, _ = validate_hostname(candidate)
                if is_val:
                    root = get_root_domain(candidate)
                    if root and root not in self.known_seeds and root not in suggested_roots:
                        suggested_roots[root] = {
                            "source": "amass_intel",
                            "evidence": f"Amass WHOIS/Intel correlation from {primary_seed}",
                            "asn": list(asns_found)[:2],
                            "cidr": list(cidrs_found)[:2],
                        }

        # Yield each suggested root
        for root, meta in suggested_roots.items():
            yield {
                "type": "asset",
                "data": {
                    "domain": root,
                    "value": root,
                    "type": "suggested_root",
                    "status": "suggested",
                    "open_ports": [],
                    "metadata": {
                        "source": meta["source"],
                        "evidence": meta["evidence"],
                        "asn": meta.get("asn", []),
                        "cidr": meta.get("cidr", []),
                        "suggested_at": int(time.time()),
                    },
                    "discovered_by": meta["source"],
                    "sources": [meta["source"]],
                },
            }
            yield {
                "type": "suggested_root",
                "domain": root,
                "source": meta["source"],
                "evidence": meta["evidence"],
            }
            yield {"type": "log", "message": f"[+] Suggested root found: {root} ({meta['evidence']})"}

        total_suggested = len(suggested_roots)
        yield {
            "type": "scan_summary",
            "provider": "root_expansion",
            "status": "completed",
            "count": total_suggested,
        }
        yield {
            "type": "log",
            "message": f"[√] Root Expansion completed → {total_suggested} suggested root(s) (None added to scan scope without manual approval)",
        }
