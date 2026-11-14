"""DnsxProvider
==============
Resolves subdomains discovered by the passive enumeration phase using dnsx.

Pipeline position:  Passive Discovery → Merge → Deduplicate → **DNSx** → Subzy → Naabu → …

Responsibilities:
- Accepts a flat list of subdomain strings.
- Runs dnsx with JSON output to collect A, AAAA, and CNAME records.
- Filters NXDOMAIN / wildcard results.
- Yields log events and asset events using the standard ReconForge format.
- Emits a scan_summary event when finished.

dnsx is intentionally NOT registered as a standalone discovery provider.
UnifiedDiscoveryProvider calls it after Phase 1 deduplication.
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

from app.core.scope import get_root_domain, is_disallowed_ip, validate_hostname
from app.providers.base import BaseProvider

logger = logging.getLogger("reconforge.providers.dnsx")


class DnsxProvider(BaseProvider):
    """Resolve subdomains and collect DNS records via dnsx."""

    @property
    def name(self) -> str:
        return "DNSx"

    @property
    def description(self) -> str:
        return (
            "Resolves subdomains using dnsx, collecting A, AAAA, and CNAME records "
            "while filtering NXDOMAIN and wildcard responses."
        )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _windows_path_to_wsl(path: str) -> str:
        drive, rest = os.path.splitdrive(os.path.abspath(path))
        drive_letter = drive.rstrip(":").lower()
        rest = rest.replace("\\", "/")
        return f"/mnt/{drive_letter}{rest}"

    @staticmethod
    def _parse_record(line: str) -> Optional[Dict[str, Any]]:
        """Parse a single dnsx JSON output line.

        Returns a dict with keys:
            host      – the queried hostname (str)
            a         – list of A record IPs (List[str])
            aaaa      – list of AAAA record IPs (List[str])
            cname     – list of CNAME targets (List[str])
            status    – DNS status string, e.g. "NOERROR" / "NXDOMAIN"
        Returns None if the line cannot be parsed or represents NXDOMAIN.
        """
        text = (line or "").strip()
        if not text:
            return None
        try:
            payload = json.loads(text)
        except json.JSONDecodeError:
            return None

        host = (payload.get("host") or payload.get("input") or "").strip().lower()
        if not host:
            return None

        status = (payload.get("status_code") or payload.get("status") or "").upper()

        # Drop NXDOMAIN — domain does not exist
        if status == "NXDOMAIN":
            return None

        a_records: List[str] = []
        aaaa_records: List[str] = []
        cname_records: List[str] = []

        # dnsx --json emits arrays keyed by record type
        for entry in payload.get("a", []):
            if entry:
                a_records.append(str(entry).strip())
        for entry in payload.get("aaaa", []):
            if entry:
                aaaa_records.append(str(entry).strip())
        for entry in payload.get("cname", []):
            if entry:
                cname_records.append(str(entry).strip())

        # Fallback: some versions embed "resolver_ip" or a top-level "ip"
        if not a_records:
            fallback_ip = payload.get("resolver_ip") or payload.get("ip")
            if fallback_ip:
                a_records.append(str(fallback_ip).strip())

        return {
            "host": host,
            "a": a_records,
            "aaaa": aaaa_records,
            "cname": cname_records,
            "status": status,
        }

    @staticmethod
    def resolve_wildcard_answers(root_domain: str) -> Set[str]:
        """
        For a given root domain, resolve 3 random nonexistent labels.
        The resolved IP addresses form the wildcard set.
        """
        import socket
        import uuid

        wildcard_ips = set()
        for _ in range(3):
            rand_label = f"rf-wc-{uuid.uuid4().hex[:12]}.{root_domain}"
            try:
                infos = socket.getaddrinfo(rand_label, None)
                for item in infos:
                    sockaddr = item[4]
                    if sockaddr and len(sockaddr) > 0:
                        wildcard_ips.add(str(sockaddr[0]))
            except (socket.gaierror, socket.herror, OSError):
                pass
        return wildcard_ips

    @staticmethod
    def _is_wildcard(host: str, all_answers: Set[str], wildcard_ips: Set[str]) -> bool:
        """
        Requirement 2: Filter a host only if ALL its answers fall inside that set.
        Hosts sharing an IP are legitimate (if wildcard_ips is empty, returns False).
        """
        if not wildcard_ips or not all_answers:
            return False
        return all_answers.issubset(wildcard_ips)

    # ------------------------------------------------------------------
    # Main entry point
    # ------------------------------------------------------------------

    async def discover(
        self, seed_domains: List[str]
    ) -> AsyncGenerator[Dict[str, Any], None]:
        """
        seed_domains – deduplicated subdomain strings from Phase 1.
        """
        raw_hosts = list(
            dict.fromkeys(h.strip().lower() for h in seed_domains if h and h.strip())
        )

        # Requirement 4: Validate hostnames before DNS
        hosts = []
        for h in raw_hosts:
            is_valid, reason = validate_hostname(h)
            if is_valid:
                hosts.append(h)
            else:
                yield {
                    "type": "log",
                    "message": f"[-] Invalid hostname dropped before DNS: {h} ({reason})"
                }

        yield {"type": "log", "message": "\n========== DNSx Resolution =========="}
        yield {"type": "log", "message": "Launching DNSx..."}
        yield {"type": "log", "message": f"Resolving {len(hosts)} subdomains..."}

        if not hosts:
            msg = "DNSx completed. No subdomains provided."
            logger.info(msg)
            yield {"type": "log", "message": msg}
            yield {
                "type": "scan_summary",
                "provider": self.name,
                "resolved": 0,
                "nxdomain": 0,
                "wildcards_filtered": 0,
            }
            return

        is_windows = platform.system().lower() == "windows"
        tool_path = self.detect_tool("dnsx")

        if not tool_path:
            err_msg = "DNSx binary not found (tool_missing: dnsx)"
            logger.error(err_msg)
            yield {
                "type": "stage_error",
                "stage": "dnsx",
                "tool": "dnsx",
                "message": err_msg,
            }
            yield {
                "type": "scan_summary",
                "provider": "dnsx",
                "status": "SKIPPED",
                "count": 0,
            }
            return

        executable = "wsl" if is_windows else tool_path
        temp_path = ""
        start_ts = time.time()

        resolved_count = 0
        nxdomain_count = 0
        wildcard_count = 0
        resolved_hosts: List[Dict[str, Any]] = []

        try:
            # Write hostnames to a temp file for dnsx -l flag
            with tempfile.NamedTemporaryFile(
                mode="w",
                encoding="utf-8",
                delete=False,
                suffix=".txt",
                dir=os.getcwd(),
            ) as target_file:
                target_file.write("\n".join(hosts))
                target_file.write("\n")
                temp_path = target_file.name

            list_path = (
                self._windows_path_to_wsl(temp_path) if is_windows else temp_path
            )

            # Construct command
            args = ["-e", tool_path] if is_windows else []
            dnsx_flags = [
                "-l", list_path,
                "-a",           # collect A records
                "-aaaa",        # collect AAAA records
                "-cname",       # collect CNAME records
                "-json",        # JSON output
                "-silent",      # suppress banner
                "-resp",        # include response data
            ]
            cmd = [executable, *args, *dnsx_flags]

            exec_msg = f"[*] Executing command: {' '.join(cmd)}"
            logger.info(exec_msg)
            yield {"type": "log", "message": exec_msg}

            from app.job_control import register_process, unregister_process, check_job_status
            await check_job_status()

            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding="utf-8",
                errors="replace",
                bufsize=1,
            )
            register_process(process)

            try:
                assert process.stdout is not None

                # --- First pass: collect all A record IPs to detect wildcards ---
                # For a proper wildcard check we would normally probe a random
                # label. Here we flag IPs that appear on ≥20 % of all hosts as
                # potential wildcards (heuristic).  This pass collects records;
                # wildcard filtering happens after process exits.
                raw_records: List[Dict[str, Any]] = []

                for raw_line in process.stdout:
                    await check_job_status()
                    parsed = self._parse_record(raw_line)
                    if parsed is None:
                        # NXDOMAIN or unparseable
                        nxdomain_count += 1
                        continue
                    raw_records.append(parsed)
                    await asyncio.sleep(0)

            finally:
                unregister_process(process)
                if process.poll() is None:
                    process.terminate()
                    process.wait()

            stderr_out = ""
            try:
                if process.stderr is not None:
                    stderr_out = process.stderr.read() or ""
            except Exception:
                stderr_out = ""

            if stderr_out.strip():
                logger.warning("[dnsx stderr] %s", stderr_out.strip())
                yield {"type": "log", "message": f"[dnsx stderr] {stderr_out.strip()}"}

            # --- Requirement 2: DNS wildcard detection by probing 3 random nonexistent labels per root domain ---
            unique_roots = {get_root_domain(rec["host"]) for rec in raw_records if rec.get("host")}
            wildcard_ips_by_root: Dict[str, Set[str]] = {}
            for root in unique_roots:
                if root:
                    wc_set = await asyncio.to_thread(self.resolve_wildcard_answers, root)
                    if wc_set:
                        wildcard_ips_by_root[root] = wc_set
                        wc_msg = f"[*] Wildcard DNS active for {root}: wildcard set {sorted(list(wc_set))}"
                        logger.info(wc_msg)
                        yield {"type": "log", "message": wc_msg}

            # --- Emit asset events for valid resolved records ---
            for rec in raw_records:
                host = rec["host"]
                a_recs = rec["a"]
                aaaa_recs = rec["aaaa"]
                cname_recs = rec["cname"]
                status = rec["status"]

                all_answers = set(a_recs + aaaa_recs)
                root = get_root_domain(host)
                wc_set = wildcard_ips_by_root.get(root, set())

                # Requirement 2: Filter a host only if all its answers fall inside the wildcard set.
                # Hosts sharing an IP are legitimate (if wc_set is empty, none are filtered).
                if self._is_wildcard(host, all_answers, wc_set):
                    wildcard_count += 1
                    yield {
                        "type": "log",
                        "message": f"[-] Wildcard filtered: {host} → {sorted(list(all_answers))} matches wildcard set for {root}",
                    }
                    continue

                # Requirement 3: After DNS resolution, ALWAYS drop hosts whose IPs are
                # loopback, RFC1918, link-local, CGNAT or cloud-metadata ranges, regardless
                # of scope config, and log the reason.
                disallowed = False
                drop_reason = None
                for ip_str in all_answers:
                    is_bad, reason = is_disallowed_ip(ip_str)
                    if is_bad:
                        disallowed = True
                        drop_reason = reason
                        break

                if disallowed:
                    logger.warning("[dnsx] Dropped host %s: %s", host, drop_reason)
                    yield {
                        "type": "log",
                        "message": f"[-] Dropped host {host}: resolved to {drop_reason} (private/loopback/cloud-metadata range)",
                    }
                    continue

                resolved_count += 1
                resolved_hosts.append(rec)

                # Primary IP for storage (first A record if present)
                primary_ip = a_recs[0] if a_recs else (aaaa_recs[0] if aaaa_recs else None)

                log_parts = [f"[+] Resolved: {host}"]
                if a_recs:
                    log_parts.append(f"A={','.join(a_recs)}")
                if aaaa_recs:
                    log_parts.append(f"AAAA={','.join(aaaa_recs)}")
                if cname_recs:
                    log_parts.append(f"CNAME={','.join(cname_recs)}")
                logger.info(" | ".join(log_parts))
                yield {"type": "log", "message": " | ".join(log_parts)}

                yield {
                    "type": "asset",
                    "data": {
                        "domain": host,
                        "type": "subdomain",
                        "status": "resolved",
                        "open_ports": [],
                        "resolved_ip": primary_ip,
                        "metadata": {
                            "source": "dnsx",
                            "dnsx": {
                                "a": a_recs,
                                "aaaa": aaaa_recs,
                                "cname": cname_recs,
                                "dns_status": status,
                                "resolved_at": int(time.time()),
                            },
                        },
                        "discovered_by": "dnsx",
                        "sources": ["dnsx"],
                    },
                }
                await asyncio.sleep(0)

        except Exception as exc:
            logger.exception("[-] DnsxProvider failed: %s", exc)
            yield {"type": "log", "message": f"[-] DnsxProvider failed: {exc}"}

        finally:
            if temp_path:
                try:
                    os.unlink(temp_path)
                except OSError:
                    logger.warning("Failed to remove DNSx target file: %s", temp_path)

        duration_s = int(time.time() - start_ts)
        complete_msg = (
            f"DNSx completed. "
            f"Resolved: {resolved_count} | "
            f"NXDOMAIN: {nxdomain_count} | "
            f"Wildcards filtered: {wildcard_count} | "
            f"Duration: {duration_s}s"
        )
        logger.info(complete_msg)
        yield {"type": "log", "message": complete_msg}

        hosts_in = len(hosts)
        hosts_resolved = resolved_count
        dead_count = hosts_in - hosts_resolved

        if dead_count > 0:
            dead_log = f"[*] {dead_count} host(s) failed DNS resolution and will be excluded from all downstream scanning stages."
            logger.info(dead_log)
            yield {"type": "log", "message": dead_log}

        yield {
            "type": "scan_summary",
            "provider": self.name,
            "resolved": resolved_count,
            "nxdomain": nxdomain_count,
            "wildcards_filtered": wildcard_count,
            "duration_seconds": duration_s,
            "hosts_in": hosts_in,
            "hosts_resolved": hosts_resolved,
            "hosts_dead": dead_count,
        }
