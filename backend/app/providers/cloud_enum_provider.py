"""Phase 8.3 — Opt-in cloud bucket enumeration.

Deep-mode only and disabled by default. Candidate keywords are derived from
the project's seed domains; only buckets that reference an in-scope root name
are reported. No bucket contents are downloaded and no credentials are used.
"""

import asyncio
import logging
import os
import platform
import re
import subprocess
import time
from typing import Any, AsyncGenerator, Dict, List, Optional
from urllib.parse import urlparse

from app.core.phase8_config import get_phase8_config
from app.providers.base import BaseProvider

logger = logging.getLogger("reconforge.providers.cloud_enum")

CLOUD_URL_RE = re.compile(
    r"https?://[^\s'\"<>()]+(?:s3[^\s'\"<>()]*\.amazonaws\.com|blob\.core\.windows\.net|storage\.googleapis\.com)[^\s'\"<>()]*",
    re.IGNORECASE,
)
BUCKET_HOST_RE = re.compile(
    r"(?:https?://)?([a-z0-9][a-z0-9.\-]{1,120}\.(?:s3[^\s/]*\.amazonaws\.com|blob\.core\.windows\.net|storage\.googleapis\.com))",
    re.IGNORECASE,
)


class CloudEnumProvider(BaseProvider):
    @property
    def name(self) -> str:
        return "CloudEnum"

    @property
    def description(self) -> str:
        return "Opt-in public cloud bucket enumeration for in-scope root names."

    # ------------------------------------------------------------------
    # Pure helpers
    # ------------------------------------------------------------------

    @staticmethod
    def root_in_scope(root: str, scope: Optional[Dict[str, List[str]]]) -> bool:
        """Wildcard-aware check that allows a seed root under *.root rules."""
        root = (root or "").strip().lower().strip(".")
        if not root:
            return False
        if not scope:
            return True
        out_rules = [str(r).strip().lower() for r in (scope.get("out_of_scope") or []) if str(r).strip()]
        for rule in out_rules:
            # An out-of-scope subdomain does not exclude its parent root keyword,
            # but an out-of-scope wildcard/exact root does.
            if rule == root:
                return False
            if rule.startswith("*.") and root.endswith("." + rule[2:]):
                return False
            if rule.startswith("*") and not rule.startswith("*.") and root.endswith(rule[1:]):
                return False
        in_rules = [str(r).strip().lower() for r in (scope.get("in_scope") or []) if str(r).strip()]
        if not in_rules:
            return True
        for rule in in_rules:
            if rule == root:
                return True
            if rule.startswith("*.") and root == rule[2:]:
                return True
            if rule == f"*.{root}":
                return True
        return False

    @staticmethod
    def derive_keywords(seed_domains: List[str], scope: Optional[Dict[str, List[str]]], max_keywords: int = 10) -> List[str]:
        """Builds small keyword candidates from in-scope seed roots."""
        keywords: List[str] = []
        for seed in seed_domains or []:
            raw = str(seed or "").strip().lower()
            if not raw:
                continue
            if "://" in raw:
                raw = urlparse(raw).hostname or ""
            raw = raw.lstrip("*.").split(":")[0].strip(".")
            if not raw or "." not in raw:
                continue
            root = ".".join(raw.split(".")[-2:]) if len(raw.split(".")) >= 2 else raw
            if not CloudEnumProvider.root_in_scope(root, scope):
                continue
            label = root.split(".")[0]
            for candidate in (root, root.replace(".", "-"), label, label.replace(".", "-")):
                candidate = candidate.strip("-")
                if candidate and candidate not in keywords:
                    keywords.append(candidate)
            if len(keywords) >= max_keywords:
                break
        return keywords[:max_keywords]

    @staticmethod
    def keyword_matches_host(keyword: str, host: str) -> bool:
        """Compares a keyword to a host with punctuation/hyphen normalisation."""
        norm_kw = re.sub(r"[^a-z0-9]", "", (keyword or "").lower())
        norm_host = re.sub(r"[^a-z0-9]", "", (host or "").lower())
        return bool(norm_kw) and norm_kw in norm_host

    @staticmethod
    def parse_cloud_enum_output(lines: List[str], keyword: str) -> List[Dict[str, Any]]:
        """Extracts cloud bucket URLs relevant to *keyword*."""
        results: List[Dict[str, Any]] = []
        seen = set()
        kw = (keyword or "").lower()
        for raw_line in lines or []:
            line = str(raw_line or "").strip()
            if not line:
                continue
            matches = CLOUD_URL_RE.findall(line)
            for url in matches:
                cleaned = url.rstrip(").,;'\"")
                host_match = BUCKET_HOST_RE.search(cleaned)
                host = host_match.group(1).lower() if host_match else (urlparse(cleaned).hostname or "").lower()
                if not host or (kw and not CloudEnumProvider.keyword_matches_host(kw, host)):
                    continue
                if host in seen:
                    continue
                seen.add(host)
                public = any(marker in line.lower() for marker in ("public", "open", "list", "accessible"))
                results.append({
                    "url": cleaned,
                    "host": host,
                    "bucket_name": host.split(".")[0],
                    "public": public,
                    "provider": (
                        "aws" if "amazonaws.com" in host else
                        "azure" if "windows.net" in host else
                        "gcp" if "googleapis.com" in host else "unknown"
                    ),
                })
        return results

    @staticmethod
    def parse_s3scanner_output(output: str, keyword: str) -> List[Dict[str, Any]]:
        results: List[Dict[str, Any]] = []
        lower = (output or "").lower()
        if not any(marker in lower for marker in ("exists", "bucket exists", "public", "readable")):
            return results
        public = "public" in lower or "readable" in lower or "list" in lower
        # s3scanner output includes the bucket name; use the keyword-derived name
        # only if it appears in the output to avoid attributing unrelated buckets.
        if keyword and keyword.lower() not in lower:
            return results
        bucket_name = keyword.strip().lower()
        host = f"{bucket_name}.s3.amazonaws.com"
        results.append({
            "url": f"https://{host}",
            "host": host,
            "bucket_name": bucket_name,
            "public": public,
            "provider": "aws",
        })
        return results

    # ------------------------------------------------------------------
    # Tool helpers
    # ------------------------------------------------------------------

    def _strict_tool(self, tool_name: str) -> Optional[str]:
        try:
            return self.detect_tool(tool_name)
        except Exception:
            return None

    def _tool_prefix(self, tool_path: str) -> List[str]:
        if tool_path.endswith(".py"):
            if platform.system().lower() == "windows":
                return ["wsl", "-e", "python3", self.wsl_path_convert(tool_path)]
            return ["python3", tool_path]
        if platform.system().lower() == "windows":
            return ["wsl", "-e", tool_path]
        return [tool_path]

    async def _run_tool(self, args: List[str], timeout: int) -> Any:
        from app.job_control import register_process, unregister_process, kill_process_tree

        def _run() -> Any:
            proc = subprocess.Popen(
                args,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding="utf-8",
                errors="replace",
            )
            register_process(proc)
            try:
                out, err = proc.communicate(timeout=timeout)
                return proc.returncode, out or "", err or ""
            except subprocess.TimeoutExpired:
                kill_process_tree(proc, "cloud_enum")
                try:
                    out, err = proc.communicate(timeout=5)
                except Exception:
                    out, err = "", ""
                return -1, out or "", err or ""
            finally:
                unregister_process(proc)

        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, _run)

    async def discover(self, seed_domains: List[str], **kwargs: Any) -> AsyncGenerator[Dict[str, Any], None]:
        async for event in self.enumerate(seed_domains, **kwargs):
            yield event

    # ------------------------------------------------------------------
    # Phase entry point
    # ------------------------------------------------------------------

    async def enumerate(
        self,
        seed_domains: List[str],
        scan_mode: str = "fast",
        project_config: Optional[Dict[str, Any]] = None,
        scope: Optional[Dict[str, List[str]]] = None,
    ) -> AsyncGenerator[Dict[str, Any], None]:
        cfg = get_phase8_config(project_config)["cloud_enum"]
        scope_cfg = scope if scope is not None else (project_config or {}).get("scope")

        yield {"type": "log", "message": "\n========== Cloud Bucket Enumeration (Phase 8) =========="}

        if not cfg.get("enabled", False):
            yield {
                "type": "stage_skipped",
                "stage": "Cloud Bucket Enumeration (cloud_enum)",
                "tool": "cloud_enum",
                "reason": "opt_in_disabled",
            }
            yield {"type": "scan_summary", "provider": "cloud_enum", "status": "SKIPPED", "count": 0}
            return

        keywords = self.derive_keywords(
            seed_domains or [],
            scope_cfg,
            max_keywords=int(cfg.get("max_keywords", 10) or 10),
        )
        if not keywords:
            yield {"type": "log", "message": "[*] Cloud Enumeration: no in-scope keywords derivable from seeds."}
            yield {"type": "scan_summary", "provider": "cloud_enum", "status": "SKIPPED", "count": 0, "reason": "no_keywords"}
            return

        cloud_enum_path = self._strict_tool("cloud_enum")
        s3scanner_path = self._strict_tool("s3scanner")
        if not cloud_enum_path:
            yield {"type": "stage_skipped", "stage": "Cloud Bucket Enumeration (cloud_enum)", "tool": "cloud_enum", "reason": "tool_missing: cloud_enum"}
        if not s3scanner_path:
            yield {"type": "stage_skipped", "stage": "Cloud Bucket Enumeration (s3scanner)", "tool": "s3scanner", "reason": "tool_missing: s3scanner"}
        if not cloud_enum_path and not s3scanner_path:
            yield {"type": "scan_summary", "provider": "cloud_enum", "status": "SKIPPED", "count": 0, "reason": "tool_missing"}
            return

        timeout = int(cfg.get("timeout_seconds", 180) or 180)
        start_ts = time.time()
        total = 0
        seen_hosts = set()

        yield {"type": "log", "message": f"[*] Cloud Enumeration: testing {len(keywords)} keyword(s): {', '.join(keywords)}"}

        for keyword in keywords:
            results: List[Dict[str, Any]] = []
            if cloud_enum_path:
                cmd = [*self._tool_prefix(cloud_enum_path), "-k", keyword]
                yield {"type": "log", "message": self.format_cmd_log(cmd)}
                rc, out, err = await self._run_tool(cmd, timeout=timeout)
                if rc in (0, 1, 2):
                    results = self.parse_cloud_enum_output((out or "").splitlines(), keyword)
                else:
                    yield {
                        "type": "stage_error",
                        "stage": "Cloud Bucket Enumeration (cloud_enum)",
                        "tool": "cloud_enum",
                        "returncode": rc,
                        "message": f"cloud_enum exited with code {rc}: {(err or out).strip()[:300]}",
                    }
            elif s3scanner_path:
                candidates = [
                    keyword,
                    f"{keyword}-dev", f"{keyword}-prod", f"{keyword}-staging",
                    f"{keyword}-test", f"{keyword}-backup", f"{keyword}-static",
                ]
                for candidate in candidates[:7]:
                    cmd = [*self._tool_prefix(s3scanner_path), "scan", "--bucket", candidate]
                    yield {"type": "log", "message": self.format_cmd_log(cmd)}
                    rc, out, err = await self._run_tool(cmd, timeout=min(timeout, 60))
                    if rc == 0:
                        results.extend(self.parse_s3scanner_output(out or "", candidate))
                    elif "usage" in (err or out or "").lower():
                        rc2, out2, _ = await self._run_tool(
                            [*self._tool_prefix(s3scanner_path), "--bucket", candidate],
                            timeout=min(timeout, 60),
                        )
                        if rc2 == 0:
                            results.extend(self.parse_s3scanner_output(out2 or "", candidate))

            for bucket in results:
                host = bucket["host"].lower()
                if host in seen_hosts:
                    continue
                # Fail closed: the bucket host must reference one of the in-scope keywords.
                if not self.keyword_matches_host(keyword, host):
                    continue
                seen_hosts.add(host)
                total += 1
                yield {
                    "type": "asset",
                    "data": {
                        "domain": host,
                        "type": "bucket",
                        "value": bucket["url"],
                        "status": "live",
                        "metadata": {
                            "url": bucket["url"],
                            "host": host,
                            "bucket_name": bucket["bucket_name"],
                            "provider": bucket["provider"],
                            "public": bool(bucket.get("public")),
                            "tied_to_keyword": keyword,
                            "in_scope_keyword": keyword,
                            "read_only": True,  # exists/listing checks only; no content download
                            "source": "cloud_enum",
                        },
                        "discovered_by": "cloud_enum",
                        "sources": ["cloud_enum"],
                    },
                }
                yield {
                    "type": "log",
                    "message": f"[+] Cloud bucket candidate: {bucket['url']} (public={bool(bucket.get('public'))})",
                }

        yield {
            "type": "scan_summary",
            "provider": "cloud_enum",
            "status": "completed",
            "count": total,
            "keywords_tested": len(keywords),
            "duration_seconds": int(time.time() - start_ts),
        }
        yield {"type": "log", "message": f"[√] Cloud Enumeration complete: {total} bucket candidate(s)."}
