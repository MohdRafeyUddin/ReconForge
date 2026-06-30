"""GfProvider
============
Classifies normalised URLs into vulnerability-class buckets using gf patterns.

Pipeline position:  … → Uro → **GF** → Nuclei → …

Responsibilities:
- Accepts a flat list of normalised URL strings (output of UroProvider).
- Runs gf against each supported pattern.
- Supported categories (matching the project requirements):
      xss, sqli, ssrf, redirect, lfi, rce, idor, ssti,
      debug, upload, aws, graphql
- A URL may match multiple categories.
- Yields log events and gf_event events using the standard ReconForge format.
- Emits a scan_summary event when finished.

gf is intentionally NOT registered as a standalone discovery provider.
UnifiedDiscoveryProvider calls it after Uro.
"""

import asyncio
import logging
import os
import platform
import subprocess
import tempfile
import time
from collections import defaultdict
from typing import Any, AsyncGenerator, Dict, List, Set

from app.providers.base import BaseProvider

logger = logging.getLogger("reconforge.providers.gf")

# Ordered list of gf pattern names to run (must match ~/.gf/*.json filenames)
GF_PATTERNS: List[str] = [
    "xss",
    "sqli",
    "ssrf",
    "redirect",
    "lfi",
    "rce",
    "idor",
    "ssti",
    "debug-pages",   # gf pattern name; mapped to "debug" in output
    "upload-fields", # gf pattern name; mapped to "upload" in output
    "aws-keys",      # gf pattern name; mapped to "aws" in output
    "graphql",
]

# Map gf pattern names to canonical category labels used in storage
PATTERN_TO_CATEGORY: Dict[str, str] = {
    "xss": "xss",
    "sqli": "sqli",
    "ssrf": "ssrf",
    "redirect": "redirect",
    "lfi": "lfi",
    "rce": "rce",
    "idor": "idor",
    "ssti": "ssti",
    "debug-pages": "debug",
    "upload-fields": "upload",
    "aws-keys": "aws",
    "graphql": "graphql",
}


class GfProvider(BaseProvider):
    """URL classifier powered by gf patterns."""

    @property
    def name(self) -> str:
        return "GF"

    @property
    def description(self) -> str:
        return (
            "Classifies normalised URLs by vulnerability category using gf pattern "
            "matching (xss, sqli, ssrf, redirect, lfi, rce, idor, ssti, debug, "
            "upload, aws, graphql)."
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

    async def _run_pattern(
        self,
        pattern: str,
        list_path: str,
        is_windows: bool,
    ) -> List[str]:
        """Run gf for a single pattern and return matched URLs.

        Returns an empty list if gf exits non-zero or the pattern file is
        missing (gf silently exits 1 when the pattern does not exist).
        """
        executable = "wsl" if is_windows else "gf"
        gf_bin = "/home/kali/go/bin/gf"
        args = [gf_bin] if is_windows else []
        # gf reads input from a file via stdin redirect or can accept piped input
        # Use: cat file | gf <pattern>
        # We open the file and pipe it via stdin instead of shell=True for safety.
        cmd = [executable, *args, pattern]

        try:
            from app.job_control import check_job_status
            await check_job_status()

            with open(list_path, "r", encoding="utf-8", errors="replace") as fh:
                process = subprocess.Popen(
                    cmd,
                    stdin=fh,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    bufsize=1,
                )

            matched: List[str] = []
            try:
                assert process.stdout is not None
                for raw_line in process.stdout:
                    await check_job_status()
                    url = raw_line.strip()
                    if url:
                        matched.append(url)
                    await asyncio.sleep(0)
            finally:
                if process.poll() is None:
                    process.terminate()
                    process.wait()

            return matched

        except Exception as exc:
            logger.warning("gf pattern '%s' failed: %s", pattern, exc)
            return []

    # ------------------------------------------------------------------
    # Main entry point
    # ------------------------------------------------------------------

    async def discover(
        self, seed_domains: List[str]
    ) -> AsyncGenerator[Dict[str, Any], None]:
        """
        seed_domains – normalised URL strings from UroProvider.
        (Named seed_domains for BaseProvider compatibility.)
        """
        urls = list(dict.fromkeys(u.strip() for u in seed_domains if u and u.strip()))

        yield {"type": "log", "message": "\n========== GF Pattern Classification =========="}
        yield {"type": "log", "message": "Launching GF..."}
        yield {"type": "log", "message": f"Classifying {len(urls)} URLs across {len(GF_PATTERNS)} patterns..."}

        if not urls:
            msg = "GF completed. No URLs provided."
            logger.info(msg)
            yield {"type": "log", "message": msg}
            yield {
                "type": "scan_summary",
                "provider": self.name,
                "urls_classified": 0,
                "matches_by_category": {},
            }
            return

        is_windows = platform.system().lower() == "windows"
        temp_path = ""
        start_ts = time.time()

        # url → set of categories
        url_categories: Dict[str, Set[str]] = defaultdict(set)
        matches_by_category: Dict[str, int] = {}

        try:
            # Write URLs to a temp file — shared across all pattern runs
            with tempfile.NamedTemporaryFile(
                mode="w",
                encoding="utf-8",
                delete=False,
                suffix=".txt",
                dir=os.getcwd(),
            ) as target_file:
                target_file.write("\n".join(urls))
                target_file.write("\n")
                temp_path = target_file.name

            list_path = (
                self._windows_path_to_wsl(temp_path) if is_windows else temp_path
            )

            for pattern in GF_PATTERNS:
                category = PATTERN_TO_CATEGORY.get(pattern, pattern)

                from app.job_control import check_job_status
                await check_job_status()

                pattern_msg = f"[*] Running gf pattern: {pattern}"
                logger.info(pattern_msg)
                yield {"type": "log", "message": pattern_msg}

                matched = await self._run_pattern(pattern, list_path, is_windows)
                matches_by_category[category] = len(matched)

                for url in matched:
                    url_categories[url].add(category)

                if matched:
                    hit_msg = f"[+] {pattern}: {len(matched)} matches"
                    logger.info(hit_msg)
                    yield {"type": "log", "message": hit_msg}
                else:
                    yield {"type": "log", "message": f"[-] {pattern}: 0 matches"}

                await asyncio.sleep(0)

            # Emit gf_event for each classified URL
            for url, categories in sorted(url_categories.items()):
                cat_list = sorted(categories)
                log_msg = f"[+] {url} → {', '.join(cat_list)}"
                logger.info(log_msg)
                yield {"type": "log", "message": log_msg}

                yield {
                    "type": "gf_event",
                    "data": {
                        "url": url,
                        "categories": cat_list,
                        "source": "gf",
                        "classified_at": int(time.time()),
                    },
                }
                await asyncio.sleep(0)

        except Exception as exc:
            logger.exception("[-] GfProvider failed: %s", exc)
            yield {"type": "log", "message": f"[-] GfProvider failed: {exc}"}

        finally:
            if temp_path:
                try:
                    os.unlink(temp_path)
                except OSError:
                    logger.warning("Failed to remove GF input file: %s", temp_path)

        duration_s = int(time.time() - start_ts)
        total_classified = len(url_categories)
        complete_msg = (
            f"GF completed. "
            f"URLs classified: {total_classified} | "
            f"Duration: {duration_s}s"
        )
        logger.info(complete_msg)
        yield {"type": "log", "message": complete_msg}
        yield {
            "type": "scan_summary",
            "provider": self.name,
            "urls_classified": total_classified,
            "matches_by_category": matches_by_category,
            "duration_seconds": duration_s,
        }
