"""UroProvider
=============
Deduplicates and normalises Katana-collected URLs using uro.

Pipeline position:  … → Katana → **Uro** → GF → Nuclei → …

Responsibilities:
- Accepts a flat list of raw URL strings collected by KatanaProvider.
- Passes them through uro for smart deduplication (drops redundant query-param
  variations while keeping structurally unique endpoints).
- Stores both the original URL and the uro-normalised URL.
- Yields log events and url_event events using the standard ReconForge format.
- Emits a scan_summary event when finished.

uro is intentionally NOT registered as a standalone discovery provider.
UnifiedDiscoveryProvider calls it after Katana.
"""

import asyncio
import logging
import os
import platform
import subprocess
import tempfile
import time
from typing import Any, AsyncGenerator, Dict, List

from app.providers.base import BaseProvider

logger = logging.getLogger("reconforge.providers.uro")


class UroProvider(BaseProvider):
    """URL deduplicator / normaliser powered by uro."""

    @property
    def name(self) -> str:
        return "Uro"

    @property
    def description(self) -> str:
        return (
            "Deduplicates and normalises Katana-collected URLs using uro, "
            "removing redundant query-parameter variants while retaining "
            "structurally unique endpoints."
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

    # ------------------------------------------------------------------
    # Main entry point
    # ------------------------------------------------------------------

    async def discover(
        self, seed_domains: List[str]
    ) -> AsyncGenerator[Dict[str, Any], None]:
        """
        seed_domains – raw URL strings collected by KatanaProvider.
        (The parameter is named seed_domains for BaseProvider compatibility;
         in this stage it carries URLs, not hostnames.)
        """
        # Deduplicate input while preserving order
        raw_urls = list(dict.fromkeys(u.strip() for u in seed_domains if u and u.strip()))

        yield {"type": "log", "message": "\n========== Uro URL Normalisation =========="}
        yield {"type": "log", "message": "Launching Uro..."}
        yield {"type": "log", "message": f"Processing {len(raw_urls)} raw URLs..."}

        if not raw_urls:
            msg = "Uro completed. No URLs provided."
            logger.info(msg)
            yield {"type": "log", "message": msg}
            yield {
                "type": "scan_summary",
                "provider": self.name,
                "input_urls": 0,
                "normalised_urls": 0,
                "removed": 0,
            }
            return

        is_windows = platform.system().lower() == "windows"
        # uro is a Python CLI tool; invoke as 'python -m uro' or direct 'uro'
        executable = "wsl" if is_windows else "uro"
        temp_path = ""
        start_ts = time.time()

        normalised_urls: List[str] = []

        try:
            # Write raw URLs to a temp file and feed via stdin / -i flag
            with tempfile.NamedTemporaryFile(
                mode="w",
                encoding="utf-8",
                delete=False,
                suffix=".txt",
                dir=os.getcwd(),
            ) as target_file:
                target_file.write("\n".join(raw_urls))
                target_file.write("\n")
                temp_path = target_file.name

            list_path = (
                self._windows_path_to_wsl(temp_path) if is_windows else temp_path
            )

            if is_windows:
                cmd = [executable, "uro", "-i", list_path]
            else:
                cmd = [executable, "-i", list_path]

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

                for raw_line in process.stdout:
                    await check_job_status()
                    normalised = raw_line.strip()
                    if not normalised:
                        continue

                    normalised_urls.append(normalised)
                    logger.debug("[uro] %s", normalised)

                    yield {
                        "type": "url_event",
                        "data": {
                            "url": normalised,
                            "original_url": normalised,   # uro output is already normalised
                            "source": "uro",
                            "normalised": True,
                        },
                    }
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
                logger.warning("[uro stderr] %s", stderr_out.strip())
                yield {"type": "log", "message": f"[uro stderr] {stderr_out.strip()}"}

        except Exception as exc:
            logger.exception("[-] UroProvider failed: %s", exc)
            yield {"type": "log", "message": f"[-] UroProvider failed: {exc}"}

        finally:
            if temp_path:
                try:
                    os.unlink(temp_path)
                except OSError:
                    logger.warning("Failed to remove Uro input file: %s", temp_path)

        removed = len(raw_urls) - len(normalised_urls)
        duration_s = int(time.time() - start_ts)
        complete_msg = (
            f"Uro completed. "
            f"Input: {len(raw_urls)} | "
            f"Normalised: {len(normalised_urls)} | "
            f"Removed: {removed} | "
            f"Duration: {duration_s}s"
        )
        logger.info(complete_msg)
        yield {"type": "log", "message": complete_msg}
        yield {
            "type": "scan_summary",
            "provider": self.name,
            "input_urls": len(raw_urls),
            "normalised_urls": len(normalised_urls),
            "removed": removed,
            "duration_seconds": duration_s,
        }
