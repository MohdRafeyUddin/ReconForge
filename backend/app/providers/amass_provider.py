import asyncio
import logging
import platform
import subprocess
from typing import AsyncGenerator, Dict, Any, List, Set

from app.providers.base import BaseProvider

logger = logging.getLogger("reconforge.providers.amass")


class AmassProvider(BaseProvider):

    @property
    def name(self) -> str:
        return "Amass"

    @property
    def description(self) -> str:
        return "In-depth Attack Surface Mapping using passive enumeration via Amass."

    async def discover(
        self,
        seed_domains: List[str]
    ) -> AsyncGenerator[Dict[str, Any], None]:

        # Keep only the requested Executing Amass... log
        logger.info("Executing Amass...")
        yield {"type": "log", "message": "Executing Amass..."}

        is_windows = platform.system().lower() == "windows"
        seen_subdomains: Set[str] = set()

        for domain in seed_domains:
            if is_windows:
                executable = "wsl"
                args = [
                    "/snap/bin/amass",
                    "enum",
                    "-passive",
                    "-d",
                    domain
                ]
            else:
                executable = "/snap/bin/amass"
                args = [
                    "enum",
                    "-passive",
                    "-d",
                    domain
                ]

            try:
                from app.job_control import register_process, unregister_process, check_job_status
                await check_job_status()

                process = subprocess.Popen(
                    [executable, *args],
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
                        line = raw_line.strip()
                        if not line:
                            continue

                        # Trim whitespace and convert to lowercase
                        subdomain = line.lower().strip()

                        # Verify it belongs to the scanned root domain
                        domain_lc = domain.lower().strip()
                        if subdomain == domain_lc or subdomain.endswith(f".{domain_lc}"):
                            pass
                        else:
                            continue

                        # Deduplicate
                        if subdomain in seen_subdomains:
                            continue
                        seen_subdomains.add(subdomain)

                        # Keep only Found subdomain... log
                        sub_msg = f"Found subdomain: {subdomain}"
                        logger.info(sub_msg)
                        yield {"type": "log", "message": sub_msg}

                        # Immediately emit asset event
                        yield {
                            "type": "asset",
                            "data": {
                                "domain": subdomain,
                                "type": "subdomain",
                                "status": "unknown",
                                "open_ports": [],
                                "metadata": {
                                    "source": "amass"
                                },
                                "discovered_by": "amass"
                            }
                        }

                        await asyncio.sleep(0)
                finally:
                    unregister_process(process)
                    if process.poll() is None:
                        process.terminate()
                        process.wait()

            except Exception as e:
                logger.exception(f"[-] Failed to execute amass: {str(e)}")
                raise

            await asyncio.sleep(0)

        # Keep only Amass completed. log
        logger.info("Amass completed.")
        yield {
            "type": "log",
            "message": "Amass completed."
        }
