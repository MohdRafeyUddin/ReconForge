import asyncio
import logging
import platform
import subprocess
from typing import AsyncGenerator, Dict, Any, List

from app.providers.base import BaseProvider

logger = logging.getLogger("reconforge.providers.assetfinder")


class AssetfinderProvider(BaseProvider):

    @property
    def name(self) -> str:
        return "Assetfinder"

    @property
    def description(self) -> str:
        return "Finds domains and subdomains related to a given domain using assetfinder."

    async def discover(
        self,
        seed_domains: List[str]
    ) -> AsyncGenerator[Dict[str, Any], None]:

        msg = (
            f"[*] Assetfinder Provider selected. "
            f"Seed domains received: {', '.join(seed_domains)}"
        )

        logger.info(msg)
        yield {"type": "log", "message": msg}

        is_windows = platform.system().lower() == "windows"

        for domain in seed_domains:

            if is_windows:
                executable = "wsl"
                args = [
                    "/home/kali/go/bin/assetfinder",
                    "--subs-only",
                    domain
                ]
            else:
                executable = "/home/kali/go/bin/assetfinder"
                args = [
                    "--subs-only",
                    domain
                ]

            cmd_str = f"{executable} {' '.join(args)}"

            exec_msg = f"[*] Executing command: {cmd_str}"
            logger.info(exec_msg)
            yield {"type": "log", "message": exec_msg}

            try:

                logger.info(
                    "[*] Launching assetfinder via subprocess.run "
                    f"for domain: {domain}"
                )

                result = subprocess.run(
                    [executable, *args],
                    capture_output=True,
                    text=True,
                    check=False
                )

                logger.info(
                    "[*] Assetfinder process completed for "
                    f"{domain} with exit code {result.returncode}"
                )

                if result.stderr:
                    stderr_msg = (
                        f"[assetfinder stderr] "
                        f"{result.stderr.strip()}"
                    )

                    logger.warning(stderr_msg)

                    yield {
                        "type": "log",
                        "message": stderr_msg
                    }

                discovered_count = 0

                for line in result.stdout.splitlines():

                    subdomain = line.strip()

                    if not subdomain:
                        continue

                    discovered_count += 1

                    logger.info(
                        f"[+] Found subdomain: {subdomain}"
                    )

                    yield {
                        "type": "asset",
                        "data": {
                            "domain": subdomain,
                            "type": "subdomain",
                            "status": "unknown",
                            "open_ports": [],
                            "metadata": {
                                "source": "assetfinder"
                            },
                            "discovered_by": "assetfinder"
                        }
                    }

                logger.info(
                    f"[+] Assetfinder discovered "
                    f"{discovered_count} subdomains "
                    f"for {domain}"
                )

                if result.returncode != 0:

                    err_msg = (
                        f"[-] Assetfinder exited with code "
                        f"{result.returncode}"
                    )

                    logger.error(err_msg)

                    yield {
                        "type": "log",
                        "message": err_msg
                    }

                    raise RuntimeError(err_msg)

            except Exception as e:

                err_msg = (
                    f"[-] Failed to execute assetfinder: {str(e)}"
                )

                logger.exception(err_msg)

                yield {
                    "type": "log",
                    "message": err_msg
                }

                raise

            await asyncio.sleep(0)

        done_msg = "[+] Assetfinder scan complete."

        logger.info(done_msg)

        yield {
            "type": "log",
            "message": done_msg
        }
