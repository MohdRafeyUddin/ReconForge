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
                import asyncio
                from app.job_control import register_process, unregister_process, check_job_status
                
                await check_job_status()

                logger.info(
                    "[*] Launching assetfinder via Popen "
                    f"for domain: {domain}"
                )

                process = subprocess.Popen(
                    [executable, *args],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    encoding="utf-8",
                    errors="replace"
                )
                register_process(process)

                discovered_count = 0
                try:
                    for line in process.stdout:
                        await check_job_status()
                        subdomain = line.strip().lower()
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
                        await asyncio.sleep(0)
                finally:
                    unregister_process(process)
                    if process.poll() is None:
                        process.terminate()
                        process.wait()

                returncode = process.returncode

                logger.info(
                    f"[+] Assetfinder completed for "
                    f"{domain} with exit code {returncode}"
                )

                logger.info(
                    f"[+] Assetfinder discovered "
                    f"{discovered_count} subdomains "
                    f"for {domain}"
                )

                if returncode != 0:

                    err_msg = (
                        f"[-] Assetfinder exited with code "
                        f"{returncode}"
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
