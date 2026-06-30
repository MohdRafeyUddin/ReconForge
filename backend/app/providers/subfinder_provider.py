# import asyncio
# import logging
# import platform
# from typing import AsyncGenerator, Dict, Any, List
# from app.providers.base import BaseProvider

# logger = logging.getLogger("reconforge.providers.subfinder")

# class SubfinderProvider(BaseProvider):
#     @property
#     def name(self) -> str:
#         return "Subfinder"
        
#     @property
#     def description(self) -> str:
#         return "Fast passive subdomain enumeration tool using open-source intelligence sources."

#     async def discover(self, seed_domains: List[str]) -> AsyncGenerator[Dict[str, Any], None]:
#         import subprocess

#         msg = f"[*] Subfinder Provider selected. Seed domains received: {', '.join(seed_domains)}"
#         logger.info(msg)
#         yield {"type": "log", "message": msg}

#         is_windows = platform.system().lower() == "windows"

#         for domain in seed_domains:

#             if is_windows:
#                 executable = "wsl"
#             args = ["/home/kali/go/bin/subfinder", "-d", domain, "-silent"]
#         else:
#             executable = "/home/kali/go/bin/subfinder"
#             args = ["-d", domain, "-silent"]

#         cmd_str = f"{executable} {' '.join(args)}"

#         exec_msg = f"[*] Executing command: {cmd_str}"
#         logger.info(exec_msg)
#         yield {"type": "log", "message": exec_msg}

#         try:
#             result = subprocess.run(
#                 [executable, *args],
#                 capture_output=True,
#                 text=True,
#                 check=False
#             )

#             if result.stderr:
#                 stderr_msg = f"[subfinder stderr] {result.stderr.strip()}"
#                 logger.warning(stderr_msg)
#                 yield {"type": "log", "message": stderr_msg}

#             discovered_count = 0

#             for line in result.stdout.splitlines():

#                 subdomain = line.strip()

#                 if not subdomain:
#                     continue

#                 discovered_count += 1

#                 sub_msg = f"[+] Found subdomain: {subdomain}"
#                 logger.info(sub_msg)
#                 yield {"type": "log", "message": sub_msg}

#                 yield {
#                     "type": "asset",
#                     "data": {
#                         "domain": subdomain,
#                         "type": "subdomain",
#                         "status": "unknown",
#                         "open_ports": [],
#                         "metadata": {
#                             "source": "subfinder"
#                         },
#                         "discovered_by": "subfinder"
#                     }
#                 }

#             logger.info(
#                 f"[+] Subfinder discovered {discovered_count} subdomains for {domain}"
#             )

#             if result.returncode != 0:
#                 err_msg = (
#                     f"[-] Subfinder exited with code {result.returncode}"
#                 )
#                 logger.error(err_msg)
#                 yield {"type": "log", "message": err_msg}
#                 raise RuntimeError(err_msg)

#         except Exception as e:
#             err_msg = f"[-] Failed to execute subfinder: {str(e)}"
#             logger.exception(err_msg)
#             yield {"type": "log", "message": err_msg}
#             raise

#     complete_msg = "[√] Subfinder scan complete."
#     logger.info(complete_msg)
#     yield {"type": "log", "message": complete_msg}


import asyncio
import logging
import platform
import subprocess
from typing import AsyncGenerator, Dict, Any, List

from app.providers.base import BaseProvider

logger = logging.getLogger("reconforge.providers.subfinder")


class SubfinderProvider(BaseProvider):

    @property
    def name(self) -> str:
        return "Subfinder"

    @property
    def description(self) -> str:
        return "Fast passive subdomain enumeration tool using open-source intelligence sources."

    async def discover(
        self,
        seed_domains: List[str]
    ) -> AsyncGenerator[Dict[str, Any], None]:

        msg = (
            f"[*] Subfinder Provider selected. "
            f"Seed domains received: {', '.join(seed_domains)}"
        )

        logger.info(msg)
        yield {"type": "log", "message": msg}

        is_windows = platform.system().lower() == "windows"

        for domain in seed_domains:

            if is_windows:
                executable = "wsl"
                args = [
                    "/home/kali/go/bin/subfinder",
                    "-d",
                    domain,
                    "-silent"
                ]
            else:
                executable = "/home/kali/go/bin/subfinder"
                args = [
                    "-d",
                    domain,
                    "-silent"
                ]

            cmd_str = f"{executable} {' '.join(args)}"

            exec_msg = f"[*] Executing command: {cmd_str}"
            logger.info(exec_msg)
            yield {"type": "log", "message": exec_msg}

            try:
                import asyncio
                from app.job_control import register_process, unregister_process, check_job_status
                
                await check_job_status()
                
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
                                    "source": "subfinder"
                                },
                                "discovered_by": "subfinder"
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
                    f"[+] Subfinder discovered "
                    f"{discovered_count} subdomains "
                    f"for {domain}"
                )

                if returncode != 0:

                    err_msg = (
                        f"[-] Subfinder exited with code "
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
                    f"[-] Failed to execute subfinder: {str(e)}"
                )

                logger.exception(err_msg)

                yield {
                    "type": "log",
                    "message": err_msg
                }

                raise

            await asyncio.sleep(0)

        complete_msg = "[√] Subfinder scan complete."

        logger.info(complete_msg)

        yield {
            "type": "log",
            "message": complete_msg
        }