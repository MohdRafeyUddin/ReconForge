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

        msg = (
            f"[*] Amass Provider selected (passive mode). "
            f"Seed domains received: {', '.join(seed_domains)}"
        )

        logger.info(msg)
        yield {"type": "log", "message": msg}

        is_windows = platform.system().lower() == "windows"
        seen_subdomains: Set[str] = set()
        total_discovered = 0

        for domain in seed_domains:
            if is_windows:
                executable = "wsl"
                args = [
                    "/home/kali/go/bin/amass",
                    "enum",
                    "-passive",
                    "-d",
                    domain
                ]
            else:
                executable = "/home/kali/go/bin/amass"
                args = [
                    "enum",
                    "-passive",
                    "-d",
                    domain
                ]

            cmd_str = f"{executable} {' '.join(args)}"

            exec_msg = f"[*] Executing command: {cmd_str}"
            logger.info(exec_msg)
            yield {"type": "log", "message": exec_msg}

            try:

                logger.info(
                    "[*] Launching amass via subprocess.Popen "
                    f"for domain: {domain}"
                )

                process = subprocess.Popen(
                    [executable, *args],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    bufsize=1,
                    universal_newlines=True,
                )

                domain_count = 0

                # Stream stdout line-by-line while the process is running.
                # Avoid blocking the event loop by performing blocking reads in a thread.
                try:
                    while True:
                        line = await asyncio.to_thread(process.stdout.readline)
                        if not line:
                            break

                        logger.info(f"RAW STDOUT: {repr(line)}")

                        candidate = line.strip()

                        if not candidate:
                            continue

                        # Parse Amass graph output lines.
                        # Example:
                        #   hackerone.com (FQDN) --> node --> docs.hackerone.com (FQDN)
                        # Extract the destination FQDN on the right side of the graph chain.
                        subdomain = candidate

                        if "-->" in subdomain:
                            parts = subdomain.split("-->")
                            subdomain = parts[-1].strip() if parts else ""

                        # Drop Amass type suffixes like "(FQDN)", "(ASN)", etc.
                        subdomain = subdomain.replace("(FQDN)", "")
                        subdomain = subdomain.replace("(IPAddress)", "")
                        subdomain = subdomain.replace("(IPv6)", "")
                        subdomain = subdomain.replace("(ASN)", "")
                        subdomain = subdomain.replace("(Netblock)", "")

                        # Remove common Amass adornments like brackets/parentheses leftovers.
                        subdomain = subdomain.strip(" []()\t\r\n")


                        # Must be a hostname ending with the scanned domain.
                        # Allow either exact match or subdomain match.
                        domain_lc = domain.lower().strip()
                        subdomain_lc = subdomain.lower()
                        if subdomain_lc == domain_lc:
                            pass
                        elif subdomain_lc.endswith(f".{domain_lc}"):
                            pass
                        else:
                            continue


                        # Reject anything containing whitespace.
                        if any(ch.isspace() for ch in subdomain):
                            continue

                        # Ignore IPs/IPv6 literals.
                        if ':' in subdomain:
                            continue
                        if subdomain.replace('.', '').isdigit():
                            continue

                        # Ignore ASN / Netblock relationship tokens.
                        if subdomain.isdigit():
                            continue


                        # Require a conservative hostname character set.
                        if not all((ch.isalnum() or ch in ['-', '.']) for ch in subdomain):
                            continue

                        # Length guard (basic).
                        if len(subdomain) > 253:
                            continue

                        # Ignore MX targets outside the scanned domain: filter happens by
                        # the domain membership check below (must end with scanned domain).

                        # Basic dedup.
                        if subdomain in seen_subdomains:


                            logger.info(
                                f"[*] Skipping duplicate Amass subdomain: {subdomain}"
                            )
                            continue

                        seen_subdomains.add(subdomain)
                        domain_count += 1
                        total_discovered += 1

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
                                    "source": "amass"
                                },
                                "discovered_by": "amass"
                            }
                        }
                finally:
                    # Ensure we wait for process completion after stdout is drained.
                    exit_code = process.wait()


                    # Drain remaining stderr (best-effort) after completion.
                    try:
                        if process.stderr:
                            stderr_text = process.stderr.read()
                        else:
                            stderr_text = ""
                    except Exception:
                        stderr_text = ""

                    logger.info(
                        "[*] Amass process completed for "
                        f"{domain} with exit code {exit_code}"
                    )

                    if stderr_text and stderr_text.strip():
                        stderr_msg = (
                            f"[amass stderr] "
                            f"{stderr_text.strip()}"
                        )

                        logger.warning(stderr_msg)

                        yield {
                            "type": "log",
                            "message": stderr_msg
                        }

                logger.info(
                    f"[+] Amass discovered "
                    f"{domain_count} new subdomains "
                    f"for {domain}"
                )

                if exit_code != 0:


                    err_msg = (
                        f"[-] Amass exited with code "
                        f"{exit_code}"
                    )

                    logger.error(err_msg)

                    yield {
                        "type": "log",
                        "message": err_msg
                    }

                    raise RuntimeError(err_msg)


            except Exception as e:

                err_msg = (
                    f"[-] Failed to execute amass: {str(e)}"

                )

                logger.exception(err_msg)

                yield {
                    "type": "log",
                    "message": err_msg
                }

                raise

            await asyncio.sleep(0)

        complete_msg = (
            f"[+] Amass passive scan complete. "
            f"Discovered {total_discovered} unique subdomains."
        )

        logger.info(complete_msg)

        yield {
            "type": "log",
            "message": complete_msg
        }
