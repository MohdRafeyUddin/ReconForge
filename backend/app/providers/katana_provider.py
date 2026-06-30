"""Internal Katana provider for web crawling and endpoint discovery.

Katana is executed internally as part of the Unified Discovery pipeline
after Naabu. It crawls only LIVE hosts (using their probed HTTP/HTTPS URLs).
"""

import asyncio
import json
import logging
import os
import platform
import subprocess
import tempfile
import time
from collections import defaultdict
from typing import AsyncGenerator, Dict, Any, List, Optional
import re
from urllib.parse import urlparse, urljoin, unquote

from app.providers.base import BaseProvider

logger = logging.getLogger("reconforge.providers.katana")

IGNORED_EXTENSIONS = {
    "png", "jpg", "jpeg", "gif", "svg", "webp", "ico", "css",
    "woff", "woff2", "ttf", "eot", "otf", "mp3", "mp4", "avi",
    "mov", "webm", "zip", "rar", "7z"
}

def is_ignored_resource(url_str: str) -> bool:
    try:
        parsed = urlparse(url_str)
        path = parsed.path.lower()
        if "." in path:
            ext = path.rsplit(".", 1)[-1]
            if ext in IGNORED_EXTENSIONS:
                return True
    except Exception:
        pass
    return False

def normalize_url(url_str: str) -> Optional[str]:
    if not url_str or not isinstance(url_str, str):
        return None
    try:
        # Decode malformed escaped paths/parameters
        decoded = unquote(url_str.strip())
        
        # Replace backslashes in paths with forward slashes (e.g., %5C)
        decoded = decoded.replace("\\", "/")
        
        parsed = urlparse(decoded)
        scheme = parsed.scheme.lower()
        netloc = parsed.netloc.lower()
        
        if not scheme or not netloc:
            return None # Reject malformed
            
        path = parsed.path
        # Collapse duplicate slashes
        while "//" in path:
            path = path.replace("//", "/")
            
        # Remove trailing slash except for root path "/"
        if path.endswith("/") and len(path) > 1:
            path = path.rstrip("/")
            
        # Reconstruct normalized URL
        normalized = f"{scheme}://{netloc}{path}"
        if parsed.query:
            normalized += f"?{parsed.query}"
        return normalized
    except Exception:
        return None

def classify_endpoint(url_str: str) -> str:
    try:
        parsed = urlparse(url_str)
        path = parsed.path.lower()
        query = parsed.query.lower()
        combined = f"{path}?{query}" if query else path
        
        if any(kw in combined for kw in ["login", "signin", "auth", "oauth", "session"]):
            return "Login"
        if any(kw in combined for kw in ["register", "signup", "join", "create-account"]):
            return "Register"
        if any(kw in combined for kw in ["graphql", "gql"]):
            return "GraphQL"
        if any(kw in combined for kw in ["api", "v1", "v2", "v3", "rest", "endpoint", "json"]):
            return "API"
        if any(kw in combined for kw in ["admin", "dashboard", "portal", "console", "manager", "root"]):
            return "Admin"
        if any(kw in combined for kw in ["doc", "docs", "help", "guide", "manual", "faq"]):
            return "Documentation"
        if path.endswith((".js", ".mjs")):
            return "Static JS"
        if any(kw in combined for kw in ["form", "contact", "submit", "feedback"]):
            return "Forms"
        return "Other"
    except Exception:
        return "Other"


class KatanaProvider(BaseProvider):
    @property
    def name(self) -> str:
        return "Katana"

    @property
    def description(self) -> str:
        return "Internal web crawler and endpoint discovery tool for LIVE HTTP/HTTPS hosts."

    @staticmethod
    def _windows_path_to_wsl(path: str) -> str:
        drive, rest = os.path.splitdrive(os.path.abspath(path))
        drive_letter = drive.rstrip(":").lower()
        rest = rest.replace("\\", "/")
        return f"/mnt/{drive_letter}{rest}"

    async def discover(self, seed_domains: List[str]) -> AsyncGenerator[Dict[str, Any], None]:
        # seed_domains here represents target URLs (e.g. http://host or https://host)
        targets = list(dict.fromkeys(t.strip() for t in seed_domains if t and t.strip()))

        yield {"type": "log", "message": "\n========== Katana =========="}
        yield {"type": "log", "message": "Launching Katana..."}
        yield {"type": "log", "message": f"Crawling {len(targets)} LIVE targets..."}

        if not targets:
            msg = "Katana completed. No LIVE targets to crawl."
            logger.info(msg)
            yield {"type": "log", "message": msg}
            yield {"type": "scan_summary", "provider": self.name, "targets_scanned": 0, "urls_found": 0}
            return

        is_windows = platform.system().lower() == "windows"
        executable = "wsl" if is_windows else "/home/kali/go/bin/katana"
        
        # Structure to collect results aggregated by target hostname
        # hostname -> {urls, js_files, endpoints, forms, third_party_urls, classified_endpoints}
        crawled_data: Dict[str, Dict[str, Any]] = defaultdict(
            lambda: {
                "urls": set(),
                "js_files": set(),
                "endpoints": set(),
                "forms": [],
                "third_party_urls": set(),
                "classified_endpoints": defaultdict(list)
            }
        )

        # Build map of hostname -> list of scanned domains to associate results properly
        target_hosts = set()
        for t in targets:
            parsed = urlparse(t)
            h = parsed.hostname or parsed.path
            if ":" in h:
                h = h.split(":", 1)[0]
            if h:
                target_hosts.add(h.lower().strip())

        start_ts = time.time()
        total_urls_discovered = 0
        total_duplicates_skipped = 0
        total_resources_ignored = 0
        total_third_party_ignored = 0
        hosts_crawled = 0

        visited_urls = set()

        for target in targets:
            try:
                # normalise session_host from target
                parsed_target = urlparse(target)
                session_host = parsed_target.hostname or parsed_target.path
                if ":" in session_host:
                    session_host = session_host.split(":", 1)[0]
                session_host = session_host.lower().strip()

                yield {"type": "log", "message": f"\n[*] Starting Crawl Session: {target}"}
                hosts_crawled += 1

                args = ["/home/kali/go/bin/katana"] if is_windows else []
                katana_flags = [
                    "-u", target,
                    "-jc",            # Enable JavaScript crawling
                    "-fx",            # Enable automatic form extraction
                    "-j",             # Output JSONL format
                    "-silent",        # Silent mode
                    "-duc",           # Disable update check
                    "-d", "2",        # Max depth of 2
                    "-c", "10",       # Concurrency
                    "-rl", "100",     # Rate limit
                    "-timeout", "10", # Timeout per request
                    "-ef", "png,jpg,jpeg,gif,svg,webp,ico,css,woff,woff2,ttf,eot,otf,mp3,mp4,avi,mov,webm,zip,rar,7z", # Exclude static asset extensions
                ]
                cmd = [executable, *args, *katana_flags]

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
                        line = (raw_line or "").strip()
                        if not line:
                            continue

                        try:
                            record = json.loads(line)
                        except Exception:
                            continue

                        # Extract discovered URL from record["request"]["endpoint"]
                        url = record.get("request", {}).get("endpoint")
                        if not url:
                            continue

                        total_urls_discovered += 1

                        # 1. Global URL Deduplication
                        norm_url = normalize_url(url)
                        if not norm_url:
                            continue # Reject malformed
                            
                        if norm_url in visited_urls:
                            total_duplicates_skipped += 1
                            continue
                        visited_urls.add(norm_url)

                        # Extract host to verify if first-party
                        try:
                            parsed_url = urlparse(norm_url)
                            host = parsed_url.hostname or ""
                            host = host.lower().strip()
                        except Exception:
                            continue

                        if not host:
                            continue

                        # Check first-party vs third-party
                        is_first_party = False
                        matched_host = None
                        if host in target_hosts:
                            is_first_party = True
                            matched_host = host
                        else:
                            for th in target_hosts:
                                if host.endswith("." + th) or th.endswith("." + host):
                                    is_first_party = True
                                    matched_host = th
                                    break

                        if is_first_party:
                            # 4. Ignore Static Resources
                            if is_ignored_resource(norm_url):
                                total_resources_ignored += 1
                                continue

                            # Store first-party URL
                            crawled_data[matched_host]["urls"].add(norm_url)

                            # JavaScript files detection
                            is_js = parsed_url.path.lower().endswith((".js", ".mjs"))
                            if is_js:
                                crawled_data[matched_host]["js_files"].add(norm_url)

                            # Classify Endpoint
                            category = classify_endpoint(norm_url)
                            if norm_url not in crawled_data[matched_host]["classified_endpoints"][category]:
                                crawled_data[matched_host]["classified_endpoints"][category].append(norm_url)

                            # Endpoint detection (HTTP Method + Path)
                            method = record.get("request", {}).get("method") or "GET"
                            path = parsed_url.path or "/"
                            if parsed_url.query:
                                path += f"?{parsed_url.query}"
                            endpoint_str = f"{method} {path}"

                            if is_ignored_resource(path):
                                total_resources_ignored += 1
                            else:
                                crawled_data[matched_host]["endpoints"].add(endpoint_str)
                        else:
                            # Third-party URL handling
                            if is_ignored_resource(norm_url):
                                total_resources_ignored += 1
                                continue
                            
                            total_third_party_ignored += 1
                            crawled_data[session_host]["third_party_urls"].add(norm_url)
                            continue

                        # Parse HTML response body from record["response"]["body"]
                        body = record.get("response", {}).get("body") or ""
                        if body:
                            # Extract JavaScript files
                            js_matches = re.findall(r'<script\s+[^>]*src=["\']([^"\']+)["\']', body, re.IGNORECASE)
                            for js_src in js_matches:
                                absolute_js = urljoin(url, js_src)
                                norm_js = normalize_url(absolute_js)
                                if not norm_js:
                                    continue
                                
                                total_urls_discovered += 1
                                if norm_js in visited_urls:
                                    total_duplicates_skipped += 1
                                    continue
                                visited_urls.add(norm_js)

                                try:
                                    js_parsed = urlparse(norm_js)
                                    js_host = (js_parsed.hostname or "").lower().strip()
                                except Exception:
                                    continue

                                # First vs Third party check for JS
                                is_js_first = False
                                js_matched_host = None
                                if js_host in target_hosts:
                                    is_js_first = True
                                    js_matched_host = js_host
                                else:
                                    for th in target_hosts:
                                        if js_host.endswith("." + th) or th.endswith("." + js_host):
                                            is_js_first = True
                                            js_matched_host = th
                                            break

                                if is_js_first:
                                    if is_ignored_resource(norm_js):
                                        total_resources_ignored += 1
                                        continue
                                    crawled_data[js_matched_host]["js_files"].add(norm_js)
                                    crawled_data[js_matched_host]["urls"].add(norm_js)
                                    # Classify JS
                                    category = classify_endpoint(norm_js)
                                    if norm_js not in crawled_data[js_matched_host]["classified_endpoints"][category]:
                                        crawled_data[js_matched_host]["classified_endpoints"][category].append(norm_js)
                                else:
                                    if is_ignored_resource(norm_js):
                                        total_resources_ignored += 1
                                        continue
                                    total_third_party_ignored += 1
                                    crawled_data[session_host]["third_party_urls"].add(norm_js)

                            # Extract links/endpoints
                            href_matches = re.findall(r'<a\s+[^>]*href=["\']([^"\']+)["\']', body, re.IGNORECASE)
                            for href in href_matches:
                                if href.startswith("#") or href.lower().startswith("javascript:"):
                                    continue
                                absolute_href = urljoin(url, href)
                                norm_href = normalize_url(absolute_href)
                                if not norm_href:
                                    continue
                                
                                total_urls_discovered += 1
                                if norm_href in visited_urls:
                                    total_duplicates_skipped += 1
                                    continue
                                visited_urls.add(norm_href)

                                try:
                                    href_parsed = urlparse(norm_href)
                                    href_host = (href_parsed.hostname or "").lower().strip()
                                except Exception:
                                    continue

                                # First vs Third party check for href
                                is_href_first = False
                                href_matched_host = None
                                if href_host in target_hosts:
                                    is_href_first = True
                                    href_matched_host = href_host
                                else:
                                    for th in target_hosts:
                                        if href_host.endswith("." + th) or th.endswith("." + href_host):
                                            is_href_first = True
                                            href_matched_host = th
                                            break

                                if is_href_first:
                                    if is_ignored_resource(norm_href):
                                        total_resources_ignored += 1
                                        continue

                                    href_path = href_parsed.path or "/"
                                    if href_parsed.query:
                                        href_path += f"?{href_parsed.query}"
                                    
                                    crawled_data[href_matched_host]["endpoints"].add(f"GET {href_path}")
                                    crawled_data[href_matched_host]["urls"].add(norm_href)
                                    # Classify endpoint
                                    category = classify_endpoint(norm_href)
                                    if norm_href not in crawled_data[href_matched_host]["classified_endpoints"][category]:
                                        crawled_data[href_matched_host]["classified_endpoints"][category].append(norm_href)
                                else:
                                    if is_ignored_resource(norm_href):
                                        total_resources_ignored += 1
                                        continue
                                    total_third_party_ignored += 1
                                    crawled_data[session_host]["third_party_urls"].add(norm_href)

                            # Extract forms
                            form_matches = re.finditer(r'<form\s+([^>]*?)>(.*?)</form>', body, re.IGNORECASE | re.DOTALL)
                            for form_match in form_matches:
                                form_attrs = form_match.group(1)
                                form_inner = form_match.group(2)

                                action_m = re.search(r'action=["\']([^"\']+)["\']', form_attrs, re.IGNORECASE)
                                method_m = re.search(r'method=["\']([^"\']+)["\']', form_attrs, re.IGNORECASE)

                                action = action_m.group(1) if action_m else ""
                                method_method = method_m.group(1).upper() if method_m else "GET"

                                absolute_action = urljoin(url, action)
                                norm_action = normalize_url(absolute_action)
                                if not norm_action:
                                    continue

                                # Check ignored resource on action
                                if is_ignored_resource(norm_action):
                                    total_resources_ignored += 1
                                    continue

                                try:
                                    action_parsed = urlparse(norm_action)
                                    action_host = (action_parsed.hostname or "").lower().strip()
                                except Exception:
                                    continue

                                # First vs Third party check for action
                                is_action_first = False
                                action_matched_host = None
                                if action_host in target_hosts:
                                    is_action_first = True
                                    action_matched_host = action_host
                                else:
                                    for th in target_hosts:
                                        if action_host.endswith("." + th) or th.endswith("." + action_host):
                                            is_action_first = True
                                            action_matched_host = th
                                            break

                                if is_action_first:
                                    fields = []
                                    input_matches = re.finditer(r'<input\s+([^>]*?)>', form_inner, re.IGNORECASE)
                                    for input_match in input_matches:
                                        input_attrs = input_match.group(1)
                                        name_m = re.search(r'name=["\']([^"\']+)["\']', input_attrs, re.IGNORECASE)
                                        type_m = re.search(r'type=["\']([^"\']+)["\']', input_attrs, re.IGNORECASE)
                                        if name_m:
                                            fields.append({
                                                "name": name_m.group(1),
                                                "type": type_m.group(1) if type_m else "text"
                                            })

                                    form_obj = {
                                        "action": norm_action,
                                        "method": method_method,
                                        "fields": fields
                                    }

                                    if form_obj not in crawled_data[action_matched_host]["forms"]:
                                        crawled_data[action_matched_host]["forms"].append(form_obj)
                                else:
                                    total_third_party_ignored += 1
                                    crawled_data[session_host]["third_party_urls"].add(norm_action)

                        # Yield real-time streaming progress to websocket console
                        progress_msg = f"[+] Discovered URL on {matched_host}: {norm_url}"
                        yield {"type": "log", "message": progress_msg}

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
                    pass

                if stderr_out.strip():
                    logger.warning(f"[katana stderr] {stderr_out.strip()}")
                    yield {"type": "log", "message": f"[katana stderr] {stderr_out.strip()}"}

                exit_code = process.wait()
                if exit_code != 0:
                    msg = f"[-] Katana exited with code: {exit_code} for target {target}"
                    logger.error(msg)
                    yield {"type": "log", "message": msg}

            except Exception as target_exc:
                logger.warning(f"[-] Crawl session failed for {target}: {target_exc}")
                yield {"type": "log", "message": f"[-] Crawl session failed for {target}: {str(target_exc)}"}

        # Yield asset enrichment events
        for host, data in crawled_data.items():
            yield {
                "type": "asset",
                "data": {
                    "domain": host,
                    "type": "subdomain",
                    "status": "live",
                    "metadata": {
                        "source": "katana",
                        "katana": {
                            "urls": sorted(list(data["urls"])),
                            "js_files": sorted(list(data["js_files"])),
                            "endpoints": sorted(list(data["endpoints"])),
                            "forms": data["forms"],
                            "third_party_urls": sorted(list(data["third_party_urls"])),
                            "classified_endpoints": {
                                cat: sorted(list(urls))
                                for cat, urls in data["classified_endpoints"].items()
                            },
                            "scanned_at": int(time.time()),
                        },
                    },
                    "discovered_by": "katana",
                    "sources": ["katana"],
                },
            }

        duration_s = int(time.time() - start_ts)
        
        # Calculate statistics
        total_urls_stored = sum(len(data["urls"]) for data in crawled_data.values())
        total_js_stored = sum(len(data["js_files"]) for data in crawled_data.values())
        total_forms_discovered = sum(len(data["forms"]) for data in crawled_data.values())
        
        total_api_endpoints = 0
        for data in crawled_data.values():
            total_api_endpoints += len(data["classified_endpoints"].get("API", []))
            total_api_endpoints += len(data["classified_endpoints"].get("GraphQL", []))

        # Yield debug logging & completion metrics
        debug_msg = (
            f"Total URLs discovered: {total_urls_discovered}\n"
            f"Unique URLs stored: {total_urls_stored}\n"
            f"Duplicate URLs skipped: {total_duplicates_skipped}\n"
            f"Static resources ignored: {total_resources_ignored}\n"
            f"Third-party URLs ignored: {total_third_party_ignored}\n"
            f"JavaScript files stored: {total_js_stored}\n"
            f"Forms discovered: {total_forms_discovered}\n"
            f"API endpoints discovered: {total_api_endpoints}\n"
            f"Crawl duration: {duration_s}s"
        )
        logger.info(debug_msg)
        yield {"type": "log", "message": debug_msg}

        complete_msg = "Katana crawling completed."
        logger.info(complete_msg)
        yield {"type": "log", "message": complete_msg}
        yield {
            "type": "scan_summary",
            "provider": self.name,
            "hosts_scanned": len(targets),
            "hosts_with_urls": len(crawled_data),
            "urls_discovered": total_urls_discovered,
            "duration_seconds": duration_s,
        }
