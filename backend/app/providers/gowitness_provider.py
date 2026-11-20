import asyncio
import hashlib
import logging
import os
import platform
import re
import shutil
import subprocess
import tempfile
import time
from datetime import datetime
from typing import Any, AsyncGenerator, Dict, List, Optional
from urllib.parse import urlparse

from app.providers.base import BaseProvider
from app.services.screenshot_storage import get_run_dir, relative_path

logger = logging.getLogger("reconforge.providers.gowitness")

CHROMIUM_INSTALL_HINT = "sudo apt install -y chromium"
HAVE_SCREENSHOT_RE = re.compile(
    r"target=(\S+).*?have-screenshot=(true|false)", re.IGNORECASE
)
TARGET_RE = re.compile(r"target=(\S+)", re.IGNORECASE)


class GowitnessProvider(BaseProvider):
    @property
    def name(self) -> str:
        return "GoWitness"

    @property
    def description(self) -> str:
        return (
            "Captures screenshots of live host roots and prioritized "
            "discovered URLs using GoWitness."
        )

    # ------------------------------------------------------------------
    # CLI verification / command builder
    # ------------------------------------------------------------------

    @classmethod
    def _tool_prefix(cls, tool_path: str, is_windows: bool) -> List[str]:
        return ["wsl", "-e", tool_path] if is_windows else [tool_path]

    @classmethod
    def verify_gowitness_cli(cls, tool_path: str, is_windows: bool = False) -> Dict[str, Any]:
        """Runs `version` and the matching `--help`; returns detected syntax info."""
        prefix = cls._tool_prefix(tool_path, is_windows)
        version_output = ""
        help_output = ""
        version = "v2"
        try:
            ver = subprocess.run([*prefix, "version"], capture_output=True, text=True, timeout=15)
            version_output = (ver.stdout or "") + (ver.stderr or "")
        except Exception as exc:
            logger.debug("[gowitness] version check failed: %s", exc)

        try:
            v3_help = subprocess.run(
                [*prefix, "scan", "single", "-h"],
                capture_output=True, text=True, timeout=15,
            )
            v3_text = (v3_help.stdout or "") + (v3_help.stderr or "")
            if v3_help.returncode == 0 and "--screenshot-path" in v3_text:
                version = "v3"
                help_output = v3_text
        except Exception:
            pass

        if version != "v3":
            try:
                v2_help = subprocess.run([*prefix, "--help"], capture_output=True, text=True, timeout=15)
                v2_text = (v2_help.stdout or "") + (v2_help.stderr or "")
                if v2_help.returncode == 0:
                    help_output = v2_text
            except Exception:
                pass

        if "v3" in version_output.lower() or "gowitness: 3" in version_output.lower():
            version = "v3"

        return {
            "version": version,
            "version_output": version_output,
            "help_output": help_output,
        }

    @classmethod
    def detect_gowitness_version(cls, tool_path: str, is_windows: bool = False) -> str:
        return cls.verify_gowitness_cli(tool_path, is_windows=is_windows)["version"]

    @classmethod
    def build_gowitness_cmd(
        cls,
        tool_path: str,
        url: str,
        screenshot_path: str,
        version: str = "v3",
        is_windows: bool = False,
        timeout: Optional[int] = None,
        chrome_path: Optional[str] = None,
        diagnostics: bool = False,
        driver: Optional[str] = None,
    ) -> List[str]:
        cmd = ["wsl", "-e"] if is_windows else []
        if version == "v3":
            cmd.extend([
                tool_path,
                "scan", "single",
                "-u", url,
                "--screenshot-path", screenshot_path,
                "--screenshot-format", "png",
                "--write-none",
            ])
            if timeout:
                cmd.extend(["-T", str(int(timeout))])
            if chrome_path:
                cmd.extend(["--chrome-path", chrome_path])
            if driver:
                cmd.extend(["--driver", driver])
            if diagnostics:
                cmd.extend(["--log-scan-errors", "--no-log-color"])
        else:
            cmd.extend([
                tool_path,
                "single",
                "-u", url,
                "--screenshot-path", screenshot_path,
                "--write-db=false",
            ])
            if timeout:
                cmd.extend(["--timeout", str(int(timeout))])
        return cmd

    @classmethod
    def detect_chromium(cls, is_windows: bool) -> Optional[str]:
        """Returns a resolved Chromium/Chrome path in WSL/host, or None."""
        try:
            if is_windows:
                res = subprocess.run(
                    ["wsl", "-e", "bash", "-lc",
                     "command -v chromium-browser || command -v google-chrome || "
                     "command -v google-chrome-stable || command -v chromium || true"],
                    capture_output=True, text=True, timeout=10,
                )
                paths = [p.strip() for p in (res.stdout or "").splitlines() if p.strip()]
                return paths[0] if paths else None
            for candidate in (
                "chromium-browser",
                "google-chrome",
                "google-chrome-stable",
                "chromium",
            ):
                found = shutil.which(candidate)
                if found:
                    return found
        except Exception:
            return None
        return None

    # ------------------------------------------------------------------
    # Output parsing / failure classification
    # ------------------------------------------------------------------

    @staticmethod
    def parse_have_screenshot(output: str, url: str) -> Optional[bool]:
        """Parses `have-screenshot=true|false` lines for a URL.

        Returns True/False when the line is present, or None when the output
        does not expose this field (newer GoWitness versions).
        """
        if not output:
            return None
        for line in str(output).splitlines():
            if "have-screenshot=" not in line.lower():
                continue
            match = HAVE_SCREENSHOT_RE.search(line)
            if not match:
                continue
            line_url = match.group(1).strip().strip("'\"")
            if line_url == url or url in line or line_url.rstrip("/") == url.rstrip("/"):
                return match.group(2).lower() == "true"
        return None

    @staticmethod
    def classify_failure(stderr_text: str, timed_out: bool, no_png: bool) -> str:
        text = (stderr_text or "").lower()
        if timed_out:
            return "timeout"
        if any(
            marker in text
            for marker in (
                "browser not found", "chrome", "chromium", "executable file not found",
                "no such file or directory", "could not find chrome",
            )
        ):
            return "browser not found"
        if any(
            marker in text
            for marker in (
                "sandbox", "shared libraries", "libnss", "libgbm", "error while loading",
                "cannot open shared object", "segmentation fault",
            )
        ):
            return "sandbox/library error"
        if no_png:
            return "no PNG file produced"
        return "unknown error"

    # ------------------------------------------------------------------
    # Provider entry point
    # ------------------------------------------------------------------

    async def discover(
        self,
        seed_domains: List[str],
        rate_limit: int = 10,
        per_url_timeout: int = 60,
        concurrency: int = 3,
        project_id: Optional[str] = None,
        job_id: Optional[str] = None,
        page_hashes: Optional[Dict[str, str]] = None,
        **kwargs: Any,
    ) -> AsyncGenerator[Dict[str, Any], None]:
        from app.job_control import current_job_id

        urls = list(dict.fromkeys(u.strip() for u in seed_domains if u and u.strip()))
        page_hashes = page_hashes or {}
        per_url_timeout = max(1, min(int(per_url_timeout or 60), 600))
        concurrency = max(1, min(int(concurrency or 3), 10))

        yield {"type": "log", "message": "\n========== GoWitness Screenshot Capture =========="}

        if not urls:
            yield {"type": "log", "message": "GoWitness completed. No target URLs provided."}
            yield {
                "type": "scan_summary",
                "provider": "gowitness",
                "screenshots": 0,
                "successful_screenshots": 0,
                "failed_screenshots": 0,
                "count": 0,
                "skipped_reason": "no_live_hosts_upstream",
            }
            return

        tool_path = self.detect_tool("gowitness")
        is_windows = platform.system().lower() == "windows"
        if not tool_path:
            yield {
                "type": "stage_error",
                "stage": "visual_verification",
                "tool": "gowitness",
                "reason": "tool_missing: gowitness",
                "message": "GoWitness binary could not be resolved. Install it and refresh the WSL tool registry.",
            }
            yield {
                "type": "scan_summary", "provider": "gowitness", "status": "SKIPPED",
                "screenshots": 0, "successful_screenshots": 0, "failed_screenshots": 0, "count": 0,
            }
            return

        cli = self.verify_gowitness_cli(tool_path, is_windows=is_windows)
        version = cli["version"]
        help_output = cli.get("help_output") or ""
        # Preflight Chromium/Chrome once per run (not a pre-scan gate).
        chrome_path = self.detect_chromium(is_windows)
        if not chrome_path:
            reason = (
                "Chromium/Chrome browser could not be resolved in WSL; screenshot phase skipped. "
                f"Install with: {CHROMIUM_INSTALL_HINT}"
            )
            yield {"type": "stage_error", "stage": "visual_verification", "tool": "gowitness", "reason": reason, "message": reason}
            yield {"type": "log", "message": f"[-] {reason}"}
            yield {
                "type": "scan_summary",
                "provider": "gowitness",
                "status": "SKIPPED",
                "screenshots": 0,
                "successful_screenshots": 0,
                "failed_screenshots": len(urls),
                "failed_urls": urls,
                "count": 0,
                "reason": reason,
            }
            return

        yield {
            "type": "log",
            "message": (
                f"[*] GoWitness {version} ({tool_path}) | Chromium: {chrome_path} | "
                f"per-URL timeout: {per_url_timeout}s | concurrency: {concurrency}"
            ),
        }

        resolved_job_id = str(job_id or current_job_id.get() or "unscoped")
        resolved_project_id = str(project_id or "unscoped")
        try:
            run_dir = get_run_dir(resolved_project_id, resolved_job_id, create=True)
        except ValueError as exc:
            yield {
                "type": "stage_error", "stage": "visual_verification", "tool": "gowitness",
                "reason": str(exc), "message": f"Invalid screenshot storage path: {exc}",
            }
            yield {"type": "scan_summary", "provider": "gowitness", "status": "failed", "count": 0}
            return

        diagnostics = bool(
            version == "v3"
            and "--log-scan-errors" in help_output
            and "--no-log-color" in help_output
        )
        timeout_flag = ("-T" in help_output) or ("--timeout" in help_output)
        # Prefer gorod when the installed build exposes it: chromedp can hang on
        # pages that never finish loading even though the page has a title.
        preferred_driver = (
            "gorod"
            if version == "v3" and "--driver" in help_output and "gorod" in help_output.lower()
            else None
        )
        if preferred_driver:
            yield {"type": "log", "message": f"[*] GoWitness driver: {preferred_driver}"}
        start_ts = time.monotonic()
        semaphore = asyncio.Semaphore(concurrency)
        rate_lock = asyncio.Lock()
        next_slot = [time.monotonic()]

        async def wait_rate_slot() -> None:
            async with rate_lock:
                now = time.monotonic()
                slot = max(now, next_slot[0])
                next_slot[0] = slot + (1.0 / max(int(rate_limit or 10), 1))
            if slot > now:
                await asyncio.sleep(slot - now)

        async def capture_one(url: str, idx: int) -> Dict[str, Any]:
            async with semaphore:
                await wait_rate_slot()
                try:
                    parsed = urlparse(url)
                    host = (parsed.hostname or parsed.netloc or "unknown").lower()
                except Exception:
                    host = "unknown"

                temp_dir = tempfile.mkdtemp(prefix="reconforge_gowitness_")
                target_path = self.wsl_path_convert(temp_dir) if is_windows else temp_dir
                cmd = self.build_gowitness_cmd(
                    tool_path=tool_path,
                    url=url,
                    screenshot_path=target_path,
                    version=version,
                    is_windows=is_windows,
                    timeout=per_url_timeout if timeout_flag else None,
                    chrome_path=chrome_path,
                    diagnostics=diagnostics,
                    driver=preferred_driver,
                )
                events: List[Dict[str, Any]] = [
                    {"type": "log", "message": self.format_cmd_log(cmd)}
                ]
                result: Dict[str, Any] = {
                    "url": url, "host": host, "success": False,
                    "failure": "", "events": events, "asset": None,
                }
                try:
                    from app.job_control import (
                        check_job_status, kill_process_tree, register_process, unregister_process,
                    )
                    await check_job_status()
                    process = subprocess.Popen(
                        cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                        text=True, encoding="utf-8", errors="replace",
                    )
                    register_process(process)
                    timed_out = False
                    stdout_text = ""
                    stderr_text = ""
                    try:
                        loop = asyncio.get_event_loop()

                        def _collect():
                            if hasattr(process, "communicate"):
                                return process.communicate(timeout=per_url_timeout + 20)
                            process.wait(timeout=per_url_timeout + 20)
                            return "", ""

                        stdout_text, stderr_text = await asyncio.wait_for(
                            loop.run_in_executor(None, _collect),
                            timeout=per_url_timeout + 25,
                        )
                    except (subprocess.TimeoutExpired, asyncio.TimeoutError):
                        timed_out = True
                        kill_process_tree(process, "gowitness")
                        events.append({
                            "type": "stage_timeout", "stage": "visual_verification",
                            "tool": "gowitness",
                            "reason": f"per-URL timeout ({per_url_timeout}s) exceeded for {url}",
                        })
                        events.append({"type": "log", "message": f"[-] GoWitness timed out on {url}."})
                    finally:
                        unregister_process(process)
                        if process.poll() is None:
                            try:
                                process.kill()
                            except Exception:
                                pass

                    rc = process.returncode if isinstance(process.returncode, int) else 0
                    combined_output = f"{stdout_text or ''}\n{stderr_text or ''}"
                    hint = self.parse_have_screenshot(combined_output, url)
                    png_files = sorted(
                        f for f in os.listdir(temp_dir) if f.lower().endswith(".png")
                    )

                    if rc != 0 and not (timed_out and png_files):
                        snippet = (stderr_text or stdout_text or "").strip()[:500]
                        cause = self.classify_failure(snippet, timed_out, no_png=not png_files)
                        reason = f"GoWitness exited with code {rc} ({cause})"
                        if snippet:
                            reason = f"{reason}: {snippet}"
                        if cause == "browser not found":
                            reason = f"{reason}. Install with: {CHROMIUM_INSTALL_HINT}"
                        result["failure"] = reason
                        events.append({
                            "type": "stage_error", "stage": "visual_verification",
                            "tool": "gowitness", "returncode": rc,
                            "error": reason, "reason": reason,
                        })
                        events.append({"type": "log", "message": f"[-] {url}: {reason[:500]}"})
                        return result

                    if hint is False:
                        cause = self.classify_failure(stderr_text, timed_out, no_png=not png_files)
                        result["failure"] = f"have-screenshot=false ({cause})"
                        events.append({"type": "log", "message": f"[-] {url}: have-screenshot=false; screenshot failed."})
                        return result

                    if not png_files:
                        cause = self.classify_failure(stderr_text, timed_out, no_png=True)
                        result["failure"] = f"no PNG file produced ({cause})"
                        events.append({"type": "log", "message": f"[-] {url}: no PNG file produced; screenshot failed."})
                        return result

                    with open(os.path.join(temp_dir, png_files[0]), "rb") as f:
                        image_bytes = f.read()
                    if not image_bytes:
                        result["failure"] = "empty PNG file produced"
                        events.append({"type": "log", "message": f"[-] {url}: empty PNG file; screenshot failed."})
                        return result

                    screenshot_hash = hashlib.sha256(image_bytes).hexdigest()
                    page_hash = page_hashes.get(url)
                    if not page_hash:
                        # A host-level body hash only describes the root page;
                        # applying it to deeper URLs would hide real changes.
                        try:
                            parsed_url = urlparse(url)
                            is_root = parsed_url.path in ("", "/") and not parsed_url.query
                        except Exception:
                            is_root = False
                        if is_root:
                            page_hash = page_hashes.get(host)
                    page_hash = page_hash or screenshot_hash
                    safe_host = "".join(
                        c if c.isalnum() or c in ("-", "_") else "_" for c in host
                    )[:80] or "host"
                    filename = f"shot_{safe_host}_{idx}_{screenshot_hash[:12]}.png"
                    dest = os.path.join(run_dir, filename)
                    if os.path.exists(dest):
                        base, ext = os.path.splitext(filename)
                        filename = f"{base}_{int(time.time())}{ext}"
                        dest = os.path.join(run_dir, filename)
                    shutil.move(os.path.join(temp_dir, png_files[0]), dest)
                    rel_path = relative_path(resolved_project_id, resolved_job_id, filename)
                    now_iso = datetime.utcnow().isoformat()
                    metadata = {
                        "url": url,
                        "host": host,
                        "title": f"Screenshot of {host}",
                        "filename": filename,
                        "screenshot_path": rel_path,
                        "size": len(image_bytes),
                        "page_hash": page_hash,
                        "screenshot_hash": screenshot_hash,
                        "timestamp": now_iso,
                        "first_seen": now_iso,
                        "last_seen": now_iso,
                        "run_id": resolved_job_id,
                        "source": "gowitness",
                        "have_screenshot": True,
                        "timed_out": timed_out,
                    }
                    asset = {
                        "domain": host,
                        "type": "screenshot",
                        "value": url,
                        "status": "live",
                        "metadata": metadata,
                        "discovered_by": "gowitness",
                        "sources": ["gowitness"],
                    }
                    result.update({"success": True, "asset": asset})
                    events.append({"type": "asset", "data": asset})
                    events.append({
                        "type": "screenshot_event",
                        "data": {
                            "url": url,
                            "host": host,
                            "title": metadata["title"],
                            "screenshot_path": rel_path,
                            "page_hash": page_hash,
                            "timestamp": now_iso,
                            "source": "gowitness",
                            "job_id": resolved_job_id,
                        },
                    })
                    events.append({"type": "log", "message": f"[+] Captured screenshot for {url} → {rel_path}"})
                    return result
                except Exception as exc:
                    message = f"GoWitness execution failed for {url}: {type(exc).__name__}: {exc}"
                    result["failure"] = message
                    events.append({
                        "type": "stage_error", "stage": "visual_verification",
                        "tool": "gowitness", "reason": message, "message": message,
                    })
                    return result
                finally:
                    shutil.rmtree(temp_dir, ignore_errors=True)

        captured_tasks = [
            asyncio.create_task(capture_one(url, idx))
            for idx, url in enumerate(urls)
        ]

        successes = 0
        failed_urls: List[str] = []
        failure_reasons: List[str] = []
        try:
            # Stream each capture as it completes so long targeted runs show
            # progress instead of buffering every event until the end (and
            # losing partial results when the phase time cap fires).
            for finished in asyncio.as_completed(captured_tasks):
                try:
                    result = await finished
                except asyncio.CancelledError:
                    raise
                except Exception as exc:
                    logger.error("[gowitness] capture task failed: %s", exc)
                    continue
                for ev in result["events"]:
                    yield ev
                if result["success"]:
                    successes += 1
                else:
                    failed_urls.append(result["url"])
                    failure_reasons.append(f"{result['url']}: {result['failure']}")
        finally:
            for task in captured_tasks:
                if not task.done():
                    task.cancel()
            await asyncio.gather(*captured_tasks, return_exceptions=True)

        failed_count = len(failed_urls)
        duration_s = round(time.monotonic() - start_ts, 2)
        if urls and successes == 0:
            joined = " | ".join(failure_reasons[:5])
            lower = joined.lower()
            if "browser not found" in lower:
                likely = "browser not found"
                hint = f" Install with: {CHROMIUM_INSTALL_HINT}"
            elif "sandbox/library" in lower:
                likely = "sandbox/library error"
                hint = f" Try: {CHROMIUM_INSTALL_HINT}"
            elif "timeout" in lower:
                likely = "timeout"
                hint = ""
            else:
                likely = "see stderr"
                hint = ""
            err = (
                f"All {len(urls)} requested screenshot(s) failed (likely cause: {likely}).{hint} "
                f"Details: {joined[:800]}"
            )
            yield {"type": "stage_error", "stage": "visual_verification", "tool": "gowitness", "error": err, "reason": err}
            yield {"type": "log", "message": f"[-] {err}"}
        elif failed_count:
            warn = (
                f"[!] {failed_count}/{len(urls)} screenshot(s) failed. Failed URLs: "
                + ", ".join(failed_urls[:20])
                + (" ..." if len(failed_urls) > 20 else "")
                + f" | Reasons: {'; '.join(failure_reasons[:3])}"
            )
            yield {"type": "warning_event", "warning": "gowitness_partial_failures", "failed_urls": failed_urls, "reason": warn, "message": warn}
            yield {"type": "log", "message": warn}

        yield {
            "type": "scan_summary",
            "provider": "gowitness",
            "status": "completed" if successes > 0 or not urls else "failed",
            "count": successes,
            "screenshots": successes,
            "successful_screenshots": successes,
            "failed_screenshots": failed_count,
            "failed_urls": failed_urls,
            "urls_requested": len(urls),
            "storage_dir": run_dir,
            "duration_seconds": duration_s,
        }
        yield {
            "type": "log",
            "message": (
                f"[√] GoWitness completed. Successful: {successes} | Failed: {failed_count} | "
                f"Requested: {len(urls)}"
            ),
        }
