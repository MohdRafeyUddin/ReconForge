"""Phase 8.4 — Optional OAST (Interactsh) integration.

Starts ``interactsh-client`` for the duration of a validation scan, exposes the
generated callback URL to Dalfox (``-b``) and the configured server/token to
Nuclei (``-iserver`` / ``-interactsh-token``), and correlates inbound
interactions back to in-scope targets.

OAST is never mandatory: when disabled or when the client is missing the scan
continues normally.
"""

import asyncio
import logging
import platform
import re
import subprocess
import threading
import time
from datetime import datetime
from typing import Any, Dict, Iterable, List, Optional
from urllib.parse import urlparse

from app.core.scope import is_in_scope

logger = logging.getLogger("reconforge.services.oast")

KNOWN_DOMAIN_RE = re.compile(
    r"\b([a-z0-9]{8,}\.(?:oast\.(?:pro|live|site|online|fun|me)|interactsh\.[a-z0-9.\-]+|oastify\.com))\b",
    re.IGNORECASE,
)
GENERIC_DOMAIN_RE = re.compile(r"\b([a-z0-9]{8,}\.[a-z0-9\-]+(?:\.[a-z0-9\-]+)+)\b", re.IGNORECASE)
HOST_HEADER_RE = re.compile(r"^Host:\s*([^\r\n]+)", re.IGNORECASE | re.MULTILINE)
REQUEST_LINE_RE = re.compile(
    r"^(?:GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+(\S+)\s+HTTP/",
    re.IGNORECASE | re.MULTILINE,
)


class OASTSession:
    """Manages one interactsh-client process and its interaction queue."""

    def __init__(self, config: Dict[str, Any], tool_path: str):
        self.config = config or {}
        self.tool_path = tool_path
        self.server = str(self.config.get("server") or "").strip().rstrip("/")
        if "://" in self.server:
            self.server = urlparse(self.server).netloc
        self.token = str(self.config.get("token") or "")
        self.domain: Optional[str] = str(self.config.get("domain") or "").strip().lower() or None
        self.process: Optional[subprocess.Popen] = None
        self._thread: Optional[threading.Thread] = None
        self._queue: Optional[asyncio.Queue] = None
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._stopped = False

    @staticmethod
    def resolve_tool() -> Optional[str]:
        try:
            from app.core.tools import resolve_tool_absolute_path
            return resolve_tool_absolute_path("interactsh")
        except Exception:
            return None

    @property
    def enabled(self) -> bool:
        return bool(self.domain)

    @property
    def oast_url(self) -> str:
        return f"https://{self.domain}" if self.domain else ""

    def _cmd(self) -> List[str]:
        args = ["-json", "-silent", "-no-color"]
        if self.server:
            args.extend(["-server", self.server])
        if self.token:
            args.extend(["-token", self.token])
        if platform.system().lower() == "windows":
            return ["wsl", "-e", self.tool_path, *args]
        return [self.tool_path, *args]

    def _handle_line(self, line: str) -> None:
        if not line:
            return
        stripped = line.strip()
        if not stripped:
            return
        # Interaction JSON records
        if stripped.startswith("{"):
            try:
                import json
                record = json.loads(stripped)
                if isinstance(record, dict) and (
                    record.get("protocol") or record.get("unique-id") or record.get("full-id")
                ):
                    if self._queue is not None:
                        self._queue.put_nowait(record)
                    return
            except Exception:
                pass
        if self.domain:
            return
        lowered = stripped.lower()
        match = KNOWN_DOMAIN_RE.search(stripped)
        if not match and (
            "payload" in lowered or "listing" in lowered or "domain" in lowered or "oast" in lowered
        ):
            match = GENERIC_DOMAIN_RE.search(stripped)
        if match:
            candidate = match.group(1).lower().strip(".")
            # Avoid treating the server hostname itself as a generated payload.
            if self.server and candidate == self.server.lower():
                return
            self.domain = candidate
            logger.info("OAST callback domain acquired: %s", candidate)

    def _reader(self) -> None:
        assert self.process is not None and self.process.stdout is not None
        try:
            for line in self.process.stdout:
                if self._loop and self._loop.is_running():
                    try:
                        self._loop.call_soon_threadsafe(self._handle_line, line)
                    except RuntimeError:
                        break
        except Exception as exc:
            logger.debug("OAST reader stopped: %s", exc)

    async def start(self, startup_timeout: int = 20) -> bool:
        """Starts the client and waits for a generated callback domain."""
        try:
            self._loop = asyncio.get_event_loop()
            self._queue = asyncio.Queue()
            self.process = subprocess.Popen(
                self._cmd(),
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                encoding="utf-8",
                errors="replace",
                bufsize=1,
            )
            from app.job_control import register_process
            register_process(self.process)
            self._thread = threading.Thread(target=self._reader, daemon=True)
            self._thread.start()

            deadline = time.time() + max(5, int(startup_timeout or 20))
            while time.time() < deadline:
                if self.domain:
                    return True
                if self.process.poll() is not None and (self._queue is None or self._queue.empty()):
                    # Client exited before producing a domain.
                    err_tail = ""
                    try:
                        if self.process.stdout:
                            err_tail = (self.process.stdout.read() or "")[:300]
                    except Exception:
                        pass
                    logger.warning("OAST client exited during startup (rc=%s): %s", self.process.returncode, err_tail)
                    return False
                await asyncio.sleep(0.2)
            return bool(self.domain)
        except Exception as exc:
            logger.warning("Failed to start OAST client: %s", exc)
            return False

    def drain_interactions(self, max_items: int = 50) -> List[Dict[str, Any]]:
        items: List[Dict[str, Any]] = []
        if self._queue is None:
            return items
        for _ in range(max_items):
            try:
                items.append(self._queue.get_nowait())
            except Exception:
                break
        return items

    @staticmethod
    def interaction_to_finding(
        interaction: Dict[str, Any],
        scope: Optional[Dict[str, List[str]]],
        candidate_hosts: Iterable[str],
    ) -> Optional[Dict[str, Any]]:
        """Correlates an interaction with a scanned host. Returns None if unknown/out-of-scope."""
        if not isinstance(interaction, dict):
            return None
        raw = str(interaction.get("raw-request") or "")
        protocol = str(interaction.get("protocol") or "unknown").lower()
        remote = str(interaction.get("remote-address") or "").strip()
        candidate_list = [str(h or "").strip().lower() for h in candidate_hosts if h]
        if not candidate_list:
            return None

        target_host = ""
        host_header = HOST_HEADER_RE.search(raw)
        header_host = (host_header.group(1).strip().lower() if host_header else "").split(":")[0]
        if header_host:
            for cand in candidate_list:
                if header_host == cand or header_host.endswith("." + cand):
                    target_host = cand
                    break
        if not target_host:
            raw_lower = raw.lower()
            for cand in candidate_list:
                if cand and cand in raw_lower:
                    target_host = cand
                    break
        if not target_host:
            return None

        request_match = REQUEST_LINE_RE.search(raw)
        request_path = request_match.group(1) if request_match else "/"
        if not request_path.startswith("/"):
            request_path = "/" + request_path

        url = f"https://{target_host}{request_path}"
        if scope and not is_in_scope(url, scope) and not is_in_scope(target_host, scope):
            return None

        severity = "high" if protocol in ("http", "https") else "medium"
        evidence = (
            f"OAST {protocol} interaction received from {remote or 'unknown remote address'} "
            f"for {request_path}"
        )
        return {
            "type": "finding_event",
            "data": {
                "source": "interactsh",
                "severity": severity,
                "template_id": f"oast-{protocol}",
                "template_name": f"Out-of-band {protocol.upper()} interaction",
                "matched_url": url,
                "host": target_host,
                "evidence": evidence,
                "protocol": protocol,
                "remote_address": remote,
                "request_path": request_path,
                "correlation": {
                    "host": target_host,
                    "request_path": request_path,
                },
                "timestamp": datetime.utcnow().isoformat(),
            },
        }

    def stop(self) -> None:
        if self._stopped:
            return
        self._stopped = True
        try:
            if self.process is not None:
                from app.job_control import unregister_process
                unregister_process(self.process)
                if self.process.poll() is None:
                    self.process.terminate()
                    try:
                        self.process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        self.process.kill()
                        try:
                            self.process.wait(timeout=3)
                        except Exception:
                            pass
        except Exception as exc:
            logger.debug("OAST shutdown error: %s", exc)
