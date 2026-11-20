"""Phase 8.2 — Secret scanning over saved in-scope response/JS bodies.

Preferred scanner: trufflehog (no verification, fully offline). Fallback:
gitleaks. Only files referenced by in-scope assets are scanned. Raw secret
values are never persisted, logged or broadcast — only detector, location and a
short masked prefix are emitted.
"""

import hashlib
import hmac
import json
import logging
import os
import platform
import re
import secrets as _secrets
import shutil
import subprocess
import tempfile
import time
from typing import Any, AsyncGenerator, Dict, List, Optional, Tuple
from urllib.parse import urlparse

from app.core.phase8_config import get_phase8_config
from app.core.redaction import mask_secret_value, redact_text
from app.core.scope import is_in_scope
from app.providers.base import BaseProvider
from app.services.response_storage import BASE_STORAGE_DIR

logger = logging.getLogger("reconforge.providers.secrets")

STORAGE_ROOT = os.path.dirname(BASE_STORAGE_DIR)
SECRET_HMAC_KEY_PATH = os.path.join(STORAGE_ROOT, "secret_values.key")
_HMAC_KEY_CACHE: Optional[bytes] = None


def _load_hmac_key() -> bytes:
    """Loads/generates the local HMAC key used for secret value hashes.

    The key lives under backend/storage/*.key (gitignored) and is generated on
    first use so identity keys stay stable across runs.
    """
    global _HMAC_KEY_CACHE
    if _HMAC_KEY_CACHE is not None:
        return _HMAC_KEY_CACHE
    try:
        os.makedirs(STORAGE_ROOT, exist_ok=True)
        if os.path.isfile(SECRET_HMAC_KEY_PATH):
            with open(SECRET_HMAC_KEY_PATH, "r", encoding="utf-8") as f:
                key_hex = f.read().strip()
            key = bytes.fromhex(key_hex)
            if len(key) < 16:
                raise ValueError("HMAC key file is too short")
            _HMAC_KEY_CACHE = key
            return key
        key = _secrets.token_bytes(32)
        try:
            fd = os.open(SECRET_HMAC_KEY_PATH, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        except FileExistsError:
            with open(SECRET_HMAC_KEY_PATH, "r", encoding="utf-8") as f:
                key = bytes.fromhex(f.read().strip())
            _HMAC_KEY_CACHE = key
            return key
        try:
            os.write(fd, key.hex().encode("utf-8"))
        finally:
            os.close(fd)
        try:
            os.chmod(SECRET_HMAC_KEY_PATH, 0o600)
        except Exception:
            pass
        _HMAC_KEY_CACHE = key
        return key
    except Exception as exc:
        logger.error("Unable to load or create the secret HMAC key: %s", exc)
        raise


def _secret_value_hash(raw_secret: str) -> str:
    """HMAC-SHA256 of a raw secret; the raw value is never persisted."""
    return hmac.new(
        _load_hmac_key(),
        str(raw_secret).encode("utf-8", errors="replace"),
        hashlib.sha256,
    ).hexdigest()


def _resolve_stored_file(rel_path: str) -> Optional[str]:
    """Resolves response-body and JS-storage relative paths safely."""
    rel = str(rel_path or "").replace("\\", "/").lstrip("/")
    if not rel or ".." in rel:
        return None
    for root in (BASE_STORAGE_DIR, STORAGE_ROOT):
        full_path = os.path.abspath(os.path.join(root, rel))
        try:
            if os.path.commonpath([full_path, root]) != root:
                continue
        except ValueError:
            continue
        if os.path.isfile(full_path):
            return full_path
    return None


class SecretsProvider(BaseProvider):
    @property
    def name(self) -> str:
        return "Secrets"

    @property
    def description(self) -> str:
        return "Scans stored in-scope response and JavaScript bodies for secrets, masking all values."

    # ------------------------------------------------------------------
    # Pure helpers
    # ------------------------------------------------------------------

    @staticmethod
    def select_scannable_files(
        assets: List[Dict[str, Any]],
        scope: Optional[Dict[str, List[str]]] = None,
    ) -> List[Dict[str, Any]]:
        """Selects files referenced by in-scope assets. Fails closed on scope."""
        selected: List[Dict[str, Any]] = []
        seen_paths = set()
        for asset in assets or []:
            if not isinstance(asset, dict):
                continue
            meta = asset.get("metadata") or {}
            rel_path = meta.get("response_body_path") or meta.get("body_path")
            if not rel_path or not isinstance(rel_path, str):
                continue
            host = str(asset.get("domain") or meta.get("host") or "").lower().strip()
            url = str(meta.get("url") or "").strip()
            check_val = url or host
            if scope and check_val and not is_in_scope(check_val, scope):
                continue
            rel_path = rel_path.replace("\\", "/").lstrip("/")
            if ".." in rel_path or rel_path in seen_paths:
                continue
            full_path = _resolve_stored_file(rel_path)
            if not full_path:
                continue
            seen_paths.add(rel_path)
            selected.append({
                "path": full_path,
                "rel_path": rel_path,
                "url": url,
                "host": host or (urlparse(url).hostname or "").lower(),
                "source": meta.get("source") or asset.get("discovered_by") or "response",
            })
        return selected

    @staticmethod
    def _file_identity(file_path: str, file_map: Dict[str, Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        if not file_path:
            return None
        normalized = os.path.abspath(str(file_path))
        if normalized in file_map:
            return file_map[normalized]
        base = os.path.basename(normalized)
        for known_path, identity in file_map.items():
            if os.path.basename(known_path) == base:
                return identity
        return None

    @staticmethod
    def parse_trufflehog_output(
        lines: List[str],
        file_map: Dict[str, Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        """Converts trufflehog JSONL into masked secret records."""
        findings: List[Dict[str, Any]] = []
        seen = set()
        for raw_line in lines or []:
            line = str(raw_line or "").strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except Exception:
                continue
            if not isinstance(record, dict):
                continue
            detector = str(
                record.get("DetectorName")
                or record.get("DetectorType")
                or record.get("Detector")
                or "secret"
            ).strip()
            raw_secret = str(record.get("Raw") or record.get("RawV2") or "")
            if not raw_secret:
                continue
            verified = bool(record.get("Verified"))
            source_meta = record.get("SourceMetadata") or {}
            data = source_meta.get("Data") or {}
            fs_meta = {}
            for key, val in data.items():
                if str(key).lower() == "filesystem" and isinstance(val, dict):
                    fs_meta = val
                    break
            file_path = str(
                fs_meta.get("file")
                or fs_meta.get("File")
                or fs_meta.get("path")
                or ""
            )
            identity = SecretsProvider._file_identity(file_path, file_map)
            if not identity:
                continue
            try:
                line_no = int(fs_meta.get("line") or fs_meta.get("Line") or 0)
            except Exception:
                line_no = 0
            url = redact_text(identity.get("url") or identity.get("host") or "")
            location = f"{url}:{line_no}"
            value_hash = _secret_value_hash(raw_secret)
            key = hashlib.sha256(
                f"{detector}|{location}|{value_hash}".encode("utf-8", errors="replace")
            ).hexdigest()[:32]
            if key in seen:
                continue
            seen.add(key)
            findings.append({
                "key": key,
                "detector": detector,
                "verified": False,
                "host": identity.get("host") or "",
                "url": url,
                "line": line_no,
                "location": location,
                "value_hash": value_hash,
                "prefix": mask_secret_value(raw_secret),
                "scanner": "trufflehog",
                "file": os.path.basename(str(file_path)),
            })
        return findings

    @staticmethod
    def parse_gitleaks_report(
        report: Any,
        file_map: Dict[str, Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        """Converts a gitleaks JSON report into masked secret records."""
        if isinstance(report, dict):
            report = report.get("findings") or report.get("results") or []
        if not isinstance(report, list):
            return []
        findings: List[Dict[str, Any]] = []
        seen = set()
        for record in report:
            if not isinstance(record, dict):
                continue
            detector = str(record.get("RuleID") or record.get("Rule") or "secret").strip()
            secret = str(record.get("Secret") or "")
            if not secret:
                continue
            file_path = str(record.get("File") or "")
            identity = SecretsProvider._file_identity(file_path, file_map)
            if not identity:
                continue
            try:
                line_no = int(record.get("StartLine") or record.get("Line") or 0)
            except Exception:
                line_no = 0
            url = redact_text(identity.get("url") or identity.get("host") or "")
            location = f"{url}:{line_no}"
            value_hash = _secret_value_hash(secret)
            key = hashlib.sha256(
                f"{detector}|{location}|{value_hash}".encode("utf-8", errors="replace")
            ).hexdigest()[:32]
            if key in seen:
                continue
            seen.add(key)
            findings.append({
                "key": key,
                "detector": detector,
                "verified": False,
                "host": identity.get("host") or "",
                "url": url,
                "line": line_no,
                "location": location,
                "value_hash": value_hash,
                "prefix": mask_secret_value(secret),
                "scanner": "gitleaks",
                "file": os.path.basename(file_path),
            })
        return findings

    # ------------------------------------------------------------------
    # Tool helpers
    # ------------------------------------------------------------------

    def _strict_tool(self, tool_name: str) -> Optional[str]:
        try:
            return self.detect_tool(tool_name)
        except Exception:
            return None

    @staticmethod
    def _tool_prefix(tool_path: str) -> List[str]:
        if platform.system().lower() == "windows":
            return ["wsl", "-e", tool_path]
        return [tool_path]

    async def _run_tool(self, args: List[str], timeout: int) -> Tuple[int, str, str]:
        import asyncio
        from app.job_control import register_process, unregister_process, kill_process_tree

        def _run() -> Tuple[int, str, str]:
            proc = subprocess.Popen(
                args,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding="utf-8",
                errors="replace",
            )
            register_process(proc)
            try:
                out, err = proc.communicate(timeout=timeout)
                return proc.returncode, out or "", err or ""
            except subprocess.TimeoutExpired:
                kill_process_tree(proc, "secrets")
                try:
                    out, err = proc.communicate(timeout=5)
                except Exception:
                    out, err = "", ""
                return -1, out or "", err or ""
            finally:
                unregister_process(proc)

        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, _run)

    async def discover(self, seed_domains: Optional[List[str]] = None, **kwargs: Any) -> AsyncGenerator[Dict[str, Any], None]:
        async for event in self.scan(seed_domains, **kwargs):
            yield event

    # ------------------------------------------------------------------
    # Phase entry point
    # ------------------------------------------------------------------

    async def scan(
        self,
        seed_domains: Optional[List[str]] = None,
        scan_mode: str = "fast",
        project_config: Optional[Dict[str, Any]] = None,
        extra_files: Optional[List[Dict[str, Any]]] = None,
        scope: Optional[Dict[str, List[str]]] = None,
    ) -> AsyncGenerator[Dict[str, Any], None]:
        cfg = get_phase8_config(project_config)["secrets_scan"]
        scope_cfg = scope if scope is not None else (project_config or {}).get("scope")
        project_id = str((project_config or {}).get("project_id") or "")
        start_ts = time.time()

        yield {"type": "log", "message": "\n========== Secret Scanning (Phase 8) =========="}

        if not cfg.get("enabled", True):
            yield {"type": "stage_skipped", "stage": "Secret Scanning (secrets)", "tool": "secrets", "reason": "disabled"}
            yield {"type": "scan_summary", "provider": "secrets", "status": "SKIPPED", "count": 0}
            return

        max_files = int(cfg.get("max_files", 500) or 500)
        timeout = int(cfg.get("timeout_seconds", 180) or 180)

        selected: List[Dict[str, Any]] = []
        if project_id:
            try:
                from app.database import get_database
                db = get_database()
                cursor = db.assets.find({
                    "project_id": project_id,
                    "$or": [
                        {"metadata.response_body_path": {"$nin": [None, ""]}},
                        {"metadata.body_path": {"$nin": [None, ""]}},
                    ],
                })
                assets = await cursor.to_list(length=max_files * 3)
                selected.extend(self.select_scannable_files(assets, scope_cfg))
            except Exception as exc:
                logger.debug("Secret scan asset query failed: %s", exc)

        for extra in extra_files or []:
            if not isinstance(extra, dict):
                continue
            rel_path = str(extra.get("path") or "").replace("\\", "/").lstrip("/")
            if not rel_path or ".." in rel_path:
                continue
            full_path = _resolve_stored_file(rel_path)
            if not full_path:
                continue
            check_val = extra.get("url") or extra.get("host") or ""
            if scope_cfg and check_val and not is_in_scope(check_val, scope_cfg):
                continue
            selected.append({
                "path": full_path,
                "rel_path": rel_path,
                "url": str(extra.get("url") or ""),
                "host": str(extra.get("host") or "").lower(),
                "source": extra.get("source") or "js_analysis",
            })

        deduped: List[Dict[str, Any]] = []
        seen = set()
        for item in selected:
            if item["path"] in seen:
                continue
            seen.add(item["path"])
            deduped.append(item)
        selected = deduped[:max_files]

        if not selected:
            yield {"type": "log", "message": "Secret Scanning: no stored in-scope response bodies available."}
            yield {"type": "scan_summary", "provider": "secrets", "status": "SKIPPED", "count": 0, "reason": "no_files"}
            return

        trufflehog_path = self._strict_tool("trufflehog")
        gitleaks_path = self._strict_tool("gitleaks")
        if not trufflehog_path:
            yield {"type": "stage_skipped", "stage": "Secret Scanning (trufflehog)", "tool": "trufflehog", "reason": "tool_missing: trufflehog"}
        if not gitleaks_path:
            yield {"type": "stage_skipped", "stage": "Secret Scanning (gitleaks)", "tool": "gitleaks", "reason": "tool_missing: gitleaks"}
        if not trufflehog_path and not gitleaks_path:
            yield {"type": "scan_summary", "provider": "secrets", "status": "SKIPPED", "count": 0, "reason": "tool_missing"}
            return

        yield {
            "type": "log",
            "message": f"[*] Secret Scanning: inspecting {len(selected)} in-scope file(s) (scanner: {'trufflehog' if trufflehog_path else 'gitleaks'})...",
        }

        file_map = {item["path"]: item for item in selected}
        findings: List[Dict[str, Any]] = []
        scanner = ""
        temp_report = None

        if trufflehog_path:
            scanner = "trufflehog"
            file_args = [
                self.wsl_path_convert(item["path"]) if platform.system().lower() == "windows" else item["path"]
                for item in selected
            ]
            cmd = [*self._tool_prefix(trufflehog_path), "filesystem", *file_args, "--json", "--no-verification"]
            yield {"type": "log", "message": self.format_cmd_log([cmd[0], cmd[1], "filesystem", f"<{len(selected)} files>", "--json", "--no-verification"])}
            rc, out, err = await self._run_tool(cmd, timeout=timeout)
            if rc in (0, 183):
                findings = self.parse_trufflehog_output(out.splitlines(), file_map)
            else:
                # Scanner stdout/stderr may contain raw secrets; never log or
                # persist it. Only the exit code is reported.
                yield {
                    "type": "stage_error",
                    "stage": "Secret Scanning (trufflehog)",
                    "tool": "trufflehog",
                    "returncode": rc,
                    "message": f"trufflehog exited with code {rc}; scanner output withheld (may contain secrets)",
                }
                findings = self.parse_trufflehog_output(out.splitlines(), file_map)
        elif gitleaks_path:
            scanner = "gitleaks"
            tmp_dir = tempfile.mkdtemp(prefix="reconforge_gitleaks_")
            report_fd, report_path = tempfile.mkstemp(prefix="reconforge_gitleaks_", suffix=".json")
            os.close(report_fd)
            temp_report = report_path
            copy_map: Dict[str, Dict[str, Any]] = {}
            try:
                for idx, item in enumerate(selected):
                    base = f"body_{idx}{os.path.splitext(item['path'])[1] or '.txt'}"
                    dest = os.path.join(tmp_dir, base)
                    shutil.copyfile(item["path"], dest)
                    copy_map[dest] = item
                source_arg = self.wsl_path_convert(tmp_dir) if platform.system().lower() == "windows" else tmp_dir
                report_arg = self.wsl_path_convert(report_path) if platform.system().lower() == "windows" else report_path
                cmd = [
                    *self._tool_prefix(gitleaks_path), "detect",
                    "--source", source_arg,
                    "--no-git",
                    "--report-format", "json",
                    "--report-path", report_arg,
                    "--exit-code", "0",
                    "--no-banner",
                ]
                yield {"type": "log", "message": self.format_cmd_log(cmd)}
                rc, out, err = await self._run_tool(cmd, timeout=timeout)
                if os.path.isfile(report_path):
                    try:
                        with open(report_path, "r", encoding="utf-8", errors="replace") as rf:
                            report = json.load(rf)
                        findings = self.parse_gitleaks_report(report, copy_map)
                    except Exception as parse_exc:
                        logger.debug("gitleaks report parse failed: %s", parse_exc)
                if rc != 0 and not findings:
                    # Never include scanner output; it may contain raw secrets.
                    yield {
                        "type": "stage_error",
                        "stage": "Secret Scanning (gitleaks)",
                        "tool": "gitleaks",
                        "returncode": rc,
                        "message": f"gitleaks exited with code {rc}; scanner output withheld (may contain secrets)",
                    }
            finally:
                shutil.rmtree(tmp_dir, ignore_errors=True)
                if temp_report and os.path.exists(temp_report):
                    try:
                        os.unlink(temp_report)
                    except Exception:
                        pass

        total = 0
        for finding in findings:
            if scope_cfg and finding.get("url") and not is_in_scope(finding["url"], scope_cfg):
                continue
            location_url = finding.get("url") or finding.get("host") or ""
            location = f"{location_url}:{finding.get('line') or 0}"
            masked_preview = finding.get("prefix") or ""
            metadata = {
                "source": "secrets",
                "scanner": finding["scanner"],
                "detector": finding["detector"],
                "secret_type": finding["detector"],
                "verified": False,  # secrets are never verified against live services
                "host": finding.get("host") or "",
                "url": finding.get("url") or "",
                "location_url": location_url,
                "location": location,
                "line": finding.get("line") or 0,
                "masked_preview": masked_preview,
                "prefix": masked_preview,
                "value_hash": finding.get("value_hash") or "",
                "identity_key": finding["key"],
                "severity": "medium",
            }
            total += 1
            yield {
                "type": "asset",
                "data": {
                    "domain": finding.get("host") or finding.get("url") or "unknown",
                    "type": "secret_finding",
                    "value": finding["key"][:500],
                    "status": "live",
                    "metadata": metadata,
                    "discovered_by": finding["scanner"],
                    "sources": [finding["scanner"], "secrets"],
                },
            }
            yield {
                "type": "log",
                "message": (
                    f"[+] Secret candidate: {finding['detector']} at "
                    f"{location_url} (line {metadata['line']}, masked={masked_preview})"
                ),
            }

        yield {
            "type": "scan_summary",
            "provider": "secrets",
            "status": "completed",
            "count": total,
            "files_scanned": len(selected),
            "scanner": scanner,
            "duration_seconds": int(time.time() - start_ts),
        }
        yield {"type": "log", "message": f"[√] Secret Scanning complete: {total} masked secret candidate(s) from {len(selected)} file(s)."}
