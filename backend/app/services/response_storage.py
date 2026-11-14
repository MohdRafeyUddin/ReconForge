"""Response Body Storage Service
==============================
Secure filesystem persistence for HTTP response bodies with:
  - Per-project isolation under `backend/storage/responses/{project_id}/`
  - Per-response body size caps (default 500 KB, configurable)
  - Project-wide retention limits (FIFO cleanup when exceeding max files or storage cap)
  - Path traversal prevention
  - Strictly requires authentication before serving (no unauthenticated access)
"""

import hashlib
import logging
import os
import re
from typing import Optional, Tuple

logger = logging.getLogger("reconforge.services.response_storage")

BASE_STORAGE_DIR = os.path.abspath(
    os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "storage", "responses")
)

# Project defaults
DEFAULT_MAX_BODY_BYTES = 500 * 1024       # 500 KB per response body
MAX_ALLOWED_BODY_BYTES = 2 * 1024 * 1024   # 2 MB absolute maximum
DEFAULT_PROJECT_MAX_BYTES = 100 * 1024 * 1024 # 100 MB per project
DEFAULT_PROJECT_MAX_FILES = 10000          # 10,000 response files per project


def get_project_storage_dir(project_id: str) -> str:
    """Returns safe, isolated directory for a project's response bodies."""
    safe_pid = re.sub(r"[^a-zA-Z0-9_\-]", "", str(project_id))
    if not safe_pid:
        raise ValueError("Invalid project_id for storage directory")
    project_dir = os.path.abspath(os.path.join(BASE_STORAGE_DIR, safe_pid))
    os.makedirs(project_dir, exist_ok=True)
    return project_dir


def _enforce_retention(project_dir: str, max_files: int = DEFAULT_PROJECT_MAX_FILES, max_bytes: int = DEFAULT_PROJECT_MAX_BYTES):
    """Enforces FIFO retention cleanup if total files or storage size exceeds limits."""
    try:
        entries = []
        total_size = 0
        for entry in os.scandir(project_dir):
            if entry.is_file():
                try:
                    stat = entry.stat()
                    entries.append((entry.path, stat.st_mtime, stat.st_size))
                    total_size += stat.st_size
                except Exception:
                    pass

        # Sort oldest first (FIFO)
        if len(entries) > max_files or total_size > max_bytes:
            entries.sort(key=lambda x: x[1])
            while entries and (len(entries) > max_files or total_size > max_bytes):
                oldest_path, _, size = entries.pop(0)
                try:
                    os.unlink(oldest_path)
                    total_size -= size
                except Exception as del_err:
                    logger.debug("Failed to remove old response file %s: %s", oldest_path, del_err)
    except Exception as exc:
        logger.warning("Retention enforcement error in %s: %s", project_dir, exc)


def delete_project_response_bodies(project_id: str) -> bool:
    """Deletes all stored response bodies for a project."""
    import shutil
    try:
        project_dir = get_project_storage_dir(project_id)
        if os.path.exists(project_dir):
            shutil.rmtree(project_dir, ignore_errors=True)
        return True
    except Exception as exc:
        logger.error("Failed to delete project response bodies for %s: %s", project_id, exc)
        return False


get_project_response_dir = get_project_storage_dir


def save_response_body(
    project_id: str,
    identifier: str,
    body: str | bytes,
    max_kb: int = 500,
    max_files: int = DEFAULT_PROJECT_MAX_FILES,
    max_bytes_total: int = DEFAULT_PROJECT_MAX_BYTES,
) -> Optional[Tuple[str, int]]:
    """
    Saves an HTTP response body to the project storage directory.
    Returns (relative_file_path, byte_count) or None on failure.
    """
    if not body:
        return None

    try:
        project_dir = get_project_storage_dir(project_id)
        max_bytes = min(max_kb * 1024, MAX_ALLOWED_BODY_BYTES)

        if isinstance(body, str):
            raw_bytes = body.encode("utf-8", errors="replace")
        else:
            raw_bytes = body

        actual_size = len(raw_bytes)
        was_truncated = False
        if actual_size > max_bytes:
            raw_bytes = raw_bytes[:max_bytes] + b"\n\n[TRUNCATED - EXCEEDED " + str(max_kb).encode("utf-8") + b"KB LIMIT]"
            was_truncated = True

        # Generate deterministic, safe filename from identifier hash
        id_hash = hashlib.sha256(identifier.encode("utf-8")).hexdigest()[:16]
        safe_ident = re.sub(r"[^a-zA-Z0-9_\-\.]", "_", identifier.strip().lower())[:32]
        filename = f"{safe_ident}_{id_hash}.txt"

        target_file = os.path.abspath(os.path.join(project_dir, filename))
        # Path traversal guard
        if os.path.commonpath([target_file, project_dir]) != project_dir:
            raise ValueError("Path traversal attempt in response storage")

        with open(target_file, "wb") as f:
            f.write(raw_bytes)

        # Enforce retention limits
        _enforce_retention(project_dir, max_files=max_files, max_bytes=max_bytes_total)

        # Relative path stored in asset metadata
        rel_path = f"{os.path.basename(project_dir)}/{filename}"
        return rel_path, len(raw_bytes)
    except Exception as exc:
        logger.error("Failed to save response body for %s: %s", identifier, exc)
        return None


def read_response_body(project_id: str, filename: str) -> Optional[str]:
    """
    Safely reads an HTTP response body. Strictly enforces project directory bounds.
    Raises ValueError on detected path traversal attempt.
    """
    if ".." in filename or "/" in filename or "\\" in filename:
        # Check raw requested path against project dir
        project_dir = get_project_storage_dir(project_id)
        resolved = os.path.abspath(os.path.join(project_dir, filename))
        if os.path.commonpath([resolved, project_dir]) != project_dir:
            raise ValueError(f"Path traversal detected in requested filename: {filename}")

    try:
        project_dir = get_project_storage_dir(project_id)
        clean_filename = os.path.basename(filename)
        target_path = os.path.abspath(os.path.join(project_dir, clean_filename))

        # Path traversal verification
        if os.path.commonpath([target_path, project_dir]) != project_dir:
            raise ValueError(f"Path traversal detected: {filename}")

        if not os.path.isfile(target_path):
            return None

        with open(target_path, "r", encoding="utf-8", errors="replace") as f:
            return f.read()
    except ValueError:
        raise
    except Exception as exc:
        logger.error("Failed to read response body %s for project %s: %s", filename, project_id, exc)
        return None
