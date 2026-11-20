"""Per-run screenshot storage with strict path confinement."""

import os
import re
from typing import Optional

STORAGE_ROOT = os.path.abspath(
    os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "storage")
)
SCREENSHOT_ROOT = os.path.join(STORAGE_ROOT, "screenshots")


def _safe_component(value: str, label: str) -> str:
    cleaned = re.sub(r"[^a-zA-Z0-9_\-]", "", str(value or ""))
    if not cleaned:
        raise ValueError(f"Invalid {label} for screenshot storage")
    return cleaned


def get_run_dir(project_id: str, job_id: str, create: bool = True) -> str:
    safe_pid = _safe_component(project_id, "project_id")
    safe_jid = _safe_component(job_id, "job_id")
    run_dir = os.path.abspath(os.path.join(SCREENSHOT_ROOT, safe_pid, safe_jid))
    if os.path.commonpath([run_dir, SCREENSHOT_ROOT]) != SCREENSHOT_ROOT:
        raise ValueError("Screenshot path traversal detected")
    if create:
        os.makedirs(run_dir, exist_ok=True)
    return run_dir


def resolve_screenshot_file(project_id: str, job_id: str, filename: str) -> Optional[str]:
    """Returns a safe existing .png path inside the run directory, or None."""
    raw = str(filename or "")
    if not raw or raw != os.path.basename(raw) or "/" in raw or "\\" in raw or ".." in raw:
        return None
    if not raw.lower().endswith(".png"):
        return None
    try:
        run_dir = get_run_dir(project_id, job_id, create=False)
    except ValueError:
        return None
    target = os.path.abspath(os.path.join(run_dir, raw))
    try:
        if os.path.commonpath([target, run_dir]) != run_dir:
            return None
    except ValueError:
        return None
    return target if os.path.isfile(target) else None


def relative_path(project_id: str, job_id: str, filename: str) -> str:
    return f"screenshots/{_safe_component(project_id, 'project_id')}/{_safe_component(job_id, 'job_id')}/{filename}"
