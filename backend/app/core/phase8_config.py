"""Phase 8 configuration defaults and per-project merging.

Global defaults live in ``app/config/phase8_defaults.json``. Per-project
documents may override any section/keys; unknown keys are ignored so the
schema stays forward/backward compatible.
"""

import copy
import json
import logging
import os
from typing import Any, Dict

logger = logging.getLogger("reconforge.core.phase8_config")

_DEFAULTS_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "config", "phase8_defaults.json")

_FALLBACK_DEFAULTS: Dict[str, Any] = {
    "js_analysis": {
        "enabled": True,
        "max_files_fast": 25,
        "max_files_deep": 100,
        "max_file_kb": 500,
        "timeout_seconds": 15,
        "sourcemaps_deep_only": True,
        "sourcemap_max_files": 10,
    },
    "secrets_scan": {"enabled": True, "max_files": 500, "timeout_seconds": 180},
    "cloud_enum": {"enabled": False, "max_keywords": 10, "timeout_seconds": 180},
    "oast": {"enabled": False, "server": "", "token": "", "startup_timeout_seconds": 20},
    "nuclei_options": {"auto_scan": False, "update_templates": False, "custom_templates_dir": ""},
    "tech_routing": {"enabled": True, "max_hosts_per_tech": 25},
    "exports": {"max_urls": 50000},
}

_DEFAULTS_CACHE: Dict[str, Any] | None = None


def load_phase8_defaults() -> Dict[str, Any]:
    """Load global Phase 8 defaults (cached). Failures fall back to built-ins."""
    global _DEFAULTS_CACHE
    if _DEFAULTS_CACHE is not None:
        return copy.deepcopy(_DEFAULTS_CACHE)
    try:
        with open(_DEFAULTS_PATH, "r", encoding="utf-8") as f:
            loaded = json.load(f)
        if not isinstance(loaded, dict):
            raise ValueError("phase8_defaults.json must contain an object")
        merged = copy.deepcopy(_FALLBACK_DEFAULTS)
        for section, values in loaded.items():
            if isinstance(values, dict) and isinstance(merged.get(section), dict):
                merged[section].update(values)
            else:
                merged[section] = values
        _DEFAULTS_CACHE = merged
    except Exception as exc:
        logger.warning("Failed to load phase8_defaults.json (%s); using built-in defaults", exc)
        _DEFAULTS_CACHE = copy.deepcopy(_FALLBACK_DEFAULTS)
    return copy.deepcopy(_DEFAULTS_CACHE)


def merge_section(defaults: Dict[str, Any], overrides: Any) -> Dict[str, Any]:
    """Shallow-merges a per-project section over its global default."""
    result = dict(defaults or {})
    if isinstance(overrides, dict):
        result.update(overrides)
    return result


def get_phase8_config(project_config: Any) -> Dict[str, Any]:
    """Returns the effective Phase 8 config for a project.

    Accepts either the orchestrator's ``project_config`` dict or a project
    document. Recognised top-level keys mirror the JSON sections.
    """
    defaults = load_phase8_defaults()
    cfg = copy.deepcopy(defaults)
    src = project_config if isinstance(project_config, dict) else {}
    for section in defaults:
        override = src.get(section)
        if isinstance(override, dict):
            cfg[section] = merge_section(cfg.get(section, {}), override)
    return cfg
