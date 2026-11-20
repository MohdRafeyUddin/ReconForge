"""Single full-scan model and per-phase switch helpers.

Stage 1 removes the Fast/Deep scan selector. New runs always use the full
pipeline; expensive phases are gated by per-project switches that default to
OFF. Legacy ``scan_mode`` values stored on old jobs/schedules are still
accepted and display unchanged, but they no longer select a pipeline tier.
"""

from typing import Any, Dict, Optional

FULL_SCAN_MODE = "full"
LEGACY_SCAN_MODES = ("fast", "deep")

# Every switch defaults OFF. ``time_cap_seconds`` is the hard-kill budget for
# that phase.
PHASE_SWITCH_DEFAULTS: Dict[str, Dict[str, Any]] = {
    "dns_bruteforce": {"enabled": False, "time_cap_seconds": 600},
    "waymore": {"enabled": False, "time_cap_seconds": 240},
    "ffuf": {"enabled": False, "time_cap_seconds": 600},
    "param_discovery": {"enabled": False, "time_cap_seconds": 300},
    "wide_port_scan": {"enabled": False, "time_cap_seconds": 600},
    "active_scanners": {"enabled": False, "time_cap_seconds": 900},
    "screenshots": {"enabled": False, "time_cap_seconds": 300},
}


def default_phase_switches() -> Dict[str, Dict[str, Any]]:
    """Returns a fresh copy of the default switch configuration."""
    return {key: dict(value) for key, value in PHASE_SWITCH_DEFAULTS.items()}


def normalize_phase_switches(raw: Optional[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    """Merges stored switch values over defaults and clamps time caps."""
    switches = default_phase_switches()
    if isinstance(raw, dict):
        for key in switches:
            incoming = raw.get(key)
            if not isinstance(incoming, dict):
                if incoming is True or incoming is False:
                    switches[key]["enabled"] = bool(incoming)
                continue
            if "enabled" in incoming:
                switches[key]["enabled"] = bool(incoming.get("enabled"))
            if incoming.get("time_cap_seconds") is not None:
                try:
                    cap = int(incoming.get("time_cap_seconds"))
                except (TypeError, ValueError):
                    cap = switches[key]["time_cap_seconds"]
                switches[key]["time_cap_seconds"] = max(1, min(cap, 7200))
    return switches


def phase_switch_enabled(switches: Optional[Dict[str, Any]], name: str) -> bool:
    """Reads a switch flag from a normalized (or raw) switch mapping."""
    if not isinstance(switches, dict):
        return bool(PHASE_SWITCH_DEFAULTS.get(name, {}).get("enabled", False))
    entry = switches.get(name)
    if isinstance(entry, dict):
        return bool(entry.get("enabled", False))
    if isinstance(entry, bool):
        return entry
    return bool(PHASE_SWITCH_DEFAULTS.get(name, {}).get("enabled", False))


def phase_time_cap(switches: Optional[Dict[str, Any]], name: str) -> int:
    """Returns the hard time cap for a switched phase."""
    default_cap = int(PHASE_SWITCH_DEFAULTS.get(name, {}).get("time_cap_seconds", 300))
    if not isinstance(switches, dict):
        return default_cap
    entry = switches.get(name)
    if not isinstance(entry, dict) or entry.get("time_cap_seconds") is None:
        return default_cap
    try:
        return max(1, min(int(entry.get("time_cap_seconds")), 7200))
    except (TypeError, ValueError):
        return default_cap


def normalize_scan_mode(value: Optional[str]) -> str:
    """New runs are always full; legacy values are accepted for compatibility."""
    return FULL_SCAN_MODE


def is_legacy_scan_mode(value: Optional[str]) -> bool:
    return str(value or "").strip().lower() in LEGACY_SCAN_MODES
