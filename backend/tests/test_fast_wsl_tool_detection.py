import io
import json
import os
import subprocess
import time
from datetime import datetime
from typing import Any, Dict, List
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from bson import ObjectId

from app.config import settings
from app.core.tools import (
    ALLOWED_BINARIES,
    ALLOWED_TOOL_KEYS,
    RECON_TOOLS,
    _get_cache_file_path,
    _get_tool_paths_file_path,
    clear_tool_path_cache,
    get_all_tools_status,
    get_all_tools_status_with_metadata,
    get_tool_status,
    invalidate_tool_cache,
    is_tool_available,
    load_tools_cache_from_disk,
    refresh_all_tools_cache,
    resolve_all_tools_in_system,
    resolve_tool_absolute_path,
    save_tools_cache_to_disk,
    validate_tool_name,
)
from app.providers.base import BaseProvider


@pytest.fixture(autouse=True)
def preserve_storage_files():
    cache_file = _get_cache_file_path()
    paths_file = _get_tool_paths_file_path()
    backup_cache = None
    backup_paths = None
    if os.path.exists(cache_file):
        with open(cache_file, "r", encoding="utf-8") as f:
            backup_cache = f.read()
    if os.path.exists(paths_file):
        with open(paths_file, "r", encoding="utf-8") as f:
            backup_paths = f.read()
    try:
        yield
    finally:
        clear_tool_path_cache()
        if backup_cache is not None:
            with open(cache_file, "w", encoding="utf-8") as f:
                f.write(backup_cache)
        if backup_paths is not None:
            with open(paths_file, "w", encoding="utf-8") as f:
                f.write(backup_paths)


# ==============================================================================
# 1. Single-Call Resolution & Allowlist Validation
# ==============================================================================

def test_single_call_resolution_uses_one_wsl_invocation_and_allowlist_binaries():
    """
    Requirement 1:
      - Replace per-tool `which` calls with ONE wsl invocation (argument list,
        no shell string built from user input) that resolves absolute paths for
        all registry tools.
      - Tool names come only from the registry allowlist.
    """
    clear_tool_path_cache()

    captured_commands: List[List[str]] = []

    mock_json_out = {
        "ffuf": "/home/kali/go/bin/ffuf",
        "subfinder": "/home/kali/go/bin/subfinder",
        "nmap": "/usr/bin/nmap",
        "httpx": "/home/kali/go/bin/httpx",
    }

    def fake_subprocess_run(cmd, *args, **kwargs):
        captured_commands.append(cmd)
        proc = MagicMock()
        proc.returncode = 0
        proc.stdout = json.dumps(mock_json_out)
        proc.stderr = ""
        return proc

    with patch("platform.system", return_value="Windows"), \
         patch("subprocess.run", side_effect=fake_subprocess_run):

        resolved_map, warning = resolve_all_tools_in_system(timeout_seconds=5)

        # 1. Assert: Exactly ONE subprocess.run call was made for all 25 tools
        assert len(captured_commands) == 1, f"Expected 1 WSL invocation, got {len(captured_commands)}"
        wsl_cmd = captured_commands[0]

        # 2. Assert: Command is an argument list using wsl -e bash -lc 'for t in ...; do echo "$t=$(command -v $t)"; done'
        assert isinstance(wsl_cmd, list)
        assert wsl_cmd[0] == "wsl"
        assert wsl_cmd[1] == "-e"
        assert wsl_cmd[2] == "bash"
        assert wsl_cmd[3] == "-lc"

        # 3. Assert: Tool names in script come strictly from registry allowlist
        bash_script = wsl_cmd[4]
        assert "for t in " in bash_script
        assert 'echo "$t=$(command -v $t)"' in bash_script
        tool_names_str = bash_script.split("for t in ")[1].split(";")[0]
        tools_in_script = tool_names_str.strip().split()
        assert len(tools_in_script) >= len(ALLOWED_BINARIES)
        for tool_arg in tools_in_script:
            assert tool_arg in ALLOWED_BINARIES, f"Tool argument '{tool_arg}' not in allowlist"

        # 4. Assert: Resolved mapping correctly parsed
        assert resolved_map.get("ffuf") == "/home/kali/go/bin/ffuf"
        assert resolved_map.get("subfinder") == "/home/kali/go/bin/subfinder"
        assert warning is None


# ==============================================================================
# 2. Cache Reuse & Persistence to backend/storage/
# ==============================================================================

def test_cache_reuse_and_disk_persistence():
    """
    Requirement 2:
      - Cache the result (paths + installed status) in memory
      - Persist it to a small JSON file under backend/storage/
      - Refresh only on explicit "Rescan WSL" or when a tool run fails with "not found".
    """
    clear_tool_path_cache()
    cache_file = _get_cache_file_path()

    # Pre-populate in-memory cache
    mock_json_out = {
        "ffuf": "/home/kali/go/bin/ffuf",
        "subfinder": "/home/kali/go/bin/subfinder",
        "nmap": "/usr/bin/nmap",
    }

    call_count = 0

    def fake_subprocess_run(cmd, *args, **kwargs):
        nonlocal call_count
        call_count += 1
        proc = MagicMock()
        proc.returncode = 0
        proc.stdout = json.dumps(mock_json_out)
        proc.stderr = ""
        return proc

    with patch("platform.system", return_value="Windows"), \
         patch("subprocess.run", side_effect=fake_subprocess_run):

        # 1. First explicit refresh
        res1 = refresh_all_tools_cache(timeout_seconds=5)
        assert call_count == 1
        assert res1["installed_count"] >= 3
        assert os.path.exists(cache_file), "Cache file was not created on disk"

        # Verify disk content format
        with open(cache_file, "r", encoding="utf-8") as f:
            disk_data = json.load(f)
        assert "last_checked" in disk_data
        assert "tools" in disk_data
        assert disk_data["tools"]["ffuf"]["installed"] is True

        # 2. Subsequent queries: MUST reuse in-memory cache and make 0 subprocess calls
        path1 = resolve_tool_absolute_path("ffuf")
        assert path1 == "/home/kali/go/bin/ffuf"
        assert is_tool_available("ffuf") is True
        assert call_count == 1, "Subprocess was invoked despite cache hit"

        all_tools = get_all_tools_status(force_refresh=False)
        assert len(all_tools) == len(RECON_TOOLS)
        assert call_count == 1, "Subprocess was invoked during get_all_tools_status"

        # 3. Simulate process restart: clear memory, verify it loads from disk cache
        clear_tool_path_cache()
        loaded = load_tools_cache_from_disk()
        assert loaded is True
        path_restored = resolve_tool_absolute_path("ffuf")
        assert path_restored == "/home/kali/go/bin/ffuf"
        assert call_count == 1, "Subprocess was invoked when loading from disk"

        # 4. Invalidate on "not found"
        invalidate_tool_cache("ffuf")
        assert is_tool_available("ffuf") is False
        assert resolve_tool_absolute_path("ffuf") is None

        # Verify disk updated
        with open(cache_file, "r", encoding="utf-8") as f:
            disk_after = json.load(f)
        assert disk_after["tools"]["ffuf"]["installed"] is False


# ==============================================================================
# 3. Timeout Handling (10s Timeout & Partial Cache Return)
# ==============================================================================

def test_timeout_handling_returns_cached_or_partial_data_with_warning():
    """
    Requirement 3:
      - ?refresh=true re-runs the single call with a 10s timeout
      - Returns partial/cached data with a warning if it times out
    """
    clear_tool_path_cache()

    # Pre-populate cache so we have baseline data
    mock_prior_out = {"ffuf": "/usr/bin/ffuf"}
    with patch("platform.system", return_value="Windows"), \
         patch("subprocess.run", return_value=MagicMock(returncode=0, stdout=json.dumps(mock_prior_out), stderr="")):
        refresh_all_tools_cache(timeout_seconds=5)

    # Now simulate WSL hang / timeout
    def fake_subprocess_timeout(cmd, *args, **kwargs):
        raise subprocess.TimeoutExpired(cmd=cmd, timeout=10)

    with patch("platform.system", return_value="Windows"), \
         patch("subprocess.run", side_effect=fake_subprocess_timeout):

        resolved_paths, warning = resolve_all_tools_in_system(timeout_seconds=10)

        # 1. Assert: Warning string generated
        assert warning is not None
        assert "timed out" in warning.lower()

        # 2. Assert: Refresh with timeout preserves prior cache and exposes warning
        status_meta = get_all_tools_status_with_metadata(force_refresh=True, timeout_seconds=10)
        assert status_meta["warning"] is not None
        assert "timed out" in status_meta["warning"].lower()
        # ffuf should still be available from prior cache
        ffuf_item = next(t for t in status_meta["tools"] if t["key"] == "ffuf")
        assert ffuf_item["installed"] is True
        assert ffuf_item["path"] == "/usr/bin/ffuf"


# ==============================================================================
# 4. Tool Name Validation
# ==============================================================================

def test_tool_name_validation_strictly_rejects_injections_and_unregistered():
    """
    Requirement 1 & 6:
      - Tool names come only from the registry allowlist.
      - Reject invalid input and injection payloads.
    """
    # 1. Valid names
    assert validate_tool_name("ffuf") == "ffuf"
    assert validate_tool_name("subfinder") == "subfinder"
    assert validate_tool_name("  Katana  ") == "katana"
    assert validate_tool_name("openredirex") == "openredirex"

    # 2. Invalid characters / injection attempts
    invalid_cases = [
        "ffuf; rm -rf /",
        "subfinder && whoami",
        "katana|grep foo",
        "nmap -sV 127.0.0.1",
        "tool with spaces",
        "tool$(id)",
        "tool`id`",
        "../etc/passwd",
        "/usr/bin/bash",
    ]
    for bad in invalid_cases:
        with pytest.raises(ValueError) as exc_info:
            validate_tool_name(bad)
        assert "Invalid tool name" in str(exc_info.value) or "not in the tool registry" in str(exc_info.value)

    # 3. Unregistered utilities (not in allowlist)
    with pytest.raises(ValueError) as exc_info:
        validate_tool_name("curl")
    assert "not in the tool registry allowlist" in str(exc_info.value)

    with pytest.raises(ValueError) as exc_info:
        validate_tool_name("python")
    assert "not in the tool registry allowlist" in str(exc_info.value)

    # 4. BaseProvider.detect_tool integration
    with pytest.raises(ValueError):
        BaseProvider.detect_tool("unregistered_cmd")

    with pytest.raises(ValueError):
        BaseProvider.detect_tool("ffuf; whoami")


# ==============================================================================
# 5. GET /api/v1/system/tools Endpoint
# ==============================================================================

@pytest.mark.asyncio
async def test_get_system_tools_endpoint_returns_cache_immediately():
    """
    Requirement 3:
      - GET /api/v1/system/tools returns the cache immediately.
      - ?refresh=true re-runs the single call with a 10s timeout.
    """
    from app.routers.system import get_system_tools

    user = {"_id": ObjectId(), "username": "admin"}

    # Mock tool cache
    mock_json_out = {"ffuf": "/usr/bin/ffuf", "katana": "/usr/bin/katana"}
    with patch("platform.system", return_value="Windows"), \
         patch("subprocess.run", return_value=MagicMock(returncode=0, stdout=json.dumps(mock_json_out), stderr="")):
        refresh_all_tools_cache(timeout_seconds=5)

    # 1. GET /system/tools (refresh=False)
    t0 = time.time()
    res = await get_system_tools(refresh=False)
    dur = time.time() - t0

    assert dur < 0.2, f"Cached response took {dur}s, expected sub-second"
    assert "tools" in res
    assert "last_checked" in res
    assert res["last_checked"] is not None
    assert res["total"] == len(RECON_TOOLS)

    # 2. GET /system/tools?refresh=true
    with patch("app.core.tools.resolve_all_tools_in_system", return_value=(mock_json_out, None)) as mock_resolve:
        res_refreshed = await get_system_tools(refresh=True)
        assert mock_resolve.called
        assert res_refreshed["total"] == len(RECON_TOOLS)


# ==============================================================================
# 6. Setting assume_tools_installed (Default True & Scan Behavior)
# ==============================================================================

@pytest.mark.asyncio
async def test_assume_tools_installed_setting_skips_pre_scan_gate():
    """
    Requirement 4:
      - Add project/global setting assume_tools_installed (default true).
      - When true, scans skip the pre-scan availability gate and use cached paths.
      - Failed runs still emit stage_error and the scan continues.
    """
    from app.providers.unified_discovery_provider import UnifiedDiscoveryProvider

    # 1. Verify global default is True
    assert settings.ASSUME_TOOLS_INSTALLED is True

    provider = UnifiedDiscoveryProvider()

    # Case A: assume_tools_installed = False, tool marked not installed
    # Should skip upfront with stage_skipped
    with patch("app.providers.unified_discovery_provider.is_tool_available", return_value=False):
        events_skipped = []
        async for ev in provider.discover(
            seed_domains=["example.com"],
            scan_mode="fast",
            project_config={"assume_tools_installed": False, "scope": {"in_scope": ["example.com"], "out_of_scope": []}},
        ):
            events_skipped.append(ev)

        # Passive tools should be skipped
        skipped_events = [e for e in events_skipped if e.get("type") == "stage_skipped"]
        assert len(skipped_events) >= 1
        assert "tool_missing" in skipped_events[0].get("reason", "")

    # Case B: assume_tools_installed = True (default)
    # Skips pre-scan gate! Tries to execute the tool directly.
    # When execution fails (e.g. returncode 127), emits stage_error and scan continues.
    class FailingToolProc:
        def __init__(self, *args, **kwargs):
            self.returncode = 127
            self.stdout = io.StringIO("")
            self.stderr = io.StringIO("bash: /usr/bin/subfinder: No such file or directory")
            self.pid = 99999

        def wait(self, timeout=None):
            return 127

        def poll(self):
            return 127

        def kill(self):
            pass

        def terminate(self):
            pass

        def communicate(self, *args, **kwargs):
            return ("", "bash: /usr/bin/subfinder: No such file or directory")

    # Tools are marked unavailable in pre-scan check, BUT assume_tools_installed=True bypasses the check!
    with patch("app.providers.unified_discovery_provider.is_tool_available", return_value=False), \
         patch.object(BaseProvider, "detect_tool", return_value="/usr/bin/subfinder"), \
         patch("subprocess.Popen", side_effect=FailingToolProc), \
         patch("app.job_control.register_process"), \
         patch("app.job_control.unregister_process"):

        events_executed = []
        async for ev in provider.discover(
            seed_domains=["example.com"],
            scan_mode="fast",
            project_config={"assume_tools_installed": True, "scope": {"in_scope": ["example.com"], "out_of_scope": []}},
        ):
            events_executed.append(ev)

        # 1. Assert: It did NOT yield stage_skipped for passive tools upfront
        passive_skips = [
            e for e in events_executed
            if e.get("type") == "stage_skipped" and "tool_missing: subfinder" in e.get("reason", "")
        ]
        assert len(passive_skips) == 0, "Pre-scan availability gate was not bypassed"

        # 2. Assert: Scan continued and completed pipeline despite tool failure
        log_msgs = [e.get("message", "") for e in events_executed if e.get("type") == "log"]
        assert any("Unified Discovery" in m or "Passive Discovery" in m for m in log_msgs)
