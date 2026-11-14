"""Tests for Scan Fixes from Latest Live Run
===========================================
Covers all 5 requirements:
1. Tool path overrides:
   - tool_paths_override.json wins over command -v and any hardcoded order.
   - Never default to ~/go/bin/<tool> without checking it exists.
   - Set amass to /snap/bin/amass by default.
2. Enforce timeouts with hard kill of whole process tree at deadline:
   - waymore, ffuf, httpx, amass.
   - Keep partial output.
   - Emit stage_timeout at the deadline, not after.
3. Remove test -x pre-checks (gau, linkfinder, others):
   - Run resolved path and handle "not found" on failure.
   - A pre-check timeout must never skip a tool.
4. LinkFinder:
   - Fix None script path (resolve ~/tools/LinkFinder/linkfinder.py via resolver/override).
   - Test where the resolver returns None emits stage_error and does not crash.
5. URL validation & sanitization:
   - Sanitize before rejecting: trim trailing ) ' " ] and punctuation: ')]}\'\">.,;:'
   - Strip default :80/:443, then dedupe.
   - Reject only nested schemes, ":/" right after host, and invalid hostnames.
6. Guard checks across all providers against NoneType command join crash.
"""

import asyncio
import json
import os
import platform
import subprocess
import tempfile
import time
from typing import Any, Dict, List
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from bson import ObjectId

from app.core.scope import sanitize_url, is_valid_url
from app.core.tools import (
    clear_tool_path_cache,
    load_tool_overrides,
    resolve_all_tools_in_system,
    resolve_tool_absolute_path,
    _get_tool_paths_override_file_path,
)
from app.providers.base import BaseProvider
from app.providers.subfinder_provider import SubfinderProvider
from app.providers.assetfinder_provider import AssetfinderProvider
from app.providers.chaos_provider import ChaosProvider
from app.providers.dnsx_provider import DnsxProvider
from app.providers.amass_provider import AmassProvider
from app.providers.katana_provider import KatanaProvider
from app.providers.httpx_provider import HttpxProvider
from app.providers.waymore_provider import WaymoreProvider
from app.providers.ffuf_provider import FfufProvider
from app.providers.linkfinder_provider import LinkfinderProvider
from app.providers.nuclei_provider import NucleiProvider
from app.providers.uro_provider import UroProvider
from app.providers.gf_provider import GfProvider
from app.providers.wafw00f_provider import Wafw00fProvider
from app.job_control import kill_process_tree


# ==============================================================================
# 1. Tool Path Overrides Precedence & Defaults
# ==============================================================================

def test_override_precedence_and_amass_default():
    """
    Requirement 1:
      - tool_paths_override.json wins over command -v and hardcoded order.
      - amass is set to /snap/bin/amass by default.
      - Never default to ~/go/bin/<tool> without checking it exists.
    """
    clear_tool_path_cache()

    # Verify default amass override
    overrides = load_tool_overrides()
    assert overrides.get("amass") == "/snap/bin/amass"

    # Temporary custom override file
    override_file = _get_tool_paths_override_file_path()
    backup_content = None
    if os.path.exists(override_file):
        with open(override_file, "r", encoding="utf-8") as f:
            backup_content = f.read()

    try:
        custom_overrides = {
            "amass": "/custom/snap/bin/amass",
            "katana": "/opt/custom/katana",
            "subfinder": "/custom/bin/subfinder",
        }
        with open(override_file, "w", encoding="utf-8") as f:
            json.dump(custom_overrides, f)

        mock_discovered = (
            "amass=/usr/bin/amass\n"
            "katana=/home/kali/go/bin/katana\n"
            "subfinder=/usr/local/bin/subfinder\n"
            "ffuf=/home/kali/go/bin/ffuf\n"
        )
        with patch("platform.system", return_value="Windows"), \
             patch("subprocess.run", return_value=MagicMock(returncode=0, stdout=mock_discovered, stderr="")):

            resolved, _ = resolve_all_tools_in_system(timeout_seconds=5)

            # Override wins over discovered command -v
            assert resolved["amass"] == "/custom/snap/bin/amass"
            assert resolved["katana"] == "/opt/custom/katana"
            assert resolved["subfinder"] == "/custom/bin/subfinder"
            # Unoverridden tool uses discovered path
            assert resolved["ffuf"] == "/home/kali/go/bin/ffuf"
    finally:
        if backup_content is not None:
            with open(override_file, "w", encoding="utf-8") as f:
                f.write(backup_content)
        else:
            with open(override_file, "w", encoding="utf-8") as f:
                json.dump({"amass": "/snap/bin/amass", "linkfinder": "/home/kali/tools/LinkFinder/linkfinder.py"}, f)


# ==============================================================================
# 2. Hard Kill Process Tree at Deadline & Keep Partial Output
# ==============================================================================

def test_kill_process_tree_function():
    """Verifies kill_process_tree invokes taskkill on Windows or os.killpg on POSIX."""
    mock_proc = MagicMock()
    mock_proc.pid = 99999
    mock_proc.poll = MagicMock(return_value=None)

    with patch("platform.system", return_value="Windows"), \
         patch("subprocess.run") as mock_run:
        kill_process_tree(mock_proc, tool_name="ffuf")
        assert mock_run.called
        # Assert taskkill was called
        call_args_list = [c[0][0] for c in mock_run.call_args_list]
        assert any("taskkill" in str(cmd) for cmd in call_args_list)


@pytest.mark.asyncio
async def test_waymore_hard_kill_and_partial_output_on_timeout():
    """
    Requirement 2: Waymore hard-kills process tree at deadline, preserves partial output,
    and emits stage_timeout.
    """
    provider = WaymoreProvider()

    # Create dummy temp file with partial URLs
    tmp_urls = ["https://example.com/api/v1", "https://example.com/login"]

    class MockWaymoreProcHangs:
        def __init__(self, cmd, *args, **kwargs):
            self.pid = 1234
            self.stdout = MagicMock(read=MagicMock(return_value=""))
            self.stderr = MagicMock(read=MagicMock(return_value=""))
            self.returncode = None
            out_file = cmd[cmd.index("-oU") + 1]
            if out_file.startswith("/mnt/"):
                parts = out_file[5:].split("/", 1)
                drive = parts[0].upper()
                rest = parts[1] if len(parts) > 1 else ""
                out_file = f"{drive}:/{rest}"
            try:
                with open(out_file, "w", encoding="utf-8") as f:
                    f.write("\n".join(tmp_urls) + "\n")
            except Exception:
                pass

        def poll(self):
            return None

        def wait(self):
            return None

        def terminate(self):
            pass

    with patch.object(BaseProvider, "detect_tool", return_value="/home/kali/.local/bin/waymore"), \
         patch("platform.system", return_value="Windows"), \
         patch("subprocess.Popen", side_effect=MockWaymoreProcHangs), \
         patch("asyncio.wait_for", side_effect=asyncio.TimeoutError), \
         patch("app.job_control.kill_process_tree") as mock_kill, \
         patch("app.job_control.check_job_status", AsyncMock()):

        events = []
        async for ev in provider.discover(seed_domains=["example.com"]):
            events.append(ev)

        # Assert process tree was hard killed
        assert mock_kill.called

        # Assert stage_timeout event emitted at deadline
        timeouts = [e for e in events if e.get("type") == "stage_timeout"]
        assert len(timeouts) >= 1
        assert timeouts[0]["tool"] == "waymore"

        # Assert partial URLs were kept
        url_events = [e for e in events if e.get("type") == "url_event"]
        assert len(url_events) == 2
        discovered_urls = [e["data"]["url"] for e in url_events]
        assert "https://example.com/api/v1" in discovered_urls


@pytest.mark.asyncio
async def test_ffuf_hard_kill_and_partial_output_on_timeout():
    """
    Requirement 2: FFUF hard-kills process tree on timeout, preserves partial JSON results,
    and emits stage_timeout.
    """
    provider = FfufProvider()

    partial_json_data = {
        "results": [
            {
                "url": "https://example.com/admin",
                "status": 200,
                "length": 1234,
                "words": 50,
                "lines": 10,
                "redirectlocation": "",
            }
        ]
    }

    class MockFfufProcHangs:
        def __init__(self, cmd, *args, **kwargs):
            self.pid = 4321
            self.stdout = MagicMock(read=MagicMock(return_value=""))
            self.stderr = MagicMock(read=MagicMock(return_value=""))
            self.returncode = None
            out_file = cmd[cmd.index("-o") + 1]
            if out_file.startswith("/mnt/"):
                parts = out_file[5:].split("/", 1)
                drive = parts[0].upper()
                rest = parts[1] if len(parts) > 1 else ""
                out_file = f"{drive}:/{rest}"
            try:
                with open(out_file, "w", encoding="utf-8") as f:
                    json.dump(partial_json_data, f)
            except Exception:
                pass

        def poll(self):
            return None

        def wait(self):
            return None

        def terminate(self):
            pass

    with patch.object(BaseProvider, "detect_tool", return_value="/home/kali/go/bin/ffuf"), \
         patch("platform.system", return_value="Windows"), \
         patch("subprocess.Popen", side_effect=MockFfufProcHangs), \
         patch("asyncio.wait_for", side_effect=asyncio.TimeoutError), \
         patch("app.job_control.kill_process_tree") as mock_kill, \
         patch("app.job_control.check_job_status", AsyncMock()):

        events = []
        async for ev in provider.discover_content(targets=["https://example.com"]):
            events.append(ev)

        assert mock_kill.called
        timeouts = [e for e in events if e.get("type") == "stage_timeout"]
        assert len(timeouts) >= 1
        assert timeouts[0]["tool"] == "ffuf"

        # Assert partial content path kept
        content_events = [e for e in events if e.get("type") == "content_path_event"]
        assert len(content_events) == 1
        assert content_events[0]["data"]["url"] == "https://example.com/admin"


@pytest.mark.asyncio
async def test_amass_hard_kill_and_partial_output_on_timeout():
    """
    Requirement 2: Amass hard-kills process tree on timeout and emits stage_timeout.
    """
    provider = AmassProvider()

    class MockAmassProcHangs:
        def __init__(self, *args, **kwargs):
            self.pid = 5555
            self.stdout = MagicMock()
            self.stdout.readline = MagicMock(return_value="")
            self.stderr = MagicMock(read=MagicMock(return_value=""))
            self.returncode = None

        def poll(self):
            return None

        def wait(self):
            return None

        def terminate(self):
            pass

    call_idx = 0
    async def fake_wait_for(coro, timeout=None):
        nonlocal call_idx
        call_idx += 1
        if call_idx <= 2:
            return f"sub{call_idx}.example.com\n"
        raise asyncio.TimeoutError()

    with patch.object(BaseProvider, "detect_tool", return_value="/snap/bin/amass"), \
         patch("platform.system", return_value="Windows"), \
         patch("subprocess.Popen", side_effect=MockAmassProcHangs), \
         patch("asyncio.wait_for", side_effect=fake_wait_for), \
         patch("app.job_control.kill_process_tree") as mock_kill, \
         patch("app.job_control.check_job_status", AsyncMock()):

        events = []
        async for ev in provider.discover(seed_domains=["example.com"]):
            events.append(ev)

        assert mock_kill.called
        timeouts = [e for e in events if e.get("type") == "stage_timeout"]
        assert len(timeouts) >= 1
        assert timeouts[0]["tool"] == "amass"

        # Partial subdomains discovered
        assets = [e for e in events if e.get("type") == "asset"]
        assert len(assets) == 2


# ==============================================================================
# 3. Removal of test -x Pre-Checks
# ==============================================================================

def test_no_test_x_pre_checks_in_source():
    """
    Requirement 3: Ensure test -x and test -f pre-checks have been eliminated from
    gau, linkfinder, subjs, gowitness, dalfox, openredirex, amass.
    """
    providers_dir = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "app", "providers"
    )
    checked_providers = [
        "gau_provider.py",
        "linkfinder_provider.py",
        "subjs_provider.py",
        "gowitness_provider.py",
        "dalfox_provider.py",
        "openredirex_provider.py",
        "amass_provider.py",
    ]
    for fname in checked_providers:
        fpath = os.path.join(providers_dir, fname)
        with open(fpath, "r", encoding="utf-8") as f:
            content = f.read()
        assert "test -x" not in content, f"{fname} contains pre-check 'test -x'"
        assert "test -f" not in content, f"{fname} contains pre-check 'test -f'"


# ==============================================================================
# 4. LinkFinder: Script Path Resolution & None Resolver Handling
# ==============================================================================

@pytest.mark.asyncio
async def test_linkfinder_resolver_returns_none_handled_gracefully():
    """
    Requirement 4:
      - LinkFinder: fix the None script path.
      - Add a test where the resolver returns None: yields stage_error and does not crash.
    """
    provider = LinkfinderProvider()

    with patch.object(BaseProvider, "detect_tool", return_value=None):
        events = []
        # Should not raise TypeError or AttributeError
        async for ev in provider.discover(seed_domains=["https://example.com/bundle.js"]):
            events.append(ev)

        stage_errors = [e for e in events if e.get("type") == "stage_error"]
        assert len(stage_errors) == 1
        assert stage_errors[0]["tool"] == "linkfinder"
        assert "not found" in stage_errors[0]["message"].lower()

        skips = [e for e in events if e.get("type") == "scan_summary"]
        assert len(skips) == 1
        assert skips[0]["status"] == "SKIPPED"


def test_linkfinder_path_resolution_via_special_candidates():
    """Verifies LinkFinder resolves via override / special candidate path."""
    clear_tool_path_cache()
    p = resolve_tool_absolute_path("linkfinder")
    # Linkfinder is in overrides or special candidates
    assert p is not None
    assert "linkfinder.py" in p.lower()


# ==============================================================================
# 5. URL Validation & Sanitization
# ==============================================================================

def test_url_sanitization_rules():
    """
    Requirement 5:
      - Trim trailing ) ' " ] and punctuation: ')]}\'\">.,;:'
      - Strip default :80 and :443.
      - Deduplicate after sanitization.
    """
    # 1. Trimming trailing punctuation
    assert sanitize_url("https://example.com/path)") == "https://example.com/path"
    assert sanitize_url("https://example.com/path'") == "https://example.com/path"
    assert sanitize_url('https://example.com/path"') == "https://example.com/path"
    assert sanitize_url("https://example.com/path]") == "https://example.com/path"
    assert sanitize_url("https://example.com/path).") == "https://example.com/path"
    assert sanitize_url("https://example.com/path...;;,,") == "https://example.com/path"
    assert sanitize_url("https://example.com/path>\"") == "https://example.com/path"

    # 2. Stripping default :80/:443
    assert sanitize_url("http://example.com:80/api/v1") == "http://example.com/api/v1"
    assert sanitize_url("https://example.com:443/api/v1") == "https://example.com/api/v1"
    # Non-default ports preserved
    assert sanitize_url("http://example.com:8080/api/v1") == "http://example.com:8080/api/v1"
    assert sanitize_url("https://example.com:8443/api/v1") == "https://example.com:8443/api/v1"

    # 3. Deduplication after sanitization
    raw_list = [
        "http://example.com:80/path",
        "http://example.com/path",
        "http://example.com/path)",
        "http://example.com/path'",
    ]
    sanitized = list(dict.fromkeys(sanitize_url(u) for u in raw_list if sanitize_url(u)))
    assert len(sanitized) == 1
    assert sanitized[0] == "http://example.com/path"


def test_url_validation_rejections_and_acceptances():
    """
    Requirement 5:
      - Reject only nested schemes, ":/" right after the host, and invalid hostnames.
      - Accept valid URLs.
    """
    # Valid URLs accepted
    assert is_valid_url("https://example.com/api/v1/users")[0] is True
    assert is_valid_url("http://sub.example.com:8080/path?q=hello")[0] is True
    assert is_valid_url("https://example.com/search?q=(test)")[0] is True
    assert is_valid_url("https://example.com/page?title=\"quoted\"")[0] is True
    assert is_valid_url("https://example.com/page?id='1'")[0] is True
    assert is_valid_url("https://example.com/dir/dir/dir/dir/index.html")[0] is True
    assert is_valid_url("http://[2001:db8::1]:8080/index.html")[0] is True

    # Reject 1: ":/" right after host
    assert is_valid_url("http://example.com:/badpath")[0] is False
    assert is_valid_url("https://example.com:/")[0] is False

    # Reject 2: Nested scheme in path or query
    assert is_valid_url("http://example.com/http://nested.com")[0] is False
    assert is_valid_url("http://example.com/https://nested.com")[0] is False
    assert is_valid_url("http://example.com/redirect?dest=http://nested.com")[0] is False

    # Reject 3: Invalid hostnames
    assert is_valid_url("http://invalid_host_with_spaces/path")[0] is False
    assert is_valid_url("http:///empty-host")[0] is False
    assert is_valid_url("http://-bad-prefix.com/path")[0] is False


# ==============================================================================
# 6. Provider NoneType Guard Tests
# ==============================================================================

@pytest.mark.asyncio
async def test_providers_guard_against_nonetype_tool_path():
    """
    Verifies that when detect_tool returns None, providers emit stage_error
    and do NOT crash with TypeError: sequence item expected str, NoneType found.
    """
    providers = [
        (SubfinderProvider(), ["example.com"]),
        (AssetfinderProvider(), ["example.com"]),
        (ChaosProvider(), ["example.com"]),
        (DnsxProvider(), ["example.com"]),
        (NucleiProvider(), ["https://example.com"]),
        (UroProvider(), ["https://example.com/1", "https://example.com/2"]),
        (GfProvider(), ["https://example.com"]),
        (Wafw00fProvider(), ["example.com"]),
    ]

    for prov, target in providers:
        with patch.object(BaseProvider, "detect_tool", return_value=None), \
             patch("platform.system", return_value="Windows"):
            events = []
            try:
                async for ev in prov.discover(target):
                    events.append(ev)
            except Exception as exc:
                pytest.fail(f"Provider {prov.name} raised exception when tool_path is None: {exc}")

            stage_errors = [e for e in events if e.get("type") in ("stage_error", "stage_skipped")]
            assert len(stage_errors) >= 1, f"Provider {prov.name} did not yield stage_error when tool_path is None"
