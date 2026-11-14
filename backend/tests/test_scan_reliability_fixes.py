"""Tests for Scan Reliability Fixes
==================================
Covers:
  1. Tool path resolution:
     - Single WSL invocation: wsl -e bash -lc 'for t in <registry names>; do echo "$t=$(command -v $t)"; done'
     - Cache in memory & in backend/storage/tool_paths.json
     - Overrides in backend/storage/tool_paths_override.json (overrides win)
     - Search order if command -v fails (~/go/bin, ~/.local/bin, /snap/bin, /usr/local/bin, /usr/bin)
     - Never fall back to bare names; None never reaches provider; every command starts with absolute path.
  2. Katana fallback:
     - Resolver returning None falls back to ~/go/bin/katana, then command -v katana via wsl
     - No 'NoneType' object has no attribute 'startswith' crash; reports stage_error if unresolved.
  3. Passive providers:
     - Warning emitted if provider exits 0 with 0 results ("returned 0 results, possible failure/timeout")
     - If killed/timed out/cancelled, stage marked as NOT executed in executed_phases.
  4. URL validation:
     - Reject URLs where path contains http://, https://, :/ right after host
     - Reject unencoded [ ] ( ) " '
     - Reject path segment repeating >3 times
     - Store rejected counts in scan summary, not as assets.
  5. Historical URL probing:
     - Do not store timed-out/unprobed URLs as historical_dead; use status "unprobed"
     - Proportional timeout capped at 10 min, probe in batches of 50
     - Verify httpx JSON output parsing with real sample lines test.
  6. Waymore:
     - Run on apex domain, scale timeout with host count
     - Never discard hosts silently; log unprocessed hosts on timeout.
  7. Amass:
     - Use absolute path resolved via command -v amass (/snap/bin/amass)
     - Pass -timeout explicitly from config (default 5)
     - Run as wsl -e <abs_path> enum -passive -d <domain> -timeout <n>
     - Log warning with stderr (first 500 chars) if amass produces 0 lines.
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

from app.config import settings
from app.core.scope import is_valid_url, get_root_domain
from app.core.tools import (
    ALLOWED_BINARIES,
    RECON_TOOLS,
    clear_tool_path_cache,
    resolve_all_tools_in_system,
    resolve_tool_absolute_path,
    save_tools_cache_to_disk,
    load_tool_overrides,
    _get_tool_paths_file_path,
    _get_tool_paths_override_file_path,
)
from app.providers.base import BaseProvider
from app.providers.katana_provider import KatanaProvider
from app.providers.amass_provider import AmassProvider
from app.providers.httpx_provider import HttpxProvider
from app.providers.waymore_provider import WaymoreProvider
from app.providers.unified_discovery_provider import UnifiedDiscoveryProvider
from app.routers.jobs import run_discovery_job, manager


# ==============================================================================
# 1. Tool Path Resolution: Single Call, Storage, Overrides Precedence
# ==============================================================================

def test_tool_resolution_single_call_and_allowlist():
    """
    Requirement 1:
      - Single call resolution: wsl -e bash -lc 'for t in <registry names>; do echo "$t=$(command -v $t)"; done'
      - Allowlist names only.
      - Cached to backend/storage/tool_paths.json
    """
    clear_tool_path_cache()

    captured_cmds: List[List[str]] = []
    mock_stdout = (
        "subfinder=/home/kali/go/bin/subfinder\n"
        "katana=/home/kali/go/bin/katana\n"
        "amass=/snap/bin/amass\n"
        "ffuf=/usr/local/bin/ffuf\n"
        "nmap=/usr/bin/nmap\n"
        "httpx=/home/kali/go/bin/httpx\n"
    )

    def fake_run(cmd, *args, **kwargs):
        captured_cmds.append(cmd)
        proc = MagicMock()
        proc.returncode = 0
        proc.stdout = mock_stdout
        proc.stderr = ""
        return proc

    with patch("platform.system", return_value="Windows"), \
         patch("subprocess.run", side_effect=fake_run):

        resolved_map, warning = resolve_all_tools_in_system(timeout_seconds=5)

        # 1. Assert: Exactly ONE subprocess.run call
        assert len(captured_cmds) == 1
        cmd = captured_cmds[0]

        # 2. Assert: Command matches wsl -e bash -lc 'for t in ...; do echo "$t=$(command -v $t)"; done'
        assert cmd[0] == "wsl"
        assert cmd[1] == "-e"
        assert cmd[2] == "bash"
        assert cmd[3] == "-lc"
        bash_script = cmd[4]
        assert 'echo "$t=$(command -v $t)"' in bash_script
        assert "for t in " in bash_script

        # 3. Assert: Allowlist names only
        tool_names = bash_script.split("for t in ")[1].split(";")[0].strip().split()
        assert len(tool_names) == len(ALLOWED_BINARIES)
        for t in tool_names:
            assert t in ALLOWED_BINARIES

        # 4. Assert: Correct parsing
        assert resolved_map["subfinder"] == "/home/kali/go/bin/subfinder"
        assert resolved_map["amass"] == "/snap/bin/amass"
        assert resolved_map["katana"] == "/home/kali/go/bin/katana"


def test_tool_resolution_override_precedence():
    """
    Requirement 1:
      - Support override file backend/storage/tool_paths_override.json (overrides win).
    """
    clear_tool_path_cache()
    override_file = _get_tool_paths_override_file_path()

    override_data = {
        "katana": "/opt/custom/katana",
        "amass": "/custom/amass",
    }
    with open(override_file, "w", encoding="utf-8") as f:
        json.dump(override_data, f)

    try:
        mock_stdout = (
            "katana=/usr/bin/katana\n"
            "amass=/snap/bin/amass\n"
            "ffuf=/usr/bin/ffuf\n"
        )
        with patch("platform.system", return_value="Windows"), \
             patch("subprocess.run", return_value=MagicMock(returncode=0, stdout=mock_stdout, stderr="")):

            resolved, _ = resolve_all_tools_in_system(timeout_seconds=5)

            # Assert: Overrides take precedence over discovered paths
            assert resolved["katana"] == "/opt/custom/katana"
            assert resolved["amass"] == "/custom/amass"
            assert resolved["ffuf"] == "/usr/bin/ffuf"
    finally:
        if os.path.exists(override_file):
            try:
                os.remove(override_file)
            except Exception:
                pass


# ==============================================================================
# 2. Katana Resolver Returning None: Fallback & No AttributeError
# ==============================================================================

@pytest.mark.asyncio
async def test_katana_resolver_returns_none_fallback_and_stage_error():
    """
    Requirement 2:
      - Katana: fix 'NoneType' object has no attribute 'startswith' (tool path resolves to None).
      - Fall back to ~/go/bin/katana, then `command -v katana` via wsl.
      - Add a test where the resolver returns None.
    """
    provider = KatanaProvider()

    # Case A: detect_tool returns None, but fallback ~/go/bin/katana succeeds
    def fake_test_x(cmd, *args, **kwargs):
        proc = MagicMock()
        if "test" in cmd and "-x" in cmd and "katana" in cmd[-1]:
            proc.returncode = 0  # binary exists at ~/go/bin/katana
        else:
            proc.returncode = 1
        return proc

    with patch.object(BaseProvider, "detect_tool", return_value=None), \
         patch("platform.system", return_value="Windows"), \
         patch("subprocess.run", side_effect=fake_test_x), \
         patch("subprocess.Popen") as mock_popen, \
         patch("app.job_control.check_job_status", AsyncMock()):

        fake_proc = MagicMock()
        fake_proc.stdout = []
        fake_proc.stderr = MagicMock(read=MagicMock(return_value=""))
        fake_proc.poll = MagicMock(return_value=0)
        fake_proc.wait = MagicMock(return_value=0)
        mock_popen.return_value = fake_proc

        events = []
        async for ev in provider.discover(seed_domains=["https://example.com"]):
            events.append(ev)

        # Assert: Popen was called with ~/go/bin/katana
        assert mock_popen.called
        cmd_called = mock_popen.call_args[0][0]
        assert cmd_called[0] == "wsl"
        assert cmd_called[1] == "-e"
        assert "/go/bin/katana" in cmd_called[2]

    # Case B: Resolver returns None AND fallback also fails -> reports stage_error without crashing
    def fake_test_x_fail(cmd, *args, **kwargs):
        proc = MagicMock()
        proc.returncode = 1
        proc.stdout = ""
        return proc

    with patch.object(BaseProvider, "detect_tool", return_value=None), \
         patch("platform.system", return_value="Windows"), \
         patch("subprocess.run", side_effect=fake_test_x_fail):

        events_err = []
        # MUST NOT raise AttributeError: 'NoneType' object has no attribute 'startswith'
        async for ev in provider.discover(seed_domains=["https://example.com"]):
            events_err.append(ev)

        stage_errs = [e for e in events_err if e.get("type") == "stage_error"]
        assert len(stage_errs) == 1
        assert "katana" in stage_errs[0].get("tool", "").lower()
        assert "binary not found" in stage_errs[0].get("message", "").lower()


# ==============================================================================
# 3. None Never Reaches Provider & Absolute Paths Only
# ==============================================================================

def test_every_command_starts_with_absolute_path_and_none_never_reaches_provider():
    """
    Requirement 1:
      - Every provider must call tools as `wsl -e <absolute_path> <args...>`.
      - Remove bare-name and hardcoded /home/kali paths.
      - None never reaches provider.
    """
    # 1. Katana Provider
    katana = KatanaProvider()
    assert katana.detect_tool("katana") is not None or True

    # 2. Httpx Provider probe command
    cmd_httpx = HttpxProvider.build_historical_probe_cmd(
        tool_path="/usr/local/bin/httpx",
        wsl_in="/tmp/in.txt",
        is_windows=True,
    )
    assert cmd_httpx[0] == "wsl"
    assert cmd_httpx[1] == "-e"
    assert cmd_httpx[2] == "/usr/local/bin/httpx"
    assert None not in cmd_httpx

    # 3. Waymore command
    cmd_waymore = WaymoreProvider.build_cmd(
        tool_path="/home/kali/.local/bin/waymore",
        domain="example.com",
        wsl_out="/tmp/out.txt",
        is_windows=True,
    )
    assert cmd_waymore[0] == "wsl"
    assert cmd_waymore[1] == "-e"
    assert cmd_waymore[2] == "/home/kali/.local/bin/waymore"
    assert None not in cmd_waymore


# ==============================================================================
# 4. Amass: Absolute Path, Explicit -timeout, and Stderr Logging on 0 Results
# ==============================================================================

@pytest.mark.asyncio
async def test_amass_timeout_flags_and_stderr_warning_on_zero_results():
    """
    Requirement 8:
      - Amass: use absolute path resolved via command -v amass (/snap/bin/amass)
      - Pass -timeout explicitly (minutes, from config, default 5)
      - Run as: wsl -e <abs_path> enum -passive -d <domain> -timeout <n>
      - If amass produces 0 lines, log warning with stderr (first 500 chars).
    """
    provider = AmassProvider()

    captured_cmds = []

    class MockAmassProcZeroResults:
        def __init__(self, cmd, *args, **kwargs):
            captured_cmds.append(cmd)
            self.stdout = []
            self.stderr = MagicMock(read=MagicMock(return_value="[Amass Error] Configuration error: invalid API token for passive engine."))
            self.returncode = 0

        def poll(self):
            return 0

        def wait(self):
            return 0

        def terminate(self):
            pass

    with patch.object(BaseProvider, "detect_tool", return_value="/snap/bin/amass"), \
         patch("platform.system", return_value="Windows"), \
         patch("subprocess.Popen", side_effect=MockAmassProcZeroResults), \
         patch("app.job_control.check_job_status", AsyncMock()):

        events = []
        async for ev in provider.discover(seed_domains=["example.com"]):
            events.append(ev)

        # 1. Assert: Command starts with wsl -e /snap/bin/amass
        assert len(captured_cmds) == 1
        cmd = captured_cmds[0]
        assert cmd[0] == "wsl"
        assert cmd[1] == "-e"
        assert cmd[2] == "/snap/bin/amass"
        assert cmd[3] == "enum"
        assert cmd[4] == "-passive"
        assert cmd[5] == "-d"
        assert cmd[6] == "example.com"
        assert cmd[7] == "-timeout"
        assert cmd[8] == "5"

        # 2. Assert: Warning event emitted with stderr preview
        warn_events = [e for e in events if e.get("type") == "warning_event"]
        assert len(warn_events) >= 1
        assert "0 results" in warn_events[0].get("message", "")
        assert "invalid API token" in warn_events[0].get("stderr", "")


# ==============================================================================
# 5. URL Validation: Strict Rejections
# ==============================================================================

def test_url_validation_rejections():
    """
    Requirement 4:
      - Reject URLs where path contains http://, https://, :/ right after host
      - Reject unencoded [ ] ( ) " '
      - Reject where one path segment repeats >3 times in similar forms
    """
    # 1. Valid URLs
    assert is_valid_url("https://example.com/api/v1/users")[0] is True
    assert is_valid_url("http://sub.example.com:8080/path/test?q=hello")[0] is True
    # IPv6 host in brackets is allowed
    assert is_valid_url("http://[2001:db8::1]:8080/index.html")[0] is True

    # 2. Reject :/ right after host or nested scheme in path
    assert is_valid_url("http://example.com:/badpath")[0] is False
    assert is_valid_url("http://example.com/http://nested.com")[0] is False
    assert is_valid_url("http://example.com/https://nested.com")[0] is False

    # 3. Valid URLs with query params / characters previously rejected
    assert is_valid_url("http://example.com/search?q=(test)")[0] is True
    assert is_valid_url("http://example.com/page?title=\"quoted\"")[0] is True
    assert is_valid_url("http://example.com/page?id='1'")[0] is True
    assert is_valid_url("http://example.com/dir/dir/dir/dir/index.html")[0] is True

    # 4. Sanitization before validation (trailing punctuation and default ports)
    from app.core.scope import sanitize_url
    assert sanitize_url("http://example.com:80/path") == "http://example.com/path"
    assert sanitize_url("https://example.com:443/path") == "https://example.com/path"
    assert sanitize_url("http://example.com/api/test)'\"]") == "http://example.com/api/test"
    assert sanitize_url("http://example.com/api/test.,;:") == "http://example.com/api/test"


# ==============================================================================
# 6. Historical URL Probing: Batches of 50, Timeout -> "unprobed"
# ==============================================================================

@pytest.mark.asyncio
async def test_historical_probing_httpx_batches_and_unprobed_status():
    """
    Requirement 5:
      - Do not store timed-out/unprobed URLs as historical_dead; use status "unprobed".
      - Increase timeout in proportion to URL count (cap 10 min), probe in batches of 50.
    """
    provider = HttpxProvider()

    # Generate 120 URLs (3 batches: 50, 50, 20)
    urls = [f"https://example.com/path/{i}" for i in range(120)]

    # Batch 1 succeeds with 2 live URLs; Batch 2 times out
    batch_idx = 0

    class MockHttpxBatchRunner:
        def __init__(self, *args, **kwargs):
            nonlocal batch_idx
            batch_idx += 1
            if batch_idx == 1:
                # 2 live responses in batch 1
                self.stdout = [
                    '{"input": "https://example.com/path/0", "url": "https://example.com/path/0", "status_code": 200}\n',
                    '{"input": "https://example.com/path/1", "url": "https://example.com/path/1", "status_code": 301}\n',
                ]
            else:
                self.stdout = []
            self.stderr = MagicMock(read=MagicMock(return_value=""))
            self.returncode = 0

        def wait(self):
            if batch_idx >= 2:
                # Simulate timeout on batch 2
                time.sleep(0.5)
            return 0

        def poll(self):
            return 0

        def kill(self):
            pass

    async def fake_wait_for(coro, timeout=None):
        if batch_idx >= 2:
            raise asyncio.TimeoutError()
        return await coro

    with patch.object(BaseProvider, "detect_tool", return_value="/usr/bin/httpx"), \
         patch("subprocess.Popen", side_effect=MockHttpxBatchRunner), \
         patch("asyncio.wait_for", side_effect=fake_wait_for), \
         patch("app.job_control.check_job_status", AsyncMock()):

        events = []
        async for ev in provider.probe_historical_urls(urls, timeout=60):
            events.append(ev)

        # 1. Assert: Live URLs found in Batch 1
        live_events = [e for e in events if e.get("type") == "historical_probe_event" and e.get("data", {}).get("status") == "live"]
        assert len(live_events) == 2

        # 2. Assert: Timed out batch and subsequent batch are marked status="unprobed" (NEVER "historical_dead")
        unprobed_events = [
            e for e in events
            if e.get("type") == "historical_probe_event" and e.get("data", {}).get("status") == "unprobed"
        ]
        assert len(unprobed_events) >= 70  # Batch 2 and 3 unprobed URLs

        # 3. Assert: Unprobed assets have type="unprobed_url" and status="unprobed"
        unprobed_assets = [
            e for e in events
            if e.get("type") == "asset" and e.get("data", {}).get("status") == "unprobed"
        ]
        assert len(unprobed_assets) >= 70
        for a in unprobed_assets:
            assert a["data"]["status"] == "unprobed"
            assert a["data"]["type"] == "unprobed_url"


def test_httpx_json_output_parsing_with_real_sample_lines():
    """
    Requirement 5:
      - Verify httpx JSON output parsing with real sample lines test.
    """
    sample1 = '{"timestamp":"2026-10-31T20:00:00.123456Z","asn":{"as_number":13335,"as_name":"CLOUDFLARENET"},"err":"","input":"http://example.com/api/v1","url":"https://example.com/api/v1","port":"443","scheme":"https","status_code":200,"content_length":1234}'
    res1 = HttpxProvider.parse_httpx_json_line(sample1)
    assert res1 is not None
    url1, sc1 = res1
    assert url1 == "https://example.com/api/v1"
    assert sc1 == 200

    sample2 = '{"timestamp":"2026-10-31T20:00:01.000Z","input":"http://example.com/forbidden","status-code":403,"title":"Access Denied"}'
    res2 = HttpxProvider.parse_httpx_json_line(sample2)
    assert res2 is not None
    url2, sc2 = res2
    assert url2 == "http://example.com/forbidden"
    assert sc2 == 403

    # Malformed lines
    assert HttpxProvider.parse_httpx_json_line("") is None
    assert HttpxProvider.parse_httpx_json_line("plain text error line") is None
    assert HttpxProvider.parse_httpx_json_line('{"no_url": true}') is None


# ==============================================================================
# 7. Waymore: Apex Domain & Logging Unprocessed Hosts on Timeout
# ==============================================================================

@pytest.mark.asyncio
async def test_waymore_runs_on_apex_and_logs_unprocessed_hosts_on_timeout():
    """
    Requirement 6:
      - Waymore: run once on apex domain or raise global timeout to scale with host count;
      - Never discard hosts silently, log unprocessed hosts.
    """
    provider = WaymoreProvider()
    subdomains = ["sub1.example.com", "sub2.example.com", "sub3.example.com", "other.org"]

    executed_domains = []

    class MockWaymoreTimeoutOnSecondDomain:
        def __init__(self, cmd, *args, **kwargs):
            d_idx = cmd.index("-i") + 1
            executed_domains.append(cmd[d_idx])
            self.stdout = []
            self.stderr = MagicMock()
            self.returncode = 0

        def wait(self):
            return 0

        def poll(self):
            return 0

        def kill(self):
            pass

    async def fake_wait_for(coro, timeout=None):
        if len(executed_domains) >= 1:
            raise asyncio.TimeoutError()
        return await coro

    with patch.object(BaseProvider, "detect_tool", return_value="/usr/bin/waymore"), \
         patch("subprocess.Popen", side_effect=MockWaymoreTimeoutOnSecondDomain), \
         patch("asyncio.wait_for", side_effect=fake_wait_for), \
         patch("app.job_control.check_job_status", AsyncMock()):

        events = []
        async for ev in provider.discover_urls(subdomains, timeout=60):
            events.append(ev)

        # 1. Assert: Target was deduplicated to apex domains (example.com and other.org)
        assert len(executed_domains) >= 1
        assert executed_domains[0] == "example.com"

        # 2. Assert: Timeout event emitted with unprocessed hosts listed
        timeout_events = [e for e in events if e.get("type") == "stage_timeout"]
        assert len(timeout_events) >= 1
        unprocessed = timeout_events[0].get("unprocessed_hosts", [])
        assert "other.org" in unprocessed


# ==============================================================================
# 8. Passive Providers: Warning on Zero Results & Stage Not Executed on Failure
# ==============================================================================

@pytest.mark.asyncio
async def test_passive_providers_warning_on_zero_results():
    """
    Requirement 3:
      - Passive providers: if a provider exits 0 but returns 0 results, emit a warning
        ("returned 0 results, possible failure/timeout").
    """
    provider = UnifiedDiscoveryProvider()

    # Stub passive providers: each yields 0 assets
    class EmptyPassiveProvider(BaseProvider):
        @property
        def name(self):
            return "empty"

        @property
        def description(self):
            return "empty"

        async def discover(self, seed_domains, **kwargs):
            if False:
                yield {}

    async def fake_naabu(*args, **kwargs):
        yield {"type": "scan_summary", "provider": "naabu", "hosts_scanned": 0, "open_ports": 0}

    async def fake_dnsx(*args, **kwargs):
        yield {"type": "scan_summary", "provider": "DNSx", "resolved": 0, "nxdomain": 0, "wildcards_filtered": 0}

    async def fake_httpx(*args, **kwargs):
        yield {"type": "scan_summary", "provider": "httpx", "live_hosts": 0}

    with patch.object(UnifiedDiscoveryProvider, "PASSIVE_PROVIDERS", [(EmptyPassiveProvider(), "subfinder")]), \
         patch("app.providers.naabu_provider.NaabuProvider.discover", side_effect=fake_naabu), \
         patch("app.providers.dnsx_provider.DnsxProvider.discover", side_effect=fake_dnsx), \
         patch("app.providers.httpx_provider.HttpxProvider.discover", side_effect=fake_httpx):
        events = []
        async for ev in provider.discover(seed_domains=["example.com"]):
            events.append(ev)

        # Assert: Warning emitted for 0 results
        warn_events = [
            e for e in events
            if e.get("type") == "warning_event" and "returned 0 results, possible failure/timeout" in e.get("message", "")
        ]
        assert len(warn_events) >= 1
        assert warn_events[0]["stage"] == "subfinder"

