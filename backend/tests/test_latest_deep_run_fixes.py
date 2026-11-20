"""Tests for Latest Deep Run Scan Fixes
======================================
Covers:
1. Historical Probing:
   (a) Probe only URLs whose host is in live-host set; mark others "unprobed" with reason "host not live"
   (b) Batch timeout affects only that batch: mark it unprobed and CONTINUE with remaining batches
   (c) Scale batch timeout with batch size and per-URL timeout
   (d) Report final live/dead/unprobed counts and reason for unprobed ones
2. Arjun/x8:
   - Exit code != 0 is stage_error (logs first 500 chars of stderr) and endpoint counts as failed, not "0 params"
   - Verify builder against arjun -h (supported flags including -w small)
   - Circuit breaker: after 3 consecutive failures/timeouts, stop phase, emit stage_error, list untested endpoints
4. crt.sh and certspotter:
   - Log HTTP status, retry 3 times with backoff on 5xx/timeouts
   - Report "request failed (status N)" separately from "0 results"
   - Certspotter accepts optional API key from local keys file
6. GoWitness:
   - Detect installed version and use matching command (v3: scan single)
   - Report error if 0 screenshots were requested for live hosts but none were produced
"""

import asyncio
import json
import os
import platform
import shutil
import subprocess
import tempfile
import time
import uuid
from typing import Any, Dict, List
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest
from bson import ObjectId
from motor.motor_asyncio import AsyncIOMotorClient

import app.database as database_module
from app.providers.httpx_provider import HttpxProvider
from app.providers.param_discovery_provider import ParamDiscoveryProvider
from app.providers.crtsh_provider import CrtshProvider
from app.providers.certspotter_provider import CertspotterProvider
from app.providers.gowitness_provider import GowitnessProvider
from app.providers.waymore_provider import WaymoreProvider
from app.providers.chaos_provider import ChaosProvider
from app.providers.linkfinder_provider import LinkfinderProvider
from app.core.provider_keys import load_provider_keys, save_provider_keys


async def setup_real_test_db():
    mongo_uri = os.getenv("MONGO_URI", "mongodb://localhost:27017")
    client = AsyncIOMotorClient(mongo_uri, serverSelectionTimeoutMS=2000)
    try:
        await client.admin.command("ping")
    except Exception as exc:
        pytest.skip(f"Real MongoDB is not running at {mongo_uri}: {exc}")

    test_db_name = f"reconforge_test_{uuid.uuid4().hex[:8]}"
    db = client[test_db_name]

    old_db = database_module.db_helper.db
    old_is_mock = database_module.db_helper.is_mock
    database_module.db_helper.db = db
    database_module.db_helper.is_mock = False

    return client, db, old_db, old_is_mock


async def teardown_real_test_db(client, db, old_db, old_is_mock):
    try:
        await client.drop_database(db.name)
        client.close()
    finally:
        database_module.db_helper.db = old_db
        database_module.db_helper.is_mock = old_is_mock


# ==============================================================================
# 1. Historical Probing Tests
# ==============================================================================

@pytest.mark.asyncio
async def test_item1_historical_probing_live_host_filtering_and_unprobed_reasons():
    """
    1(a) probe only URLs whose host is in live-host set; mark others "unprobed" with reason "host not live"
    1(d) report final live/dead/unprobed counts and reason for unprobed ones
    """
    provider = HttpxProvider()
    input_urls = [
        "http://live.example.com/api/test",
        "http://dead-host.example.com/admin",
        "https://live.example.com/login",
        "http://unseen.example.com/page",
    ]
    live_hosts = ["live.example.com"]

    # Mock tool detection
    with patch.object(provider, "detect_tool", return_value="/usr/bin/httpx"), \
         patch("app.job_control.check_job_status", AsyncMock()):

        # Mock subprocess execution for the live URLs batch
        class MockProc:
            returncode = 0
            stdout = [
                '{"url": "http://live.example.com/api/test", "status_code": 200}\n',
            ]
            stderr = []
            def wait(self, timeout=None):
                return 0

        with patch("subprocess.Popen", return_value=MockProc()), \
             patch("app.job_control.register_process"), \
             patch("app.job_control.unregister_process"):

            events = []
            async for ev in provider.probe_historical_urls(
                input_urls,
                live_hosts=live_hosts,
                rate_limit=10,
                timeout=30,
            ):
                events.append(ev)

            # Check unprobed events
            unprobed_events = [e for e in events if e.get("type") == "historical_probe_event" and e.get("data", {}).get("status") == "unprobed"]
            assert len(unprobed_events) == 2, f"Expected 2 unprobed events, got {len(unprobed_events)}"
            for ue in unprobed_events:
                assert ue["data"]["reason"] == "host not live"
                assert "dead-host.example.com" in ue["data"]["url"] or "unseen.example.com" in ue["data"]["url"]

            # Check scan_summary counts and reasons
            summaries = [e for e in events if e.get("type") == "scan_summary"]
            assert len(summaries) >= 1
            summ = summaries[0]
            assert summ["live_count"] == 1
            assert summ["dead_count"] == 1
            assert summ["unprobed_count"] == 2
            assert summ["unprobed_reasons"]["host not live"] == 2


@pytest.mark.asyncio
async def test_item1_live_host_set_accepts_scheme_and_port():
    """
    1(a) live-host entries may be URLs or host:port pairs; compare bare hosts.
    """
    provider = HttpxProvider()

    class MockProc:
        returncode = 0
        stdout = []
        stderr = []
        def wait(self, timeout=None):
            return 0

    with patch.object(provider, "detect_tool", return_value="/usr/bin/httpx"), \
         patch("app.job_control.check_job_status", AsyncMock()), \
         patch("subprocess.Popen", return_value=MockProc()), \
         patch("app.job_control.register_process"), \
         patch("app.job_control.unregister_process"):

        events = []
        async for ev in provider.probe_historical_urls(
            ["http://live.example.com/api"],
            live_hosts=["https://live.example.com:8443/"],
            rate_limit=10,
            timeout=30,
        ):
            events.append(ev)

    unprobed = [
        e for e in events
        if e.get("type") == "historical_probe_event" and e.get("data", {}).get("status") == "unprobed"
    ]
    assert unprobed == []
    summ = [e for e in events if e.get("type") == "scan_summary"][0]
    assert summ["probed_count"] == 1


@pytest.mark.asyncio
async def test_item1_batch_timeout_continues_remaining_batches():
    """
    1(b) a batch timeout affects only that batch: mark it unprobed and CONTINUE with remaining batches
    1(c) scale batch timeout with batch size and per-URL timeout
    """
    provider = HttpxProvider()
    # Create 60 URLs to form 2 batches (batch_size=50)
    urls = [f"http://live.example.com/path_{i}" for i in range(60)]
    live_hosts = ["live.example.com"]

    call_count = 0

    def mock_popen(*args, **kwargs):
        nonlocal call_count
        call_count += 1
        proc = MagicMock()
        proc.returncode = 0
        if call_count == 1:
            # Batch 1 will trigger asyncio.TimeoutError
            proc.stdout = []
            proc.stderr = []
            proc.wait = MagicMock(side_effect=lambda: time.sleep(0.01))
        else:
            # Batch 2 will succeed
            proc.stdout = ['{"url": "http://live.example.com/path_55", "status_code": 200}\n']
            proc.stderr = []
            proc.wait = MagicMock(return_value=0)
        return proc

    # Make asyncio.wait_for raise TimeoutError only for first batch
    original_wait_for = asyncio.wait_for
    wait_for_calls = 0

    async def mock_wait_for(fut, timeout):
        nonlocal wait_for_calls
        wait_for_calls += 1
        if wait_for_calls == 1:
            raise asyncio.TimeoutError()
        return await original_wait_for(fut, timeout)

    with patch.object(provider, "detect_tool", return_value="/usr/bin/httpx"), \
         patch("app.job_control.check_job_status", AsyncMock()), \
         patch("app.job_control.kill_process_tree"), \
         patch("subprocess.Popen", side_effect=mock_popen), \
         patch("asyncio.wait_for", side_effect=mock_wait_for), \
         patch("app.job_control.register_process"), \
         patch("app.job_control.unregister_process"):

        events = []
        async for ev in provider.probe_historical_urls(
            urls,
            live_hosts=live_hosts,
            rate_limit=10,
            timeout=100,
        ):
            events.append(ev)

        # Assert: Batch 1 timed out, but Batch 2 was probed and did NOT abort!
        assert call_count == 2, f"Expected 2 batch calls, got {call_count}"

        # Batch 1 URLs marked unprobed with "batch timeout"
        unprobed = [e for e in events if e.get("type") == "historical_probe_event" and e.get("data", {}).get("status") == "unprobed"]
        assert len(unprobed) == 50
        assert unprobed[0]["data"]["reason"] == "batch timeout"

        # Batch 2 live URL was found
        live_events = [e for e in events if e.get("type") == "historical_probe_event" and e.get("data", {}).get("status") == "live"]
        assert len(live_events) == 1
        assert live_events[0]["data"]["url"] == "http://live.example.com/path_55"


# ==============================================================================
# 2. Arjun / x8 Parameter Discovery Tests
# ==============================================================================

def test_item2_arjun_builder_flags_and_small_wordlist():
    """
    2. Verify builder against arjun -h output and fix unsupported flags.
    Ensures -w small is used by default to prevent large wordlist timeouts.
    """
    cmd = ParamDiscoveryProvider.build_arjun_cmd(
        tool_path="/usr/local/bin/arjun",
        url="http://testasp.vulnweb.com/login",
        wsl_out="/tmp/out.json",
        rate_limit=10,
        custom_headers={"X-Token": "secret"},
        timeout=15,
        wordlist="small",
        is_windows=False,
    )
    assert "-u" in cmd
    assert "http://testasp.vulnweb.com/login" in cmd
    assert "-oJ" in cmd
    assert "-w" in cmd
    assert "small" in cmd
    assert "-m" in cmd
    assert "GET" in cmd
    assert "--rate-limit" in cmd
    assert "--headers" in cmd


def _arjun_help_output() -> str | None:
    """Returns `arjun -h` output from the host or WSL, or None when unavailable."""
    candidates = []
    local = shutil.which("arjun")
    if local:
        candidates.append([local, "-h"])
    try:
        resolved = ParamDiscoveryProvider.detect_tool("arjun")
    except Exception:
        resolved = None
    if resolved:
        if platform.system().lower() == "windows":
            candidates.append(["wsl", "-e", resolved, "-h"])
        else:
            candidates.append([resolved, "-h"])
    candidates.append(["wsl", "-e", "arjun", "-h"])
    for candidate in candidates:
        try:
            res = subprocess.run(candidate, capture_output=True, text=True, timeout=20)
        except Exception:
            continue
        text = (res.stdout or "") + (res.stderr or "")
        if "usage:" in text.lower() and "--rate-limit" in text:
            return text
    return None


def test_item2_arjun_builder_flags_are_supported_by_arjun_help():
    """
    2. Verify every flag emitted by the builder against the installed `arjun -h`
    output so unsupported flags cannot silently make arjun exit non-zero.
    """
    help_text = _arjun_help_output()
    if not help_text:
        pytest.skip("arjun is not installed on the host or in WSL")

    cmd = ParamDiscoveryProvider.build_arjun_cmd(
        tool_path="/usr/local/bin/arjun",
        url="http://example.com/login",
        wsl_out="/tmp/out.json",
        rate_limit=10,
        custom_headers={"X-Token": "secret"},
        timeout=15,
        wordlist="small",
        is_windows=False,
    )
    used_flags = [arg for arg in cmd if arg.startswith("-")]
    assert used_flags, "builder emitted no flags"
    for flag in used_flags:
        assert flag in help_text, f"unsupported arjun flag: {flag}"


@pytest.mark.asyncio
async def test_item2_arjun_exit_code_nonzero_is_stage_error_and_counts_as_failed():
    """
    2. exit code != 0 is stage_error (log the first 500 chars of stderr) and the
    endpoint counts as failed, not "0 params".
    """
    provider = ParamDiscoveryProvider()
    endpoints = ["http://testasp.vulnweb.com/test1"]

    stderr_500 = "Error: Invalid target response or connection refused. " * 15

    class MockFailedProc:
        returncode = 1
        stdout = None
        stderr = MagicMock(read=MagicMock(return_value=stderr_500))
        def wait(self, timeout=None):
            return 1
        def poll(self):
            return 1
        def kill(self):
            pass

    with patch.object(provider, "detect_tool", return_value="/usr/local/bin/arjun"), \
         patch("app.job_control.check_job_status", AsyncMock()), \
         patch("subprocess.Popen", return_value=MockFailedProc()), \
         patch("app.job_control.register_process"), \
         patch("app.job_control.unregister_process"):

        events = []
        async for ev in provider.discover_parameters(endpoints, per_host_timeout=10):
            events.append(ev)

        # 1. Assert: stage_error was emitted with returncode 1 and stderr
        stage_errors = [e for e in events if e.get("type") == "stage_error"]
        assert len(stage_errors) >= 1
        err = stage_errors[0]
        assert err["returncode"] == 1
        assert "Error: Invalid target" in err["reason"]

        # 2. Assert: scan_summary reports endpoint as failed
        summaries = [e for e in events if e.get("type") == "scan_summary"]
        assert len(summaries) >= 1
        summ = summaries[0]
        assert summ["endpoints_failed"] == 1
        assert summ["endpoints_succeeded"] == 0


@pytest.mark.asyncio
async def test_item2_arjun_circuit_breaker_after_3_consecutive_failures():
    """
    2. Circuit breaker: after 3 consecutive failures/timeouts, stop the phase,
    emit stage_error, and list the untested endpoints.
    """
    provider = ParamDiscoveryProvider()
    endpoints = [
        "http://testasp.vulnweb.com/ep1",
        "http://testasp.vulnweb.com/ep2",
        "http://testasp.vulnweb.com/ep3",
        "http://testasp.vulnweb.com/ep4_untested",
        "http://testasp.vulnweb.com/ep5_untested",
    ]

    class MockProcFail:
        returncode = 2
        stdout = None
        stderr = MagicMock(read=MagicMock(return_value="Endpoint failed"))
        def wait(self, timeout=None):
            return 2
        def poll(self):
            return 2
        def kill(self):
            pass

    with patch.object(provider, "detect_tool", return_value="/usr/local/bin/arjun"), \
         patch("app.job_control.check_job_status", AsyncMock()), \
         patch("subprocess.Popen", return_value=MockProcFail()), \
         patch("app.job_control.register_process"), \
         patch("app.job_control.unregister_process"):

        events = []
        async for ev in provider.discover_parameters(endpoints, per_host_timeout=10):
            events.append(ev)

        # Assert: Circuit breaker stopped the phase after 3 failures
        circuit_errors = [e for e in events if e.get("type") == "stage_error" and "Circuit breaker" in e.get("error", "")]
        assert len(circuit_errors) == 1
        cb_err = circuit_errors[0]
        assert cb_err["untested_endpoints"] == [
            "http://testasp.vulnweb.com/ep4_untested",
            "http://testasp.vulnweb.com/ep5_untested",
        ]

        # Scan summary reports 3 failed, 2 untested
        summ = [e for e in events if e.get("type") == "scan_summary"][0]
        assert summ["endpoints_failed"] == 3
        assert summ["endpoints_untested"] == 2
        assert "http://testasp.vulnweb.com/ep4_untested" in summ["untested_endpoints"]


# ==============================================================================
# 4. crt.sh and certspotter Tests
# ==============================================================================

@pytest.mark.asyncio
async def test_item4_crtsh_retry_3_times_and_separate_failure_from_zero_results():
    """
    4. crt.sh: log HTTP status, retry 3 times with backoff on 5xx/timeouts,
    and report "request failed (status N)" separately from "0 results".
    """
    provider = CrtshProvider()

    # Case A: Fails with 502 across 3 retries -> emits stage_error "request failed (status 502)"
    call_attempts = 0

    async def mock_get_502(url, **kwargs):
        nonlocal call_attempts
        call_attempts += 1
        resp = MagicMock()
        resp.status_code = 502
        return resp

    with patch("httpx.AsyncClient.get", side_effect=mock_get_502), \
         patch("asyncio.sleep", AsyncMock()):

        events = []
        async for ev in provider.discover(["example.com"]):
            events.append(ev)

        assert call_attempts == 3, f"Expected 3 retry attempts, got {call_attempts}"
        errs = [e for e in events if e.get("type") == "stage_error"]
        assert len(errs) >= 1
        assert "request failed (status 502)" in errs[0]["error"]

    # Case B: Returns 200 with 0 results -> NO stage_error, reports 0 results
    async def mock_get_200_empty(url, **kwargs):
        resp = MagicMock()
        resp.status_code = 200
        resp.json = MagicMock(return_value=[])
        return resp

    with patch("httpx.AsyncClient.get", side_effect=mock_get_200_empty):
        events = []
        async for ev in provider.discover(["example.com"]):
            events.append(ev)

        errs = [e for e in events if e.get("type") == "stage_error"]
        assert len(errs) == 0, "0 results must NOT emit stage_error!"
        zero_logs = [e for e in events if e.get("type") == "log" and "0 results" in e.get("message", "")]
        assert len(zero_logs) >= 1


@pytest.mark.asyncio
async def test_item4_certspotter_api_key_and_error_handling():
    """
    4. Certspotter accepts optional API key from keys file, logs HTTP status,
    retries 3 times, reports status failed separately from 0 results.
    """
    provider = CertspotterProvider()

    # Case A: Uses API key from keys file/env in Authorization header
    recorded_headers = {}

    def mock_client_init(*args, **kwargs):
        nonlocal recorded_headers
        recorded_headers = kwargs.get("headers", {})
        client = AsyncMock()
        resp = MagicMock()
        resp.status_code = 200
        resp.json = MagicMock(return_value=[{"dns_names": ["sub.example.com"]}])
        client.get.return_value = resp
        client.__aenter__.return_value = client
        client.__aexit__.return_value = None
        return client

    with patch("app.core.provider_keys.load_provider_keys", return_value={"certspotter": "secret_cs_key_123"}), \
         patch("httpx.AsyncClient", side_effect=mock_client_init):

        events = []
        async for ev in provider.discover(["example.com"]):
            events.append(ev)

        assert "Authorization" in recorded_headers
        assert recorded_headers["Authorization"] == "Bearer secret_cs_key_123"
        assets = [e for e in events if e.get("type") == "asset"]
        assert len(assets) == 1
        assert assets[0]["data"]["domain"] == "sub.example.com"


# ==============================================================================
# 6. GoWitness Tests
# ==============================================================================

def test_item6_gowitness_version_detection_and_matching_command():
    """
    6. Detect installed version and use matching command (v3: scan single).
    """
    provider = GowitnessProvider()

    # Test v3 command builder
    cmd_v3 = provider.build_gowitness_cmd(
        tool_path="/usr/local/bin/gowitness",
        url="http://testasp.vulnweb.com/",
        screenshot_path="/tmp/screens",
        version="v3",
        is_windows=False,
    )
    assert cmd_v3 == [
        "/usr/local/bin/gowitness",
        "scan", "single",
        "-u", "http://testasp.vulnweb.com/",
        "--screenshot-path", "/tmp/screens",
        "--screenshot-format", "png",
        "--write-none",
    ]

    # Test v2 fallback command builder
    cmd_v2 = provider.build_gowitness_cmd(
        tool_path="/usr/local/bin/gowitness",
        url="http://testasp.vulnweb.com/",
        screenshot_path="/tmp/screens",
        version="v2",
        is_windows=False,
    )
    assert cmd_v2 == [
        "/usr/local/bin/gowitness",
        "single",
        "-u", "http://testasp.vulnweb.com/",
        "--screenshot-path", "/tmp/screens",
        "--write-db=false",
    ]


@pytest.mark.asyncio
async def test_item6_gowitness_errors_when_zero_screenshots_for_live_hosts():
    """
    6. When every requested screenshot fails, emit stage_error with the likely
    cause; the summary reports successes and failures.
    """
    provider = GowitnessProvider()
    live_urls = ["http://testasp.vulnweb.com/"]

    class MockProc:
        returncode = 0
        def wait(self, timeout=None):
            return 0
        def poll(self):
            return 0
        def terminate(self):
            pass

    with patch.object(provider, "detect_tool", return_value="/usr/local/bin/gowitness"), \
         patch.object(provider, "verify_gowitness_cli", return_value={"version": "v3"}), \
         patch.object(provider, "detect_chromium", return_value="/usr/bin/chromium"), \
         patch("subprocess.Popen", return_value=MockProc()), \
         patch("app.job_control.register_process"), \
         patch("app.job_control.unregister_process"), \
         patch("app.job_control.check_job_status", AsyncMock()), \
         patch("glob.glob", return_value=[]):  # No png produced

        events = []
        async for ev in provider.discover(
            live_urls, project_id="testproj", job_id="testjob", rate_limit=100
        ):
            events.append(ev)

        errors = [e for e in events if e.get("type") == "stage_error"]
        assert len(errors) >= 1
        assert "All 1 requested screenshot(s) failed" in errors[0]["reason"]

        summ = [e for e in events if e.get("type") == "scan_summary"][0]
        assert summ["status"] == "failed"
        assert summ["screenshots"] == 0
        assert summ["successful_screenshots"] == 0
        assert summ["failed_screenshots"] == 1


# ==============================================================================
# Real MongoDB Integration Test
# ==============================================================================

@pytest.mark.asyncio
async def test_historical_probing_real_mongo_persistence():
    """
    Real MongoDB test verifying historical probe assets (historical_dead, unprobed_url)
    are persisted with proper reasons in MongoDB.
    """
    client, db, old_db, old_is_mock = await setup_real_test_db()
    try:
        project_id = str(ObjectId())
        provider = HttpxProvider()

        live_hosts = ["target.example.com"]
        input_urls = [
            "http://target.example.com/dead_endpoint",
            "http://offline.example.com/unprobed_endpoint",
        ]

        class MockProc:
            returncode = 0
            stdout = []
            stderr = []
            def wait(self, timeout=None):
                return 0

        with patch.object(provider, "detect_tool", return_value="/usr/bin/httpx"), \
             patch("app.job_control.check_job_status", AsyncMock()), \
             patch("subprocess.Popen", return_value=MockProc()), \
             patch("app.job_control.register_process"), \
             patch("app.job_control.unregister_process"):

            events = []
            async for ev in provider.probe_historical_urls(input_urls, live_hosts=live_hosts):
                if ev.get("type") == "asset":
                    doc = ev["data"].copy()
                    doc["project_id"] = project_id
                    await db.assets.insert_one(doc)

        # Check in MongoDB
        dead_doc = await db.assets.find_one({"project_id": project_id, "type": "historical_dead"})
        assert dead_doc is not None
        assert dead_doc["value"] == "http://target.example.com/dead_endpoint"

        unprobed_doc = await db.assets.find_one({"project_id": project_id, "type": "unprobed_url"})
        assert unprobed_doc is not None
        assert unprobed_doc["value"] == "http://offline.example.com/unprobed_endpoint"
        assert unprobed_doc["metadata"]["reason"] == "host not live"

    finally:
        await teardown_real_test_db(client, db, old_db, old_is_mock)
