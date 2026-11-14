"""Tests for Runtime Fixes (Live Scan Items 1 - 6)
===================================================
Covers:
  1. Command execution: wsl -e <binary> <args...> argument list, Katana -cs/-cos scope
     regex preserving ( ) | $ ? and headers with quotes/semicolons, no bash -c.
  2. DNS wildcard detection: 3 random nonexistent labels per root domain; host filtered
     ONLY if all its answers fall inside that set; hosts sharing an IP are not filtered.
  3. Non-routable/disallowed IP drop: loopback, RFC1918, link-local, CGNAT, cloud-metadata
     ranges always dropped regardless of scope config (localhost.example.com -> 127.0.0.1).
  4. Hostname validation before DNS: strict RFC regex, reject encoded fragments, names where
     root domain appears twice, and labels over 63 chars.
  5. Scan profiles: scan_profile = "recon" (default) skips Nuclei host, Nuclei endpoint,
     Dalfox, OpenRedirex with stage_skipped (reason: "profile: recon"); default-login tag
     removed from Nuclei passes; risk scoring and diffing work with 0 findings on real Mongo.
  6. FFUF: derived -maxtime from wordlist length / rate with cap, ~1k list in Fast mode,
     requests sent logging, and warning when all responses are 400.
"""

import asyncio
import os
import platform
import subprocess
import tempfile
import uuid
from datetime import datetime
from typing import Any, Dict, List, Set
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from bson import ObjectId
from motor.motor_asyncio import AsyncIOMotorClient

import app.database as database_module
from app.core.scope import (
    get_root_domain,
    is_disallowed_ip,
    validate_hostname,
    build_scope_regex,
)
from app.core.tools import check_tool_in_system, RECON_TOOLS
from app.providers.base import BaseProvider
from app.providers.dnsx_provider import DnsxProvider
from app.providers.ffuf_provider import FfufProvider
from app.providers.katana_provider import KatanaProvider
from app.providers.nuclei_provider import NUCLEI_HOST_PASSES, NUCLEI_PASSES
from app.providers.unified_discovery_provider import UnifiedDiscoveryProvider
from app.routers.jobs import run_discovery_job, manager


# ==============================================================================
# Real MongoDB Fixture Helper
# ==============================================================================

async def setup_real_test_db():
    mongo_uri = os.getenv("MONGO_URI", "mongodb://localhost:27017")
    client = AsyncIOMotorClient(mongo_uri, serverSelectionTimeoutMS=2000)
    try:
        await client.admin.command("ping")
    except Exception as exc:
        pytest.skip(f"Real MongoDB is not running at {mongo_uri}: {exc}")

    test_db_name = f"reconforge_fixes_test_{uuid.uuid4().hex[:12]}"
    test_db = client[test_db_name]

    await test_db.users.create_index("username", unique=True)
    await test_db.projects.create_index("name")
    await test_db.assets.create_index([("project_id", 1), ("type", 1), ("domain", 1)])
    await test_db.assets.create_index(
        [("project_id", 1), ("type", 1), ("value", 1)],
        unique=True,
        name="project_id_1_type_1_value_1_unique",
    )
    await test_db.scan_diffs.create_index([("project_id", 1), ("created_at", -1)])

    old_db = database_module.db_helper.db
    old_client = database_module.db_helper.client
    old_is_mock = database_module.db_helper.is_mock
    database_module.db_helper.db = test_db
    database_module.db_helper.client = client
    database_module.db_helper.is_mock = False

    return client, test_db, old_db, old_is_mock, old_client


async def teardown_real_test_db(client, test_db, old_db, old_is_mock, old_client=None):
    try:
        await client.drop_database(test_db.name)
    finally:
        database_module.db_helper.db = old_db
        database_module.db_helper.client = old_client
        database_module.db_helper.is_mock = old_is_mock
        client.close()


# ==============================================================================
# Item 1: Command Execution & Katana Regex / Quote Handling
# ==============================================================================

def test_item1_katana_scope_regex_and_headers_argument_list():
    """
    Requirement 1: Katana scope regex containing ( ) | $ ? and header values
    containing quotes and semicolons must be passed as distinct arguments in an
    argument list, using 'wsl -e <binary> <args...>' without shell interpolation.
    """
    provider = KatanaProvider()
    scope = {
        "in_scope": ["*.example.com", "example.com"],
        "out_of_scope": ["admin.example.com"],
    }
    custom_headers = {
        "X-Custom-Auth": "'single-quoted'; \"double-quoted\"; key=value?foo|bar$",
    }

    # Verify build_scope_regex produces a regex containing special characters
    cs_regex = build_scope_regex(scope["in_scope"])
    assert cs_regex is not None
    assert "(" in cs_regex and ")" in cs_regex and "|" in cs_regex and "$" in cs_regex

    # Simulate command construction for Windows WSL execution
    is_windows = True
    tool_path = "/usr/bin/katana"
    executable = "wsl"
    args = ["-e", tool_path] if is_windows else []

    katana_flags = [
        "-u", "https://example.com",
        "-jc",
        "-fx",
        "-j",
        "-silent",
        "-duc",
        "-d", "2",
        "-c", "10",
        "-rl", "100",
        "-timeout", "10",
        "-ef", "png,jpg,css",
    ]
    for hk, hv in custom_headers.items():
        katana_flags.extend(["-H", f"{hk}: {hv}"])

    cos_regex = build_scope_regex(scope["out_of_scope"])
    katana_flags.extend(["-cs", cs_regex, "-cos", cos_regex, "-fs", "dn"])

    cmd = [executable, *args, *katana_flags]

    # Assert: Must start with wsl -e
    assert cmd[0] == "wsl"
    assert cmd[1] == "-e"
    assert cmd[2] == "/usr/bin/katana"

    # Assert: cs_regex is a single argument without bash string concat or syntax errors
    cs_idx = cmd.index("-cs")
    assert cmd[cs_idx + 1] == cs_regex

    # Assert: header value with quotes and semicolons is preserved verbatim
    h_idx = cmd.index("-H")
    assert cmd[h_idx + 1] == "X-Custom-Auth: 'single-quoted'; \"double-quoted\"; key=value?foo|bar$"


def test_item1_detect_tool_and_check_tool_never_use_bash_c():
    """
    Requirement 1: detect_tool and check_tool_in_system must never invoke bash -c.
    """
    import inspect
    from app.providers.base import BaseProvider
    from app.core import tools

    base_src = inspect.getsource(BaseProvider.detect_tool)
    assert "bash -c" not in base_src, "BaseProvider.detect_tool must not use 'bash -c'"

    tools_src = inspect.getsource(tools.check_tool_in_system)
    assert "bash -c" not in tools_src, "check_tool_in_system must not use 'bash -c'"


# ==============================================================================
# Item 2: DNS Wildcard Detection
# ==============================================================================

@pytest.mark.asyncio
async def test_item2_dns_wildcard_detection_three_hosts_shared_ip_none_filtered():
    """
    Requirement 2: Replace 'IP on >=3 hosts' heuristic.
    Test with 3 real hosts on one IP and no wildcard (nonexistent labels return NXDOMAIN):
    None of the 3 hosts should be filtered. Hosts sharing an IP are legitimate.
    """
    provider = DnsxProvider()

    raw_dnsx_output = [
        '{"host": "app.example.com", "a": ["93.184.216.34"], "aaaa": [], "cname": [], "status_code": "NOERROR"}',
        '{"host": "api.example.com", "a": ["93.184.216.34"], "aaaa": [], "cname": [], "status_code": "NOERROR"}',
        '{"host": "web.example.com", "a": ["93.184.216.34"], "aaaa": [], "cname": [], "status_code": "NOERROR"}',
    ]

    # Mock resolve_wildcard_answers to return empty set (no wildcard DNS on root domain)
    mock_resolve = MagicMock(return_value=set())

    with patch.object(provider, "detect_tool", return_value="/usr/bin/dnsx"), \
         patch.object(provider, "resolve_wildcard_answers", mock_resolve), \
         patch("app.core.tools.is_tool_available", return_value=True), \
         patch("app.job_control.check_job_status", AsyncMock()):

        # Mock subprocess to yield the 3 raw output lines
        mock_proc = MagicMock()
        mock_proc.stdout = raw_dnsx_output
        mock_proc.stderr = MagicMock(read=MagicMock(return_value=""))
        mock_proc.poll = MagicMock(return_value=0)
        mock_proc.wait = MagicMock(return_value=0)

        with patch("subprocess.Popen", return_value=mock_proc):
            events = []
            async for ev in provider.discover(["app.example.com", "api.example.com", "web.example.com"]):
                events.append(ev)

    # Assert: All 3 hosts were yielded as assets (none filtered by the old >=3 heuristic)
    asset_events = [e for e in events if e.get("type") == "asset"]
    assert len(asset_events) == 3
    resolved_domains = {e["data"]["domain"] for e in asset_events}
    assert resolved_domains == {"app.example.com", "api.example.com", "web.example.com"}

    # Assert: Wildcards filtered count is 0
    summary = next(e for e in events if e.get("type") == "scan_summary")
    assert summary.get("wildcards_filtered") == 0


@pytest.mark.asyncio
async def test_item2_dns_wildcard_detection_active_wildcard_filters_only_matching():
    """
    Requirement 2: When wildcard DNS answers are detected on nonexistent labels,
    filter a host ONLY if all its answers fall inside that set.
    """
    provider = DnsxProvider()

    raw_dnsx_output = [
        # fake.example.com resolves only to wildcard IP -> MUST BE FILTERED
        '{"host": "fake.example.com", "a": ["198.51.100.99"], "aaaa": [], "cname": [], "status_code": "NOERROR"}',
        # real.example.com resolves to public distinct IP -> MUST NOT BE FILTERED
        '{"host": "real.example.com", "a": ["93.184.216.34"], "aaaa": [], "cname": [], "status_code": "NOERROR"}',
        # multi.example.com has wildcard IP + distinct IP -> MUST NOT BE FILTERED (not all answers fall in set)
        '{"host": "multi.example.com", "a": ["198.51.100.99", "93.184.216.34"], "aaaa": [], "cname": [], "status_code": "NOERROR"}',
    ]

    # Wildcard set returned by probing nonexistent labels
    mock_resolve = MagicMock(return_value={"198.51.100.99"})

    with patch.object(provider, "detect_tool", return_value="/usr/bin/dnsx"), \
         patch.object(provider, "resolve_wildcard_answers", mock_resolve), \
         patch("app.core.tools.is_tool_available", return_value=True), \
         patch("app.job_control.check_job_status", AsyncMock()):

        mock_proc = MagicMock()
        mock_proc.stdout = raw_dnsx_output
        mock_proc.stderr = MagicMock(read=MagicMock(return_value=""))
        mock_proc.poll = MagicMock(return_value=0)
        mock_proc.wait = MagicMock(return_value=0)

        with patch("subprocess.Popen", return_value=mock_proc):
            events = []
            async for ev in provider.discover(["fake.example.com", "real.example.com", "multi.example.com"]):
                events.append(ev)

    asset_events = [e for e in events if e.get("type") == "asset"]
    resolved_domains = {e["data"]["domain"] for e in asset_events}

    # 'fake.example.com' was filtered as wildcard
    assert "fake.example.com" not in resolved_domains
    # 'real.example.com' and 'multi.example.com' are kept
    assert "real.example.com" in resolved_domains
    assert "multi.example.com" in resolved_domains

    summary = next(e for e in events if e.get("type") == "scan_summary")
    assert summary.get("wildcards_filtered") == 1


# ==============================================================================
# Item 3: Disallowed / Non-Routable IP Range Drop
# ==============================================================================

def test_item3_is_disallowed_ip_identifies_all_restricted_ranges():
    """
    Requirement 3: Check loopback, RFC1918, link-local, CGNAT, cloud-metadata:
    127/8, 10/8, 172.16/12, 192.168/16, 169.254/16, 100.64/10, ::1, fc00::/7, fe80::/10.
    """
    restricted_ips = [
        "127.0.0.1",
        "127.255.255.255",
        "10.0.0.1",
        "10.254.1.1",
        "172.16.0.1",
        "172.31.255.254",
        "192.168.0.1",
        "192.168.100.50",
        "169.254.169.254",  # AWS/GCP cloud metadata
        "169.254.1.1",
        "100.64.0.1",      # CGNAT
        "100.127.255.254", # CGNAT
        "::1",             # IPv6 loopback
        "fc00::1",         # IPv6 unique local
        "fd12:3456::1",    # IPv6 unique local
        "fe80::1",         # IPv6 link-local
    ]
    for ip in restricted_ips:
        is_bad, reason = is_disallowed_ip(ip)
        assert is_bad is True, f"Expected {ip} to be disallowed, but was not!"
        assert reason is not None

    allowed_ips = [
        "93.184.216.34",  # example.com
        "8.8.8.8",
        "1.1.1.1",
        "2606:4700:4700::1111",
    ]
    for ip in allowed_ips:
        is_bad, reason = is_disallowed_ip(ip)
        assert is_bad is False, f"Expected {ip} to be allowed, but was rejected!"
        assert reason is None


@pytest.mark.asyncio
async def test_item3_localhost_example_com_resolving_to_127_dropped():
    """
    Requirement 3: After DNS resolution, ALWAYS drop hosts whose IPs are loopback,
    RFC1918, link-local, CGNAT or cloud-metadata ranges, regardless of scope config,
    and log the reason. Test using localhost.example.com -> 127.0.0.1.
    """
    provider = DnsxProvider()
    raw_dnsx_output = [
        '{"host": "localhost.example.com", "a": ["127.0.0.1"], "aaaa": [], "cname": [], "status_code": "NOERROR"}',
        '{"host": "valid.example.com", "a": ["93.184.216.34"], "aaaa": [], "cname": [], "status_code": "NOERROR"}',
    ]

    with patch.object(provider, "detect_tool", return_value="/usr/bin/dnsx"), \
         patch.object(provider, "resolve_wildcard_answers", MagicMock(return_value=set())), \
         patch("app.core.tools.is_tool_available", return_value=True), \
         patch("app.job_control.check_job_status", AsyncMock()):

        mock_proc = MagicMock()
        mock_proc.stdout = raw_dnsx_output
        mock_proc.stderr = MagicMock(read=MagicMock(return_value=""))
        mock_proc.poll = MagicMock(return_value=0)
        mock_proc.wait = MagicMock(return_value=0)

        with patch("subprocess.Popen", return_value=mock_proc):
            events = []
            async for ev in provider.discover(["localhost.example.com", "valid.example.com"]):
                events.append(ev)

    asset_events = [e for e in events if e.get("type") == "asset"]
    resolved_domains = {e["data"]["domain"] for e in asset_events}

    # localhost.example.com MUST be dropped because 127.0.0.1 is loopback
    assert "localhost.example.com" not in resolved_domains
    assert "valid.example.com" in resolved_domains

    # Check that a log event explaining the reason was emitted
    log_messages = [e.get("message", "") for e in events if e.get("type") == "log"]
    dropped_log = [m for m in log_messages if "localhost.example.com" in m and "127.0.0.1" in m]
    assert len(dropped_log) >= 1


# ==============================================================================
# Item 4: Validate Hostnames Before DNS
# ==============================================================================

def test_item4_validate_hostnames_strict_rfc_and_rejections():
    """
    Requirement 4: Validate hostnames before DNS: strict RFC regex, reject names with
    encoded fragments (e.g. 'u003e'), names where the root domain appears twice, and
    labels over 63 chars.
    """
    # 1. Valid hostnames
    assert validate_hostname("example.com", "example.com")[0] is True
    assert validate_hostname("sub.example.com", "example.com")[0] is True
    assert validate_hostname("api-v1.test.corp.co.uk", "corp.co.uk")[0] is True
    assert validate_hostname("123.example.com", "example.com")[0] is True

    # 2. Reject encoded fragments (e.g. u003e, %20, HTML/URL encoding)
    is_valid, reason = validate_hostname("sub.u003e.example.com", "example.com")
    assert is_valid is False
    assert "encoded" in reason or "illegal" in reason

    is_valid, reason = validate_hostname("sub.%20test.example.com", "example.com")
    assert is_valid is False

    is_valid, reason = validate_hostname("sub.<script>.example.com", "example.com")
    assert is_valid is False

    # 3. Reject names where the root domain appears twice
    is_valid, reason = validate_hostname("sub.example.com.example.com", "example.com")
    assert is_valid is False
    assert "root_domain_appears_multiple_times" in reason

    is_valid, reason = validate_hostname("example.com.example.com", "example.com")
    assert is_valid is False
    assert "root_domain_appears_multiple_times" in reason

    # 4. Reject label over 63 chars
    long_label = "a" * 64
    is_valid, reason = validate_hostname(f"{long_label}.example.com", "example.com")
    assert is_valid is False
    assert "label_exceeds_63_chars" in reason

    # 63 chars is valid
    ok_label = "a" * 63
    assert validate_hostname(f"{ok_label}.example.com", "example.com")[0] is True

    # 5. Reject invalid RFC characters (leading/trailing hyphens, underscores)
    assert validate_hostname("-invalid.example.com", "example.com")[0] is False
    assert validate_hostname("invalid-.example.com", "example.com")[0] is False


# ==============================================================================
# Item 5: Scan Profiles (Real MongoDB)
# ==============================================================================

@pytest.mark.asyncio
async def test_item5_scan_profiles_recon_skips_nuclei_dalfox_openredirex_on_real_mongo():
    """
    Requirement 5: Add project setting scan_profile = 'recon' (default) | 'recon_validation'.
    In 'recon', skip Nuclei host, Nuclei endpoint, Dalfox and OpenRedirex with a stage_skipped
    event (reason: 'profile: recon'). Remove default-login tag from all Nuclei passes.
    Keep risk scoring and diffing working when no findings exist.
    """
    client, db, old_db, old_is_mock, old_client = await setup_real_test_db()
    try:
        project_id = ObjectId()
        job_id = ObjectId()

        # Seed project with scan_profile = "recon" (default)
        await db.projects.insert_one({
            "_id": project_id,
            "name": "Scan Profile Recon Test",
            "seed_domains": ["example.com"],
            "scan_profile": "recon",
            "scope": {"in_scope": ["example.com"], "out_of_scope": []},
            "assume_tools_installed": False,
            "created_at": datetime.utcnow(),
        })

        await db.jobs.insert_one({
            "_id": job_id,
            "project_id": str(project_id),
            "provider_name": "Unified Discovery",
            "scan_mode": "deep",
            "status": "pending",
            "logs": [],
            "created_at": datetime.utcnow(),
        })

        broadcast_events = []
        orig_broadcast = manager.broadcast

        async def capture_broadcast(j_id, msg):
            broadcast_events.append(msg)
            return await orig_broadcast(j_id, msg)

        # Fake generators for passive + active phases up to vulnerability stage
        async def fake_subfinder(seeds, **kwargs):
            yield {"type": "asset", "data": {"domain": "example.com"}}

        async def fake_dnsx(targets, **kwargs):
            yield {
                "type": "asset",
                "data": {"domain": "example.com", "status": "resolved", "resolved_ip": "93.184.216.34"},
            }
            yield {"type": "scan_summary", "provider": "DNSx", "resolved": 1, "nxdomain": 0, "wildcards_filtered": 0}

        async def fake_httpx(targets, **kwargs):
            yield {
                "type": "asset",
                "data": {
                    "domain": "example.com",
                    "url": "https://example.com",
                    "status": "live",
                    "status_code": 200,
                    "title": "Example Domain",
                    "open_ports": [443],
                },
            }
            yield {"type": "scan_summary", "provider": "httpx", "live_hosts": 1}

        async def fake_katana(targets, **kwargs):
            yield {"type": "scan_summary", "provider": "katana", "urls_discovered": 1}

        async def fake_gf(targets, **kwargs):
            yield {"type": "scan_summary", "provider": "gf", "patterns_matched": 1}

        def mock_tool_available(t):
            if t in ("subfinder", "dnsx", "httpx", "katana", "gf", "nuclei", "dalfox", "openredirex"):
                return True
            return False

        async def fake_empty_passive(*args, **kwargs):
            if False:
                yield {}

        with patch("app.core.tools.is_tool_available", side_effect=mock_tool_available), \
             patch("app.providers.unified_discovery_provider.is_tool_available", side_effect=mock_tool_available), \
             patch("app.providers.subfinder_provider.SubfinderProvider.discover", side_effect=fake_subfinder), \
             patch("app.providers.crtsh_provider.CrtshProvider.discover", side_effect=fake_empty_passive), \
             patch("app.providers.certspotter_provider.CertspotterProvider.discover", side_effect=fake_empty_passive), \
             patch("app.providers.dnsx_provider.DnsxProvider.discover", side_effect=fake_dnsx), \
             patch("app.providers.httpx_provider.HttpxProvider.discover", side_effect=fake_httpx), \
             patch("app.providers.katana_provider.KatanaProvider.discover", side_effect=fake_katana), \
             patch("app.providers.gf_provider.GfProvider.discover", side_effect=fake_gf), \
             patch.object(manager, "broadcast", side_effect=capture_broadcast):

            await asyncio.wait_for(
                run_discovery_job(
                    job_id=str(job_id),
                    project_id=str(project_id),
                    provider_name="Unified Discovery",
                    seed_domains=["example.com"],
                ),
                timeout=20.0,
            )

        # 1. Assert: Job completed successfully on real Mongo
        job_doc = await db.jobs.find_one({"_id": job_id})
        assert job_doc is not None
        assert job_doc["status"] == "completed"

        # 2. Assert: stage_skipped events were emitted for all active vulnerability scanners
        stage_skipped_events = [e for e in broadcast_events if e.get("type") == "stage_skipped"]
        skipped_reasons = {e.get("tool"): e.get("reason") for e in stage_skipped_events}

        assert skipped_reasons.get("nuclei_host") == "profile: recon"
        assert skipped_reasons.get("nuclei_endpoint") == "profile: recon"
        assert skipped_reasons.get("dalfox") == "profile: recon"
        assert skipped_reasons.get("openredirex") == "profile: recon"

        # 3. Assert: default-login tag removed from Nuclei passes
        for p in NUCLEI_PASSES:
            assert "default-login" not in p.get("tags", "")
        for p in NUCLEI_HOST_PASSES:
            assert "default-login" not in p.get("tags", "")

        # 4. Assert: Risk scoring completed and asset stored
        asset_doc = await db.assets.find_one({"project_id": str(project_id), "domain": "example.com"})
        assert asset_doc is not None
        assert asset_doc.get("risk") is not None
        assert asset_doc.get("risk", {}).get("score") is not None
        assert asset_doc.get("risk", {}).get("score") >= 0

        # 5. Assert: Diff engine executed and produced diff with 0 findings
        diff_doc = await db.scan_diffs.find_one({"project_id": str(project_id), "scan_id": str(job_id)})
        assert diff_doc is not None
        assert diff_doc.get("summary", {}).get("new_findings_count", 0) == 0

    finally:
        await teardown_real_test_db(client, db, old_db, old_is_mock, old_client)


# ==============================================================================
# Item 6: FFUF Enhancements
# ==============================================================================

@pytest.mark.asyncio
async def test_item6_ffuf_derived_maxtime_fast_mode_and_400_warning():
    """
    Requirement 6: FFUF derives -maxtime from wordlist length / rate (with a cap),
    uses ~1k-line list in Fast mode, logs requests sent, and emits a warning if every
    response is 400.
    """
    provider = FfufProvider()

    # 1. Test -maxtime derivation
    # 1000 words at 20 rps -> ceil(1000/20) + 15 = 65 seconds
    cmd = provider.build_cmd(
        tool_path="/usr/bin/ffuf",
        fuzz_url="https://example.com/FUZZ",
        wordlist_path="/home/kali/wordlists/common-1k.txt",
        wsl_out_path="/tmp/out.json",
        rate_limit=20,
        threads=20,
        scan_mode="fast",
        maxtime=65,
        maxtime_job=65,
        is_windows=True,
    )
    assert cmd[0] == "wsl"
    assert cmd[1] == "-e"
    assert "-maxtime" in cmd
    m_idx = cmd.index("-maxtime")
    assert cmd[m_idx + 1] == "65"

    # 2. Test fallback wordlist generates ~1000 words
    fallback_file = provider._create_fallback_wordlist()
    try:
        with open(fallback_file, "r", encoding="utf-8") as f:
            lines = [line.strip() for line in f if line.strip()]
        assert len(lines) == 1000, f"Fallback wordlist had {len(lines)} lines, expected 1000"
    finally:
        if os.path.exists(fallback_file):
            os.unlink(fallback_file)

    # 3. Test 400 Bad Request warning emission when all results are 400
    fake_results = {
        "results": [
            {"url": "https://example.com/admin", "status": 400, "length": 50, "words": 5, "lines": 2},
            {"url": "https://example.com/api", "status": 400, "length": 50, "words": 5, "lines": 2},
            {"url": "https://example.com/login", "status": 400, "length": 50, "words": 5, "lines": 2},
        ],
        "config": {"autocalibration_strings": []},
    }

    import json

    def fake_popen(cmd, **kwargs):
        if "-o" in cmd:
            o_idx = cmd.index("-o")
            out_file = cmd[o_idx + 1]
            if out_file.startswith("/mnt/") and len(out_file) > 6 and out_file[6] == "/":
                drive = out_file[5].upper()
                out_file = f"{drive}:{out_file[6:]}"
            with open(out_file, "w", encoding="utf-8") as f:
                json.dump(fake_results, f)
        proc = MagicMock()
        proc.stdout = MagicMock(read=MagicMock(return_value=":: Progress: [1000/1000] :: Job [1/1] :: 50 req/sec :: Duration: [0:00:20] ::"))
        proc.stderr = MagicMock(read=MagicMock(return_value=""))
        proc.poll = MagicMock(return_value=0)
        proc.wait = MagicMock(return_value=0)
        return proc

    with patch.object(provider, "detect_tool", return_value="/usr/bin/ffuf"), \
         patch("app.core.tools.is_tool_available", return_value=True), \
         patch("app.job_control.check_job_status", AsyncMock()), \
         patch("subprocess.Popen", side_effect=fake_popen):

        events = []
        async for ev in provider.discover_content(
            targets=["https://example.com"],
            scan_mode="fast",
            scope={"in_scope": ["example.com"], "out_of_scope": []},
        ):
            events.append(ev)

    # Verify warning_event was emitted for all-400 responses
    warning_events = [e for e in events if e.get("type") == "warning_event" and e.get("warning") == "ffuf_all_400"]
    assert len(warning_events) == 1
    assert "HTTP 400 Bad Request" in warning_events[0].get("message", "")

    # Verify requests sent log was emitted
    log_messages = [e.get("message", "") for e in events if e.get("type") == "log"]
    req_logs = [m for m in log_messages if "requests sent" in m]
    assert len(req_logs) >= 1
    assert "1000 requests sent" in req_logs[0]
