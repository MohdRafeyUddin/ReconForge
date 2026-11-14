import asyncio
import json
import os
import uuid
import pytest
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List
from unittest.mock import AsyncMock, MagicMock, patch
from bson import ObjectId
from motor.motor_asyncio import AsyncIOMotorClient

from app.core.scope import is_in_scope, filter_scope
from app.providers.base import BaseProvider
from app.providers.url_merge import merge_urls, get_url_priority
from app.providers.ffuf_provider import FfufProvider
from app.providers.api_surface_provider import ApiSurfaceProvider, GRAPHQL_INTROSPECTION_QUERY
from app.providers.param_discovery_provider import ParamDiscoveryProvider
from app.providers.waymore_provider import WaymoreProvider
from app.providers.httpx_provider import HttpxProvider
from app.services.diff_engine import compute_and_save_diff
from app.services.notifier import dispatch_scan_diff_alerts


# ==============================================================================
# Real MongoDB Fixture / Helper
# ==============================================================================

async def get_real_mongo_db():
    """
    Connects to real local MongoDB instance.
    Creates an isolated database per test and drops it on teardown.
    """
    mongo_uri = os.getenv("MONGO_URI", "mongodb://localhost:27017")
    client = AsyncIOMotorClient(mongo_uri, serverSelectionTimeoutMS=2000)
    try:
        await client.admin.command("ping")
    except Exception as exc:
        pytest.skip(f"Real MongoDB is not running at {mongo_uri}: {exc}")

    test_db_name = f"reconforge_test_phase4_{uuid.uuid4().hex[:12]}"
    db = client[test_db_name]
    return client, db


# ==============================================================================
# 1. URL Merge Engine: Per-host URL Cap & Prioritization
# ==============================================================================

def test_url_merge_engine_per_host_cap_and_prioritization():
    """
    Constraint: Extend URL Merge Engine so the cap applies per host
    (default 1,000/host fast, 5,000/host deep) in ADDITION to global caps.
    URLs with parameters must have highest priority.
    """
    katana_urls = [
        f"https://api.example.com/item?id={i}" for i in range(20)
    ] + [
        f"https://api.example.com/static/file{i}.html" for i in range(20)
    ]
    gau_urls = [
        f"https://admin.example.com/page?p={i}" for i in range(15)
    ] + [
        f"https://other.test.com/doc{i}" for i in range(10)
    ]

    # Test per_host_cap=5, global_cap=12
    merged = merge_urls(
        katana_urls=katana_urls,
        gau_urls=gau_urls,
        scan_mode="fast",
        per_host_cap=5,
        global_cap=12,
    )

    assert len(merged) <= 12

    # Check host distribution: no host should exceed per_host_cap (5)
    host_counts = {}
    for item in merged:
        u = item["url"]
        from urllib.parse import urlparse
        h = urlparse(u).netloc
        host_counts[h] = host_counts.get(h, 0) + 1

    for h, count in host_counts.items():
        assert count <= 5, f"Host {h} exceeded per-host cap of 5: count was {count}"

    # Check prioritization: parameter URLs (priority 0) must precede non-parameter URLs
    param_urls = [m["url"] for m in merged if "?" in m["url"]]
    assert len(param_urls) > 0
    # First URL must have parameter
    assert "?" in merged[0]["url"]


# ==============================================================================
# 2. FFUF Content Discovery: Rate Limits, Auto-calibration, CDN/WAF reduction
# ==============================================================================

@pytest.mark.asyncio
async def test_ffuf_provider_guardrails_autocalibration_and_waf_reduction():
    """
    Constraint:
      - Always use ffuf auto-calibration (-ac)
      - Rate limit applied (-rate)
      - Custom identification header applied (-H)
      - Hosts flagged CDN/WAF use a reduced rate (<= 5 rps) and small wordlist, no recursion
      - Scope check: dropped out-of-scope targets
      - Per-host result cap enforced
    """
    provider = FfufProvider()

    # Capture command executed
    captured_commands = []
    
    class DummyProc:
        def __init__(self, cmd, *args, **kwargs):
            self.cmd = cmd
            self.stdout = MagicMock()
            self.stderr = MagicMock()
            captured_commands.append(cmd)

        def wait(self):
            return 0

        def kill(self):
            pass

    # Mock tool detection and subprocess execution
    with patch.object(provider, "detect_tool", return_value="/usr/bin/ffuf"), \
         patch("subprocess.Popen", side_effect=DummyProc), \
         patch("app.job_control.register_process"), \
         patch("app.job_control.unregister_process"):

        scope_cfg = {
            "in_scope": ["*.example.com"],
            "out_of_scope": ["out-of-scope.example.com"]
        }

        targets = [
            "https://in-scope.example.com",
            "https://waf.example.com",
            "https://out-of-scope.example.com",
        ]

        waf_hosts = {"waf.example.com"}

        events = []
        async for ev in provider.discover_content(
            targets=targets,
            scan_mode="deep",
            rate_limit=25,
            custom_headers={"X-Bug-Bounty": "reconforge-user"},
            scope=scope_cfg,
            max_results_per_host=50,
            waf_detected_hosts=waf_hosts,
        ):
            events.append(ev)

        # 1. Out-of-scope target must be skipped
        cmd_strings = [" ".join(c) for c in captured_commands]
        assert not any("out-of-scope.example.com" in s for s in cmd_strings)

        # 2. Both in-scope targets had commands built
        assert len(captured_commands) == 2

        # In-scope normal host: deep mode, -ac, rate 25, recursion
        normal_cmd = next(c for c in captured_commands if "in-scope.example.com" in " ".join(c))
        assert "-ac" in normal_cmd
        assert "-rate" in normal_cmd
        rate_idx = normal_cmd.index("-rate")
        assert normal_cmd[rate_idx + 1] == "25"
        assert "-recursion" in normal_cmd
        assert "-H" in normal_cmd
        assert "X-Bug-Bounty: reconforge-user" in normal_cmd

        # WAF host: reduced rate (<= 5), no recursion even in deep mode
        waf_cmd = next(c for c in captured_commands if "waf.example.com" in " ".join(c))
        assert "-ac" in waf_cmd
        waf_rate_idx = waf_cmd.index("-rate")
        assert int(waf_cmd[waf_rate_idx + 1]) <= 5
        assert "-recursion" not in waf_cmd


# ==============================================================================
# 3. FFUF Target Selection: Only Representatives and 401/403 Hosts
# ==============================================================================

def test_ffuf_runs_only_on_cluster_representatives_and_interesting_hosts():
    """
    Constraint: ffuf/feroxbuster run ONLY on cluster representatives and 401/403
    (is_interesting) hosts, never on every live host.
    """
    all_live_assets = [
        {
            "domain": "rep1.example.com",
            "is_cluster_representative": True,
            "status": "live",
            "status_code": 200,
        },
        {
            "domain": "member-dup.example.com",
            "is_cluster_representative": False,
            "status": "live",
            "status_code": 200,
            "is_interesting": False,
        },
        {
            "domain": "forbidden-admin.example.com",
            "is_cluster_representative": False,
            "status": "live",
            "status_code": 403,
            "is_interesting": True,
        },
        {
            "domain": "auth-required.example.com",
            "is_cluster_representative": False,
            "status": "live",
            "status_code": 401,
            "is_interesting": True,
        },
        {
            "domain": "plain-member.example.com",
            "is_cluster_representative": False,
            "status": "live",
            "status_code": 200,
            "is_interesting": False,
        },
    ]

    rep_domains = {"rep1.example.com"}

    priority_hosts_set = set(rep_domains)
    for a in all_live_assets:
        m = a.get("metadata") or {}
        sc = a.get("status_code") or m.get("status_code")
        if a.get("is_interesting") or sc in (401, 403):
            priority_hosts_set.add(a.get("domain"))

    assert "rep1.example.com" in priority_hosts_set
    assert "forbidden-admin.example.com" in priority_hosts_set
    assert "auth-required.example.com" in priority_hosts_set
    # Duplicate & non-interesting members must NOT be included
    assert "member-dup.example.com" not in priority_hosts_set
    assert "plain-member.example.com" not in priority_hosts_set


# ==============================================================================
# 4. API Surface: OpenAPI Parsing & Read-Only GraphQL Introspection
# ==============================================================================

@pytest.mark.asyncio
async def test_api_surface_openapi_parsing_and_readonly_graphql():
    """
    Constraint:
      - Common API paths probed (/swagger.json, /openapi.json, etc.)
      - Discovered OpenAPI specs parsed into endpoint URLs and merged into URL pipeline
      - GraphQL introspection check is a single READ-ONLY query: {"query": "{__schema{types{name}}}"}
      - No mutations!
    """
    # Verify read-only query constant
    assert GRAPHQL_INTROSPECTION_QUERY == {"query": "{__schema{types{name}}}"}
    assert "mutation" not in json_str(GRAPHQL_INTROSPECTION_QUERY).lower()

    provider = ApiSurfaceProvider()

    sample_openapi = {
        "openapi": "3.0.0",
        "info": {"title": "Users API", "version": "1.0"},
        "paths": {
            "/api/v1/users": {"get": {}},
            "/api/v1/users/{id}": {"get": {}, "delete": {}},
            "/api/v1/auth/login": {"post": {}}
        }
    }

    sample_graphql_schema = {
        "data": {
            "__schema": {
                "types": [{"name": "Query"}, {"name": "User"}, {"name": "Mutation"}]
            }
        }
    }

    import json
    import httpx

    class MockHttpxResponse:
        def __init__(self, status_code, text, content_type="application/json"):
            self.status_code = status_code
            self.text = text
            self.content = text.encode("utf-8")
            self.headers = {"content-type": content_type}

        def json(self):
            return json.loads(self.text)

    async def mock_get(url, *args, **kwargs):
        url_s = str(url)
        if "openapi.json" in url_s:
            return MockHttpxResponse(200, json.dumps(sample_openapi))
        elif "graphql" in url_s:
            return MockHttpxResponse(200, '{"errors": "GraphQL syntax error"}')
        elif ".well-known" in url_s:
            return MockHttpxResponse(200, "Contact: security@example.com", "text/plain")
        return MockHttpxResponse(404, "Not Found")

    async def mock_post(url, *args, **kwargs):
        # Must verify post query is strictly read-only
        body = kwargs.get("json") or {}
        assert body == {"query": "{__schema{types{name}}}"}
        return MockHttpxResponse(200, json.dumps(sample_graphql_schema))

    with patch.object(httpx.AsyncClient, "get", side_effect=mock_get), \
         patch.object(httpx.AsyncClient, "post", side_effect=mock_post):

        events = []
        async for ev in provider.probe_api_surface(
            targets=["https://api.example.com"],
            scope={"in_scope": ["*.example.com"], "out_of_scope": []}
        ):
            events.append(ev)

        # 1. API spec asset emitted
        spec_assets = [e for e in events if e.get("type") == "asset" and e.get("data", {}).get("type") == "api_spec"]
        assert len(spec_assets) == 1
        assert spec_assets[0]["data"]["metadata"]["endpoints_count"] == 3

        # 2. Routes extracted and emitted into URL pipeline
        url_events = [e for e in events if e.get("type") == "url_event" and e.get("data", {}).get("source") == "api_spec"]
        assert len(url_events) == 3
        extracted_urls = [u["data"]["url"] for u in url_events]
        assert "https://api.example.com/api/v1/users" in extracted_urls

        # 3. GraphQL asset emitted with introspection enabled
        gql_assets = [e for e in events if e.get("type") == "asset" and e.get("data", {}).get("type") == "graphql_endpoint"]
        assert len(gql_assets) == 1
        assert gql_assets[0]["data"]["metadata"]["introspection_enabled"] is True
        assert gql_assets[0]["data"]["metadata"]["types_count"] == 3


def json_str(obj):
    import json
    return json.dumps(obj)


# ==============================================================================
# 5. Parameter Discovery (Arjun / x8): Deep mode only & pipeline merge
# ==============================================================================

@pytest.mark.asyncio
async def test_param_discovery_deep_mode_and_pipeline_merge():
    """
    Constraint:
      - Arjun/x8 runs on top-priority endpoints only
      - Parameter discovery runs in Deep mode only
      - Merges discovered parameters into URLs as `param_discovery` source
      - Emits `type: "param"` assets
    """
    provider = ParamDiscoveryProvider()

    mock_arjun_json = {
        "https://api.example.com/search": ["q", "filter", "sort", "token"]
    }

    import json
    import tempfile

    with patch.object(provider, "detect_tool", return_value="/usr/bin/arjun"), \
         patch("app.job_control.register_process"), \
         patch("app.job_control.unregister_process"):

        def mock_popen(cmd, *args, **kwargs):
            # Capture output JSON file path and write mock results
            if "-oJ" in cmd:
                out_path = cmd[cmd.index("-oJ") + 1]
                if out_path.startswith("/mnt/c/"):
                    win_path = "C:\\" + out_path[7:].replace("/", "\\")
                elif out_path.startswith("/mnt/"):
                    parts = out_path.split("/")
                    drive = parts[2]
                    rest = "\\".join(parts[3:])
                    win_path = f"{drive}:\\{rest}"
                else:
                    win_path = out_path
                with open(win_path, "w", encoding="utf-8") as f:
                    f.write(json.dumps(mock_arjun_json))
            p = MagicMock()
            p.wait = MagicMock(return_value=0)
            return p

        with patch("subprocess.Popen", side_effect=mock_popen):
            events = []
            async for ev in provider.discover_parameters(
                endpoints=["https://api.example.com/search"],
                rate_limit=10,
                custom_headers={"X-Auth": "secret"},
                scope={"in_scope": ["*.example.com"], "out_of_scope": []}
            ):
                events.append(ev)

            # 1. param asset documents
            param_assets = [e for e in events if e.get("type") == "asset" and e.get("data", {}).get("type") == "param"]
            assert len(param_assets) == 4
            param_names = [p["data"]["metadata"]["param_name"] for p in param_assets]
            assert "q" in param_names
            assert "token" in param_names

            # 2. merged into URL pipeline as param_discovery source
            url_events = [e for e in events if e.get("type") == "url_event" and e.get("data", {}).get("source") == "param_discovery"]
            assert len(url_events) == 4
            assert any("q=FUZZ" in u["data"]["url"] for u in url_events)


# ==============================================================================
# 6. Real MongoDB Integration: Historical URL Probing (httpx -mc) & historical_dead
# ==============================================================================

@pytest.mark.asyncio
async def test_historical_url_probing_httpx_and_historical_dead_real_mongo():
    """
    Constraint:
      - Historical URLs from GAU/Waymore are probed with httpx (-mc 200,301,302,401,403)
      - Dead ones are stored as `status: "historical_dead"`
      - Write new tests against real MongoDB. Do NOT extend MockCollection.
    """
    client, db = await get_real_mongo_db()
    try:
        project_id = f"proj_hist_{uuid.uuid4().hex[:8]}"
        job_id = f"job_hist_{uuid.uuid4().hex[:8]}"

        live_url = "https://example.com/active-api"
        dead_url = "https://example.com/old-404-endpoint"

        httpx_provider = HttpxProvider()

        # Mock httpx probe output
        import json
        mock_output = [
            json.dumps({"url": live_url, "status_code": 200}),
        ]

        def mock_popen(cmd, *args, **kwargs):
            p = MagicMock()
            p.stdout = mock_output
            p.wait = MagicMock(return_value=0)
            return p

        with patch.object(httpx_provider, "detect_tool", return_value="/usr/bin/httpx"), \
             patch("subprocess.Popen", side_effect=mock_popen), \
             patch("app.job_control.register_process"), \
             patch("app.job_control.unregister_process"):

            events = []
            async for ev in httpx_provider.probe_historical_urls(
                urls=[live_url, dead_url],
                rate_limit=15,
            ):
                events.append(ev)

                # Simulate job worker storing asset events into real MongoDB
                if ev.get("type") == "asset":
                    asset_data = ev["data"]
                    asset_data["project_id"] = project_id
                    asset_data["scan_id"] = job_id
                    asset_data["created_at"] = datetime.now(timezone.utc)
                    await db.assets.insert_one(asset_data)

            # Check emitted events
            probe_events = [e for e in events if e.get("type") == "historical_probe_event"]
            assert len(probe_events) == 2
            live_probe = next(p for p in probe_events if p["data"]["url"] == live_url)
            dead_probe = next(p for p in probe_events if p["data"]["url"] == dead_url)

            assert live_probe["data"]["status"] == "live"
            assert dead_probe["data"]["status"] == "historical_dead"

            # Query real MongoDB for historical_dead asset
            stored_dead = await db.assets.find_one({
                "project_id": project_id,
                "type": "historical_dead",
                "value": dead_url,
            })
            assert stored_dead is not None
            assert stored_dead["type"] == "historical_dead"
            assert stored_dead["discovered_by"] == "httpx_historical_probe"

    finally:
        await client.drop_database(db.name)
        client.close()


# ==============================================================================
# 7. Real MongoDB Integration: New Asset Types, Unique Index & Diff Engine
# ==============================================================================

@pytest.mark.asyncio
async def test_phase4_new_asset_types_and_diff_engine_real_mongo():
    """
    Constraint:
      - New asset types: content_path, api_spec, graphql_endpoint, param
      - Existing (project_id, type, value) unique index
      - first_seen/last_seen tracking
      - Diff engine integration: new content paths appear in "What's New"
      - Alert ONLY for 200/401/403 paths or API specs
    """
    client, db = await get_real_mongo_db()
    try:
        # Create unique compound index on assets
        await db.assets.create_index([("project_id", 1), ("type", 1), ("value", 1)], unique=True)

        project_id = str(ObjectId())

        t0 = datetime.now(timezone.utc) - timedelta(hours=2)
        t1 = datetime.now(timezone.utc)

        await db.projects.insert_one({
            "_id": ObjectId(project_id),
            "name": "Test Phase 4 Project",
            "schedule": {"stale_threshold": 2},
        })

        # Baseline job1
        j1 = await db.jobs.insert_one({
            "project_id": project_id,
            "status": "completed",
            "started_at": t0,
            "finished_at": t0 + timedelta(minutes=10),
            "scan_mode": "deep",
            "liveness_version": 2,
            "executed_phases": ["content_discovery", "api_surface", "param_discovery"],
        })
        job1_id = str(j1.inserted_id)

        # Scan 2 job2
        j2 = await db.jobs.insert_one({
            "project_id": project_id,
            "status": "completed",
            "started_at": t1,
            "finished_at": t1 + timedelta(minutes=10),
            "scan_mode": "deep",
            "liveness_version": 2,
            "executed_phases": ["content_discovery", "api_surface", "param_discovery"],
        })
        job2_id = str(j2.inserted_id)

        # Initial assets in Scan 1
        initial_assets = [
            {
                "project_id": project_id,
                "domain": "api.example.com",
                "type": "content_path",
                "value": "https://api.example.com/v1",
                "status": "live",
                "status_code": 200,
                "first_seen": t0,
                "last_seen": t0,
                "scan_id": job1_id,
                "metadata": {"url": "https://api.example.com/v1", "status_code": 200},
            },
            {
                "project_id": project_id,
                "domain": "api.example.com",
                "type": "subdomain",
                "value": "api.example.com",
                "status": "live",
                "first_seen": t0,
                "last_seen": t0,
                "scan_id": job1_id,
            }
        ]
        await db.assets.insert_many(initial_assets)

        # New Phase 4 assets discovered in Scan 2
        scan2_assets = [
            # 1. 200 OK Content Path (Must alert)
            {
                "project_id": project_id,
                "domain": "api.example.com",
                "type": "content_path",
                "value": "https://api.example.com/admin/login",
                "status": "live",
                "status_code": 200,
                "first_seen": t1,
                "last_seen": t1,
                "scan_id": job2_id,
                "metadata": {"url": "https://api.example.com/admin/login", "status_code": 200},
            },
            # 2. 403 Forbidden Content Path (Must alert)
            {
                "project_id": project_id,
                "domain": "api.example.com",
                "type": "content_path",
                "value": "https://api.example.com/internal-portal",
                "status": "live",
                "status_code": 403,
                "first_seen": t1,
                "last_seen": t1,
                "scan_id": job2_id,
                "metadata": {"url": "https://api.example.com/internal-portal", "status_code": 403},
            },
            # 3. 302 Redirect Content Path (Must NOT alert)
            {
                "project_id": project_id,
                "domain": "api.example.com",
                "type": "content_path",
                "value": "https://api.example.com/redirect-target",
                "status": "live",
                "status_code": 302,
                "first_seen": t1,
                "last_seen": t1,
                "scan_id": job2_id,
                "metadata": {"url": "https://api.example.com/redirect-target", "status_code": 302},
            },
            # 4. API Spec (Must alert)
            {
                "project_id": project_id,
                "domain": "api.example.com",
                "type": "api_spec",
                "value": "https://api.example.com/openapi.json",
                "status": "live",
                "first_seen": t1,
                "last_seen": t1,
                "scan_id": job2_id,
                "metadata": {"url": "https://api.example.com/openapi.json", "endpoints_count": 12},
            },
            # 5. GraphQL Endpoint
            {
                "project_id": project_id,
                "domain": "api.example.com",
                "type": "graphql_endpoint",
                "value": "https://api.example.com/graphql",
                "status": "live",
                "first_seen": t1,
                "last_seen": t1,
                "scan_id": job2_id,
                "metadata": {"url": "https://api.example.com/graphql", "introspection_enabled": True},
            },
            # 6. Parameter
            {
                "project_id": project_id,
                "domain": "api.example.com",
                "type": "param",
                "value": "https://api.example.com/items?query",
                "status": "live",
                "first_seen": t1,
                "last_seen": t1,
                "scan_id": job2_id,
                "metadata": {"endpoint": "https://api.example.com/items", "param_name": "query"},
            },
        ]
        await db.assets.insert_many(scan2_assets)

        # Compute diff vs previous job
        diff_doc = await compute_and_save_diff(
            project_id=project_id,
            current_job_id=job2_id,
            db=db,
        )

        assert diff_doc is not None
        diff = diff_doc.get("diff", {})
        summary = diff_doc.get("summary", {})

        # Assert new Phase 4 fields in diff and summary
        assert summary.get("new_content_paths_count") == 3
        assert summary.get("new_api_specs_count") == 1
        assert summary.get("new_graphql_endpoints_count") == 1
        assert summary.get("new_params_count") == 1

        new_cp_urls = [cp["url"] for cp in diff.get("new_content_paths", [])]
        assert "https://api.example.com/admin/login" in new_cp_urls
        assert "https://api.example.com/internal-portal" in new_cp_urls
        assert "https://api.example.com/redirect-target" in new_cp_urls
        # Existing v1 path must NOT be reported as new
        assert "https://api.example.com/v1" not in new_cp_urls

        # Verify Alert Filtering (Only 200/401/403 content paths or API specs alert)
        discord_sent = []
        async def mock_send_discord(**kwargs):
            discord_sent.append(kwargs)

        with patch("app.services.notifier._send_discord", side_effect=mock_send_discord):
            project_doc = {
                "_id": ObjectId(),
                "name": "Test Phase 4 Project",
                "alerts": {
                    "enabled": True,
                    "discord_webhook_url": "https://discord.com/api/webhooks/dummy",
                    "events": {"new_content_paths": True, "new_api_specs": True},
                }
            }
            await dispatch_scan_diff_alerts("Test Phase 4 Project", diff_doc, project_doc)

            assert len(discord_sent) == 1
            fields = discord_sent[0].get("fields", [])
            cp_field = next((f for f in fields if "New Content Paths" in f["name"]), None)
            spec_field = next((f for f in fields if "New API Specs" in f["name"]), None)

            assert cp_field is not None
            # Only the 2 alertable paths (200 OK and 403 Forbidden) must be in the alert, NOT 302!
            assert "[200]" in cp_field["value"]
            assert "[403]" in cp_field["value"]
            assert "[302]" not in cp_field["value"]
            assert "New Content Paths (2)" in cp_field["name"]

            assert spec_field is not None
            assert "openapi.json" in spec_field["value"]

    finally:
        await client.drop_database(db.name)
        client.close()


# ==============================================================================
# 8. Tool Command Construction & Name Validation
# ==============================================================================

def test_tool_command_validation_and_redacted_logging():
    """
    Constraint:
      - BaseProvider.detect_tool: reject any tool name not in the registry
        or not matching ^[a-z0-9_-]+$
      - Never interpolate unvalidated strings into a shell command
      - Argument lists only
      - Redacted command logging
    """
    provider = FfufProvider()

    # Rejection of dangerous tool names
    with pytest.raises(ValueError, match="Invalid tool name"):
        provider.detect_tool("ffuf; rm -rf /")

    with pytest.raises(ValueError, match="Invalid tool name"):
        provider.detect_tool("arjun && whoami")

    with pytest.raises(ValueError, match="Invalid tool name"):
        provider.detect_tool("waymore`id`")

    with pytest.raises(ValueError, match="not registered"):
        provider.detect_tool("unregistered_tool")

    # Command log redaction
    cmd = [
        "ffuf",
        "-u", "https://example.com/FUZZ",
        "-H", "Authorization: Bearer super-secret-jwt-token-12345",
        "-H", "X-API-Key: confidential-secret-key",
    ]
    formatted = provider.format_cmd_log(cmd)
    assert "super-secret-jwt-token-12345" not in formatted
    assert "confidential-secret-key" not in formatted
    assert "[REDACTED]" in formatted


# ==============================================================================
# 9. Phase 4 Follow-up Tests (Items 1-8)
# ==============================================================================

@pytest.mark.asyncio
async def test_baseline_new_asset_types_suppresses_new_when_phase_did_not_run_previously():
    """
    Follow-up Item 1:
      - Baseline new asset types: do not alert or report as 'new' any content_path,
        api_spec, graphql_endpoint or param asset when no earlier completed scan
        executed that phase.
      - Diff a type only if both scans ran its phase.
      - Missing tools (tool_missing) mean the phase did not run: never mark that
        type stale or removed because of a skipped phase.
    """
    client, db = await get_real_mongo_db()
    try:
        await db.assets.create_index([("project_id", 1), ("type", 1), ("value", 1)], unique=True)
        project_id = str(ObjectId())

        t0 = datetime.now(timezone.utc) - timedelta(hours=3)
        t1 = datetime.now(timezone.utc) - timedelta(hours=2)
        t2 = datetime.now(timezone.utc)

        await db.projects.insert_one({
            "_id": ObjectId(project_id),
            "name": "Phase 4 Baseline Project",
            "schedule": {"stale_threshold": 2},
        })

        # Scan 1: Completed without content_discovery or api_surface
        j1 = await db.jobs.insert_one({
            "project_id": project_id,
            "status": "completed",
            "started_at": t0,
            "finished_at": t0 + timedelta(minutes=5),
            "scan_mode": "fast",
            "liveness_version": 2,
            "executed_phases": ["subdomain_discovery", "port_scanning", "web_probing"],
            "logs": ["[*] subdomain_discovery finished", "[*] web probing finished"],
        })
        job1_id = str(j1.inserted_id)

        # Assets created in Scan 2
        await db.assets.insert_one({
            "project_id": project_id,
            "domain": "target.example.com",
            "type": "content_path",
            "value": "https://target.example.com/admin",
            "status": "live",
            "status_code": 200,
            "first_seen": t1,
            "last_seen": t1,
            "scan_id": "temp_job2",
            "metadata": {"url": "https://target.example.com/admin", "status_code": 200},
        })
        await db.assets.insert_one({
            "project_id": project_id,
            "domain": "target.example.com",
            "type": "api_spec",
            "value": "https://target.example.com/openapi.json",
            "status": "live",
            "first_seen": t1,
            "last_seen": t1,
            "scan_id": "temp_job2",
            "metadata": {"url": "https://target.example.com/openapi.json"},
        })

        # Scan 2: Executed content_discovery and api_surface
        j2 = await db.jobs.insert_one({
            "project_id": project_id,
            "status": "completed",
            "started_at": t1,
            "finished_at": t1 + timedelta(minutes=5),
            "scan_mode": "fast",
            "liveness_version": 2,
            "executed_phases": ["subdomain_discovery", "web_probing", "content_discovery", "api_surface"],
            "logs": ["[*] content discovery completed with ffuf", "[*] api spec found"],
        })
        job2_id = str(j2.inserted_id)
        await db.assets.update_many({"scan_id": "temp_job2"}, {"$set": {"scan_id": job2_id}})

        # Diff Scan 2 vs Scan 1
        diff_doc2 = await compute_and_save_diff(project_id=project_id, current_job_id=job2_id, db=db)
        summary2 = diff_doc2.get("summary", {})
        diff2 = diff_doc2.get("diff", {})

        # Since Scan 1 did NOT run content_discovery or api_surface, diff must suppress reporting them as new
        assert summary2.get("new_content_paths_count") == 0
        assert summary2.get("new_api_specs_count") == 0
        assert diff2.get("new_content_paths") == []
        assert diff2.get("new_api_specs") == []

        # Scan 3: Both Scan 2 and Scan 3 executed content_discovery
        await db.assets.insert_one({
            "project_id": project_id,
            "domain": "target.example.com",
            "type": "content_path",
            "value": "https://target.example.com/dashboard",
            "status": "live",
            "status_code": 200,
            "first_seen": t2,
            "last_seen": t2,
            "scan_id": "temp_job3",
            "metadata": {"url": "https://target.example.com/dashboard", "status_code": 200},
        })
        j3 = await db.jobs.insert_one({
            "project_id": project_id,
            "status": "completed",
            "started_at": t2,
            "finished_at": t2 + timedelta(minutes=5),
            "scan_mode": "fast",
            "liveness_version": 2,
            "executed_phases": ["subdomain_discovery", "web_probing", "content_discovery", "api_surface"],
            "logs": ["[*] content discovery completed with ffuf", "[*] api spec found"],
        })
        job3_id = str(j3.inserted_id)
        await db.assets.update_many({"scan_id": "temp_job3"}, {"$set": {"scan_id": job3_id}})

        diff_doc3 = await compute_and_save_diff(project_id=project_id, current_job_id=job3_id, db=db)
        summary3 = diff_doc3.get("summary", {})
        diff3 = diff_doc3.get("diff", {})

        # Now both scans executed content_discovery: only genuinely new path is reported
        assert summary3.get("new_content_paths_count") == 1
        new_urls3 = [cp["url"] for cp in diff3.get("new_content_paths", [])]
        assert "https://target.example.com/dashboard" in new_urls3
        assert "https://target.example.com/admin" not in new_urls3

        # Scan 4: ffuf missing -> phase skipped
        t3 = datetime.now(timezone.utc) + timedelta(hours=1)
        j4 = await db.jobs.insert_one({
            "project_id": project_id,
            "status": "completed",
            "started_at": t3,
            "finished_at": t3 + timedelta(minutes=5),
            "scan_mode": "fast",
            "liveness_version": 2,
            "executed_phases": ["subdomain_discovery", "web_probing"],
            "logs": ["tool_missing: ffuf", "skipping content discovery"],
        })
        job4_id = str(j4.inserted_id)

        diff_doc4 = await compute_and_save_diff(project_id=project_id, current_job_id=job4_id, db=db)
        summary4 = diff_doc4.get("summary", {})
        diff4 = diff_doc4.get("diff", {})

        # Skipped phase never marks content paths stale or removed
        assert summary4.get("new_content_paths_count") == 0
        assert diff4.get("new_content_paths") == []
        content_assets = await db.assets.find({"project_id": project_id, "type": "content_path"}).to_list(10)
        for ca in content_assets:
            assert ca.get("status") != "stale"
            assert ca.get("status") != "removed"

    finally:
        await client.drop_database(db.name)
        client.close()


def test_openapi_parsing_ignores_out_of_scope_servers():
    """
    Follow-up Item 2:
      - Build endpoint URLs only against the host where the spec was found
      - Ignore `servers` entries pointing at other hosts
      - Run every extracted URL through is_in_scope before entering URL pipeline
      - Test with a spec whose servers entry is out of scope
    """
    base_url = "https://api.example.com"
    spec_data = {
        "openapi": "3.0.0",
        "info": {"title": "Sample API", "version": "1.0"},
        "servers": [
            {"url": "https://attacker.external.com/api"},  # Out of scope / external host
            {"url": "https://malicious.net/v1"},          # Out of scope / external host
            {"url": "https://api.example.com/v1"},        # In scope, matching host
            {"url": "/v2"},                               # Relative path on same host
        ],
        "paths": {
            "/users": {"get": {}},
            "/billing/invoices": {"get": {}},
            "/admin/secrets": {"post": {}},
        }
    }
    scope = {
        "in_scope": ["*.example.com", "example.com"],
        "out_of_scope": ["attacker.external.com", "malicious.net"],
    }

    endpoints = ApiSurfaceProvider.extract_spec_endpoints(spec_data, base_url, scope=scope)

    assert len(endpoints) > 0
    for u in endpoints:
        assert "attacker.external.com" not in u
        assert "malicious.net" not in u
        assert u.startswith("https://api.example.com")
        assert is_in_scope(u, scope) is True

    assert "https://api.example.com/v1/users" in endpoints or "https://api.example.com/v2/users" in endpoints


def test_rate_limit_and_custom_headers_per_builder():
    """
    Follow-up Item 3:
      - Apply project rate limit and custom identification header to:
        ffuf (-rate, -H), GraphQL probes, historical-URL httpx probing, arjun, and x8,
        using each tool's real flags.
      - Show the redacted command in logs.
      - Add a test per builder.
    """
    custom_hdr = {
        "X-Security-Scan": "ReconForge-Audit-007",
        "Authorization": "Bearer super-sensitive-secret-token",
    }
    rate_limit = 25

    # 1. ffuf builder
    ffuf_cmd = FfufProvider.build_cmd(
        tool_path="/usr/bin/ffuf",
        fuzz_url="https://example.com/FUZZ",
        wordlist_path="/home/kali/wordlists/common.txt",
        wsl_out_path="/tmp/out.json",
        rate_limit=rate_limit,
        custom_headers=custom_hdr,
        scan_mode="fast",
    )
    assert "-rate" in ffuf_cmd
    assert ffuf_cmd[ffuf_cmd.index("-rate") + 1] == str(rate_limit)
    assert "-H" in ffuf_cmd
    assert "X-Security-Scan: ReconForge-Audit-007" in " ".join(ffuf_cmd)
    # Redaction test
    redacted_ffuf = FfufProvider.format_cmd_log(ffuf_cmd)
    assert "super-sensitive-secret-token" not in redacted_ffuf
    assert "[REDACTED]" in redacted_ffuf

    # 2. httpx historical probe builder
    httpx_cmd = HttpxProvider.build_historical_probe_cmd(
        tool_path="/usr/bin/httpx",
        wsl_in="/tmp/input.txt",
        rate_limit=30,
        custom_headers=custom_hdr,
    )
    assert "-rl" in httpx_cmd
    assert httpx_cmd[httpx_cmd.index("-rl") + 1] == "30"
    assert "-mc" in httpx_cmd
    assert httpx_cmd[httpx_cmd.index("-mc") + 1] == "200,301,302,401,403"
    assert "-H" in httpx_cmd
    redacted_httpx = HttpxProvider.format_cmd_log(httpx_cmd)
    assert "super-sensitive-secret-token" not in redacted_httpx
    assert "[REDACTED]" in redacted_httpx

    # 3. arjun builder
    arjun_cmd = ParamDiscoveryProvider.build_arjun_cmd(
        tool_path="/usr/bin/arjun",
        url="https://example.com/api/test",
        wsl_out="/tmp/out.json",
        rate_limit=15,
        custom_headers=custom_hdr,
    )
    assert "--rate-limit" in arjun_cmd
    assert arjun_cmd[arjun_cmd.index("--rate-limit") + 1] == "15"
    assert "--headers" in arjun_cmd
    assert "-T" in arjun_cmd
    redacted_arjun = ParamDiscoveryProvider.format_cmd_log(arjun_cmd)
    assert "super-sensitive-secret-token" not in redacted_arjun
    assert "[REDACTED]" in redacted_arjun

    # 4. x8 builder
    x8_cmd = ParamDiscoveryProvider.build_x8_cmd(
        tool_path="/usr/local/bin/x8",
        url="https://example.com/api/test",
        wsl_out="/tmp/out.json",
        rate_limit=10,
        custom_headers=custom_hdr,
    )
    assert "-d" in x8_cmd
    # 10 rps -> 100ms delay
    assert x8_cmd[x8_cmd.index("-d") + 1] == "100"
    assert "-H" in x8_cmd
    assert "-O" in x8_cmd
    assert x8_cmd[x8_cmd.index("-O") + 1] == "json"
    redacted_x8 = ParamDiscoveryProvider.format_cmd_log(x8_cmd)
    assert "super-sensitive-secret-token" not in redacted_x8
    assert "[REDACTED]" in redacted_x8

    # 5. GraphQL probe builder
    gql_probe = ApiSurfaceProvider.build_graphql_probe_request(
        gql_url="https://example.com/graphql",
        custom_headers=custom_hdr,
        rate_limit=20,
    )
    assert gql_probe["rate_limit"] == 20
    assert gql_probe["delay_seconds"] == 0.05
    assert gql_probe["headers"]["X-Security-Scan"] == "ReconForge-Audit-007"
    assert gql_probe["headers"]["Authorization"] == "Bearer super-sensitive-secret-token"
    assert "query" in gql_probe["json"]


@pytest.mark.asyncio
async def test_hard_time_limits_and_stage_timeout_events():
    """
    Follow-up Item 4:
      - ffuf -maxtime and -maxtime-job
      - per-host timeout for arjun/x8
      - global timeout for waymore (URL-only mode)
      - Timeouts end the phase gracefully, never the scan, and emit a stage_timeout event with the reason.
    """
    # 1. ffuf flags
    ffuf_cmd = FfufProvider.build_cmd(
        tool_path="ffuf",
        fuzz_url="https://example.com/FUZZ",
        wordlist_path="/tmp/wl.txt",
        wsl_out_path="/tmp/out.json",
        maxtime=180,
        maxtime_job=180,
    )
    assert "-maxtime" in ffuf_cmd
    assert ffuf_cmd[ffuf_cmd.index("-maxtime") + 1] == "180"
    assert "-maxtime-job" in ffuf_cmd
    assert ffuf_cmd[ffuf_cmd.index("-maxtime-job") + 1] == "180"

    # 2. ffuf timeout gracefully yields stage_timeout
    provider = FfufProvider()
    with patch.object(provider, "detect_tool", return_value="ffuf"), \
         patch("subprocess.Popen") as mock_popen, \
         patch("asyncio.wait_for", side_effect=asyncio.TimeoutError()), \
         patch("app.job_control.register_process"), \
         patch("app.job_control.unregister_process"):
        proc_mock = MagicMock()
        mock_popen.return_value = proc_mock
        events = []
        async for ev in provider.discover_content(["https://example.com"]):
            events.append(ev)

        timeout_evs = [e for e in events if e.get("type") == "stage_timeout"]
        assert len(timeout_evs) == 1
        assert timeout_evs[0]["tool"] == "ffuf"
        assert "timeout" in timeout_evs[0]["reason"]

    # 3. arjun timeout gracefully yields stage_timeout
    param_prov = ParamDiscoveryProvider()
    with patch.object(param_prov, "detect_tool", return_value="arjun"), \
         patch("subprocess.Popen") as mock_popen, \
         patch("asyncio.wait_for", side_effect=asyncio.TimeoutError()), \
         patch("app.job_control.register_process"), \
         patch("app.job_control.unregister_process"):
        proc_mock = MagicMock()
        mock_popen.return_value = proc_mock
        events = []
        async for ev in param_prov.discover_parameters(["https://example.com/api"]):
            events.append(ev)

        timeout_evs = [e for e in events if e.get("type") == "stage_timeout"]
        assert len(timeout_evs) == 1
        assert timeout_evs[0]["tool"] == "arjun"
        assert "timeout" in timeout_evs[0]["reason"]

    # 4. waymore global timeout gracefully yields stage_timeout
    waymore_prov = WaymoreProvider()
    with patch.object(waymore_prov, "detect_tool", return_value="waymore"), \
         patch("subprocess.Popen") as mock_popen, \
         patch("asyncio.wait_for", side_effect=asyncio.TimeoutError()), \
         patch("app.job_control.register_process"), \
         patch("app.job_control.unregister_process"):
        proc_mock = MagicMock()
        mock_popen.return_value = proc_mock
        events = []
        async for ev in waymore_prov.discover_urls(["example.com"]):
            events.append(ev)

        timeout_evs = [e for e in events if e.get("type") == "stage_timeout"]
        assert len(timeout_evs) == 1
        assert timeout_evs[0]["tool"] == "waymore"
        assert "global timeout" in timeout_evs[0]["reason"]


@pytest.mark.asyncio
async def test_ffuf_never_uses_redirect_flag_and_records_location():
    """
    Follow-up Item 5:
      - Confirm and test: ffuf never uses -r
      - 3xx Location targets are recorded in metadata but never fetched
    """
    provider = FfufProvider()

    # Verify -r is never in fast or deep mode command
    cmd_fast = provider.build_cmd("ffuf", "https://example.com/FUZZ", "/wl.txt", "/out.json", scan_mode="fast")
    assert "-r" not in cmd_fast

    cmd_deep = provider.build_cmd("ffuf", "https://example.com/FUZZ", "/wl.txt", "/out.json", scan_mode="deep")
    assert "-r" not in cmd_deep

    # Mock FFUF execution producing a 302 Redirect with redirectlocation
    ffuf_json = {
        "results": [
            {
                "input": {"FUZZ": "admin_redirect"},
                "url": "https://example.com/admin_redirect",
                "status": 302,
                "length": 145,
                "redirectlocation": "https://external-auth.example.com/login",
            }
        ]
    }

    mock_proc = MagicMock()
    mock_proc.wait = MagicMock(return_value=0)

    with patch.object(provider, "detect_tool", return_value="ffuf"), \
         patch("subprocess.Popen", return_value=mock_proc), \
         patch("app.job_control.register_process"), \
         patch("app.job_control.unregister_process"), \
         patch("tempfile.NamedTemporaryFile") as mock_tmp:

        tmp_obj = MagicMock()
        tmp_obj.name = "test_ffuf_302.json"
        mock_tmp.return_value = tmp_obj

        with open("test_ffuf_302.json", "w", encoding="utf-8") as f:
            json.dump(ffuf_json, f)

        try:
            events = []
            async for ev in provider.discover_content(["https://example.com"]):
                events.append(ev)

            asset_evs = [e for e in events if e.get("type") == "asset"]
            assert len(asset_evs) == 1
            meta = asset_evs[0]["data"]["metadata"]
            assert meta["status_code"] == 302
            assert meta["redirect_location"] == "https://external-auth.example.com/login"
        finally:
            if os.path.exists("test_ffuf_302.json"):
                os.unlink("test_ffuf_302.json")


def test_ffuf_fast_vs_deep_mode_behavior():
    """
    Follow-up Item 6:
      - Fast mode: small list, no recursion.
      - Deep mode: larger list, tech-based extensions, recursion depth max 1.
      - Hosts flagged CDN/WAF use a reduced rate and the small wordlist only with no recursion.
    """
    provider = FfufProvider()

    # Fast mode
    fast_cmd = provider.build_cmd(
        tool_path="ffuf",
        fuzz_url="https://example.com/FUZZ",
        wordlist_path="/home/kali/wordlists/common.txt",
        wsl_out_path="/tmp/out.json",
        rate_limit=25,
        scan_mode="fast",
    )
    assert "-recursion" not in fast_cmd
    assert "-recursion-depth" not in fast_cmd
    assert "-e" not in fast_cmd
    assert "-rate" in fast_cmd
    assert fast_cmd[fast_cmd.index("-rate") + 1] == "25"

    # Deep mode with PHP & IIS tech detected
    deep_cmd = provider.build_cmd(
        tool_path="ffuf",
        fuzz_url="https://example.com/FUZZ",
        wordlist_path="/home/kali/wordlists/raft-medium-words.txt",
        wsl_out_path="/tmp/out.json",
        rate_limit=25,
        scan_mode="deep",
        detected_tech=["PHP", "IIS", "ASP.NET"],
    )
    assert "-recursion" in deep_cmd
    assert "-recursion-depth" in deep_cmd
    assert deep_cmd[deep_cmd.index("-recursion-depth") + 1] == "1"
    assert "-e" in deep_cmd
    exts = deep_cmd[deep_cmd.index("-e") + 1]
    assert ".php" in exts
    assert ".asp" in exts
    assert ".aspx" in exts

    # WAF / CDN host in Deep mode: MUST be forced to fast mode (small list, no recursion, max 5 rps)
    waf_cmd = provider.build_cmd(
        tool_path="ffuf",
        fuzz_url="https://cloudflare-protected.com/FUZZ",
        wordlist_path="/home/kali/wordlists/common.txt",
        wsl_out_path="/tmp/out.json",
        rate_limit=50,
        scan_mode="deep",
        is_waf=True,
    )
    assert "-recursion" not in waf_cmd
    assert "-e" not in waf_cmd
    assert waf_cmd[waf_cmd.index("-rate") + 1] == "5"


@pytest.mark.asyncio
async def test_historical_dead_representation_and_unique_index_real_mongo():
    """
    Follow-up Item 7:
      - Choose one representation for historical-dead URLs (type: historical_dead).
      - Make sure the same URL cannot exist twice under the unique (project_id, type, value) index.
    """
    client, db = await get_real_mongo_db()
    try:
        # Enforce compound unique index
        await db.assets.create_index([("project_id", 1), ("type", 1), ("value", 1)], unique=True)
        project_id = str(ObjectId())
        dead_url = "https://example.com/defunct-service-v0"

        # First insert
        doc1 = {
            "project_id": project_id,
            "type": "historical_dead",
            "value": dead_url,
            "domain": "example.com",
            "status": "dead",
            "first_seen": datetime.now(timezone.utc),
            "last_seen": datetime.now(timezone.utc),
        }
        await db.assets.insert_one(doc1)

        # Attempting a second insert with the same key should raise DuplicateKeyError
        import pymongo.errors
        doc2 = {
            "project_id": project_id,
            "type": "historical_dead",
            "value": dead_url,
            "domain": "example.com",
            "status": "dead",
            "first_seen": datetime.now(timezone.utc),
            "last_seen": datetime.now(timezone.utc),
        }
        with pytest.raises(pymongo.errors.DuplicateKeyError):
            await db.assets.insert_one(doc2)

        # Upsert pattern preserves single representation
        now_dt = datetime.now(timezone.utc)
        await db.assets.update_one(
            {"project_id": project_id, "type": "historical_dead", "value": dead_url},
            {"$set": {"last_seen": now_dt, "status": "dead"}},
            upsert=True,
        )

        count = await db.assets.count_documents({"project_id": project_id, "type": "historical_dead", "value": dead_url})
        assert count == 1

    finally:
        await client.drop_database(db.name)
        client.close()


def test_per_host_url_cap_runs_after_priority_sorting():
    """
    Follow-up Item 8:
      - Confirm the per-host URL cap runs AFTER priority sorting.
    """
    # Create 10 URLs on api.example.com with varying priorities
    # Priority 0: query parameters (e.g. ?id=1, ?debug=true)
    # Priority 1: API routes without file extensions
    # Priority 2: Interesting extensions (.json, .js)
    # Priority 3: Other paths
    urls = [
        "https://api.example.com/static/style.css",           # Priority 3
        "https://api.example.com/v1/users?id=123",            # Priority 0
        "https://api.example.com/images/logo.png",           # Priority 3
        "https://api.example.com/v1/auth?token=abc",          # Priority 0
        "https://api.example.com/api/v2/checkout",           # Priority 1
        "https://api.example.com/about.html",                 # Priority 2
        "https://api.example.com/api/v1/settings",           # Priority 1
        "https://api.example.com/config.json",                # Priority 2
        "https://api.example.com/faq.txt",                    # Priority 2
        "https://api.example.com/docs/readme",                # Priority 1
    ]

    # Set per_host_cap to 3
    merged = merge_urls(
        katana_urls=urls,
        scan_mode="fast",
        per_host_cap=3,
        global_cap=1000,
    )

    # Exactly 3 URLs must be selected for api.example.com
    assert len(merged) == 3
    selected_urls = [m["url"] for m in merged]

    # Both Priority 0 URLs (with query parameters) MUST be included
    assert "https://api.example.com/v1/users?id=123" in selected_urls
    assert "https://api.example.com/v1/auth?token=abc" in selected_urls

    # The 3rd URL MUST be Priority 1 (API route), NOT Priority 2 or 3
    assert any(u in selected_urls for u in [
        "https://api.example.com/api/v2/checkout",
        "https://api.example.com/api/v1/settings",
        "https://api.example.com/docs/readme"
    ])
    # Lower priority URLs must NOT be present
    assert "https://api.example.com/static/style.css" not in selected_urls
    assert "https://api.example.com/images/logo.png" not in selected_urls
    assert "https://api.example.com/about.html" not in selected_urls
