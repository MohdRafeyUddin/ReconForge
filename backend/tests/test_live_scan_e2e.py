import asyncio
import os
import sys
import uuid
from pathlib import Path
from contextlib import ExitStack
import pytest

base_dir = Path(__file__).resolve().parent.parent
if str(base_dir) not in sys.path:
    sys.path.insert(0, str(base_dir))

from datetime import datetime
from unittest.mock import patch, AsyncMock
from bson import ObjectId
from motor.motor_asyncio import AsyncIOMotorClient

import app.database as database_module
from app.core.scope import normalize_seed_domain
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

    test_db_name = f"reconforge_e2e_test_{uuid.uuid4().hex[:12]}"
    test_db = client[test_db_name]

    # Create collection indexes matching production setup
    await test_db.users.create_index("username", unique=True)
    await test_db.users.create_index("email", unique=True)
    await test_db.assets.create_index([("project_id", 1), ("type", 1), ("domain", 1)])
    await test_db.assets.create_index(
        [("project_id", 1), ("type", 1), ("value", 1)],
        unique=True,
        name="project_id_1_type_1_value_1_unique"
    )
    await test_db.scan_diffs.create_index([("project_id", 1), ("created_at", -1)])

    # Swap in real test db for the app
    old_db = database_module.db_helper.db
    old_is_mock = database_module.db_helper.is_mock
    database_module.db_helper.db = test_db
    database_module.db_helper.is_mock = False

    return client, test_db, old_db, old_is_mock


async def teardown_real_test_db(client, test_db, old_db, old_is_mock):
    try:
        await client.drop_database(test_db.name)
    finally:
        database_module.db_helper.db = old_db
        database_module.db_helper.is_mock = old_is_mock
        client.close()


# ==============================================================================
# Unit Test: Seed Domain Normalization
# ==============================================================================

def test_seed_domain_normalization():
    """Verify wildcard and URL seeds are cleanly normalized to bare root domains."""
    assert normalize_seed_domain("*.example.com") == "example.com"
    assert normalize_seed_domain("*example.com") == "example.com"
    assert normalize_seed_domain("*.sub.target.org") == "sub.target.org"
    assert normalize_seed_domain("https://*.example.com:8443/test") == "example.com"
    assert normalize_seed_domain("example.com") == "example.com"
    assert normalize_seed_domain("   *.portal.io   ") == "portal.io"


# ==============================================================================
# E2E Test 1: All Phases Complete with Fake Provider Outputs on Real MongoDB
# ==============================================================================

@pytest.mark.asyncio
async def test_e2e_run_discovery_job_all_phases_completes_on_real_mongo():
    """
    Runs run_discovery_job to completion on real MongoDB with fake provider outputs
    for all phases. Asserts:
      - job status is 'completed'
      - the seed root domain is probed and stored in db.assets
      - no exception escapes
      - all executed phases are tracked
    """
    client, db, old_db, old_is_mock = await setup_real_test_db()
    try:
        project_id = ObjectId()
        job_id = ObjectId()

        # Seed document in real MongoDB
        await db.projects.insert_one({
            "_id": project_id,
            "name": "E2E Full Phases Test",
            "seed_domains": ["*.example.com"],
            "scope": {
                "in_scope": ["*.example.com", "example.com"],
                "out_of_scope": [],
            },
            "rate_limits": {"rate": 50},
            "custom_headers": {"X-Test": "Integration"},
            "clustering": {"enabled": True},
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

        # Fake async generator outputs for internal pipeline providers
        async def fake_subfinder(seeds, **kwargs):
            yield {"type": "asset", "data": {"domain": "api.example.com"}}

        async def fake_assetfinder(seeds, **kwargs):
            yield {"type": "asset", "data": {"domain": "admin.example.com"}}

        async def fake_chaos(seeds, **kwargs):
            yield {"type": "asset", "data": {"domain": "app.example.com"}}

        async def fake_amass(seeds, **kwargs):
            yield {"type": "asset", "data": {"domain": "dev.example.com"}}

        async def fake_dnsx(targets, **kwargs):
            for t in targets:
                yield {
                    "type": "asset",
                    "data": {
                        "domain": t,
                        "status": "resolved",
                        "resolved_ip": "93.184.216.34",
                        "metadata": {"dns": {"cname": []}},
                    },
                }
            yield {"type": "scan_summary", "provider": "DNSx", "resolved": len(targets), "nxdomain": 0, "wildcards_filtered": 0}

        async def fake_subzy(targets, **kwargs):
            yield {"type": "scan_summary", "provider": "subzy", "takeovers": 0}

        async def fake_naabu(targets, **kwargs):
            for t in targets:
                yield {
                    "type": "asset",
                    "data": {
                        "domain": t,
                        "open_ports": [80, 443],
                        "services": [{"port": 80, "service": "http"}, {"port": 443, "service": "https"}],
                    },
                }

        async def fake_httpx(targets, **kwargs):
            for t in targets:
                yield {
                    "type": "asset",
                    "data": {
                        "domain": t,
                        "url": f"https://{t}",
                        "status": "live",
                        "status_code": 200,
                        "title": f"Title for {t}",
                        "technologies": ["Nginx"],
                        "web_server": "nginx",
                        "open_ports": [443],
                        "metadata": {
                            "status_code": 200,
                            "title": f"Title for {t}",
                            "url": f"https://{t}",
                            "technologies": ["Nginx"],
                        },
                    },
                }

        async def fake_waf(targets, **kwargs):
            yield {"type": "scan_summary", "provider": "wafw00f", "detected": 0}

        async def fake_ffuf(targets, **kwargs):
            yield {
                "type": "asset",
                "data": {
                    "type": "content_path",
                    "value": "https://example.com/admin",
                    "path": "/admin",
                    "status_code": 403,
                    "host": "example.com",
                    "url": "https://example.com/admin",
                },
            }

        async def fake_api_surface(targets, **kwargs):
            yield {
                "type": "asset",
                "data": {
                    "type": "api_spec",
                    "value": "https://example.com/openapi.json",
                    "format": "openapi_v3",
                    "host": "example.com",
                    "url": "https://example.com/openapi.json",
                },
            }
            yield {
                "type": "asset",
                "data": {
                    "type": "graphql_endpoint",
                    "value": "https://example.com/graphql",
                    "introspection_enabled": False,
                    "host": "example.com",
                    "url": "https://example.com/graphql",
                },
            }

        async def fake_katana(targets, **kwargs):
            yield {
                "type": "asset",
                "data": {
                    "metadata": {
                        "katana": {
                            "urls": ["https://example.com/search", "https://example.com/login"],
                            "js_files": ["https://example.com/bundle.js"],
                        }
                    }
                }
            }
            yield {"type": "scan_summary", "provider": "katana", "urls_discovered": 2, "hosts_scanned": 1}

        async def fake_gau(targets, **kwargs):
            yield {"type": "url_event", "data": {"url": "https://example.com/about"}}
            yield {"type": "scan_summary", "provider": "gau", "count": 1}

        async def fake_waymore(targets, **kwargs):
            yield {"type": "url_event", "data": {"url": "https://example.com/terms"}}
            yield {"type": "scan_summary", "provider": "waymore", "count": 1}

        async def fake_subjs(targets, **kwargs):
            yield {"type": "js_event", "data": {"url": "https://example.com/bundle.js"}}
            yield {"type": "scan_summary", "provider": "subjs", "count": 1}

        gowitness_targets = []

        async def fake_gowitness(targets, **kwargs):
            gowitness_targets.extend(targets)
            yield {"type": "scan_summary", "provider": "gowitness", "screenshots": 1}

        async def fake_linkfinder(targets, **kwargs):
            yield {"type": "url_event", "data": {"url": "https://example.com/api/v1/user"}}
            yield {"type": "scan_summary", "provider": "linkfinder", "count": 1}

        async def fake_uro(targets, **kwargs):
            for t in targets:
                yield {"type": "url_event", "data": {"url": t}}
            yield {"type": "scan_summary", "provider": "Uro", "removed": 0}

        async def fake_param(targets, **kwargs):
            yield {
                "type": "asset",
                "data": {
                    "type": "param",
                    "value": "https://example.com/search?q=",
                    "url": "https://example.com/search",
                    "param": "q",
                    "method": "GET",
                    "host": "example.com",
                    "sources": ["param_discovery"],
                },
            }
            yield {
                "type": "url_event",
                "data": {
                    "url": "https://example.com/search?q=FUZZ",
                    "source": "param_discovery",
                },
            }
            yield {"type": "scan_summary", "provider": "arjun", "count": 1}

        async def fake_gf(targets, **kwargs):
            yield {"type": "scan_summary", "provider": "gf", "patterns_matched": 1}

        async def fake_nuclei(targets, **kwargs):
            yield {
                "type": "asset",
                "data": {
                    "domain": "example.com",
                    "type": "subdomain",
                    "metadata": {
                        "nuclei": {
                            "findings": [
                                {
                                    "template_id": "cve-test",
                                    "matched_url": "https://example.com",
                                    "severity": "medium",
                                }
                            ]
                        }
                    },
                },
            }
            yield {"type": "scan_summary", "provider": "nuclei", "findings": 1}

        async def fake_dalfox(targets, **kwargs):
            yield {"type": "scan_summary", "provider": "dalfox", "findings": 0}

        async def fake_openredirex(targets, **kwargs):
            yield {"type": "scan_summary", "provider": "openredirex", "findings": 0}

        async def fake_probe_historical(urls, **kwargs):
            for u in urls:
                yield {
                    "type": "historical_probe_event",
                    "data": {"url": u, "status": "live", "status_code": 200},
                }

        # Patch tool availability and provider outputs using ExitStack
        patches = [
            patch("app.core.tools.is_tool_available", return_value=True),
            patch("app.providers.unified_discovery_provider.is_tool_available", return_value=True),
            patch("app.providers.subfinder_provider.SubfinderProvider.discover", side_effect=fake_subfinder),
            patch("app.providers.assetfinder_provider.AssetfinderProvider.discover", side_effect=fake_assetfinder),
            patch("app.providers.chaos_provider.ChaosProvider.discover", side_effect=fake_chaos),
            patch("app.providers.amass_provider.AmassProvider.discover", side_effect=fake_amass),
            patch("app.providers.dnsx_provider.DnsxProvider.discover", side_effect=fake_dnsx),
            patch("app.providers.subzy_provider.SubzyProvider.discover", side_effect=fake_subzy),
            patch("app.providers.naabu_provider.NaabuProvider.discover", side_effect=fake_naabu),
            patch("app.providers.httpx_provider.HttpxProvider.discover", side_effect=fake_httpx),
            patch("app.providers.httpx_provider.HttpxProvider.probe_historical_urls", side_effect=fake_probe_historical),
            patch("app.providers.wafw00f_provider.Wafw00fProvider.discover", side_effect=fake_waf),
            patch("app.providers.ffuf_provider.FfufProvider.discover", side_effect=fake_ffuf),
            patch("app.providers.api_surface_provider.ApiSurfaceProvider.discover", side_effect=fake_api_surface),
            patch("app.providers.katana_provider.KatanaProvider.discover", side_effect=fake_katana),
            patch("app.providers.gau_provider.GauProvider.discover", side_effect=fake_gau),
            patch("app.providers.waymore_provider.WaymoreProvider.discover", side_effect=fake_waymore),
            patch("app.providers.subjs_provider.SubjsProvider.discover", side_effect=fake_subjs),
            patch("app.providers.gowitness_provider.GowitnessProvider.discover", side_effect=fake_gowitness),
            patch("app.providers.linkfinder_provider.LinkfinderProvider.discover", side_effect=fake_linkfinder),
            patch("app.providers.uro_provider.UroProvider.discover", side_effect=fake_uro),
            patch("app.providers.param_discovery_provider.ParamDiscoveryProvider.discover", side_effect=fake_param),
            patch("app.providers.gf_provider.GfProvider.discover", side_effect=fake_gf),
            patch("app.providers.nuclei_provider.NucleiProvider.discover", side_effect=fake_nuclei),
            patch("app.providers.nuclei_provider.NucleiProvider.discover_host_scan", side_effect=fake_nuclei),
            patch("app.providers.nuclei_provider.NucleiProvider.discover_endpoint_scan", side_effect=fake_nuclei),
            patch("app.providers.dalfox_provider.DalfoxProvider.discover", side_effect=fake_dalfox),
            patch("app.providers.openredirex_provider.OpenredirexProvider.discover", side_effect=fake_openredirex),
        ]
        with ExitStack() as stack:
            for p in patches:
                stack.enter_context(p)

            # Run discovery job to completion with wildcard seed
            await run_discovery_job(
                job_id=str(job_id),
                project_id=str(project_id),
                provider_name="Unified Discovery",
                seed_domains=["*.example.com"],
            )

        # 1. Assert: Job status is 'completed'
        job_doc = await db.jobs.find_one({"_id": job_id})
        assert job_doc is not None
        assert job_doc["status"] == "completed", f"Job failed with status: {job_doc.get('status')}, logs: {job_doc.get('logs')[-5:]}"

        # 2. Assert: Seed root domain 'example.com' was probed and stored in db.assets
        root_asset = await db.assets.find_one({
            "project_id": str(project_id),
            "type": "subdomain",
            "$or": [{"value": "example.com"}, {"domain": "example.com"}],
        })
        assert root_asset is not None, "Root domain 'example.com' was not probed or stored in db.assets!"
        assert root_asset.get("status") in ("live", "resolved")

        # 3. Assert: New asset types from Phase 4 were saved
        content_asset = await db.assets.find_one({"project_id": str(project_id), "type": "content_path"})
        assert content_asset is not None
        assert content_asset["value"] == "https://example.com/admin"

        api_asset = await db.assets.find_one({"project_id": str(project_id), "type": "api_spec"})
        assert api_asset is not None
        assert api_asset["value"] == "https://example.com/openapi.json"

        param_asset = await db.assets.find_one({"project_id": str(project_id), "type": "param"})
        assert param_asset is not None
        assert param_asset["value"] == "https://example.com/search?q="

        # 4. Assert: Executed phases saved on job
        executed = set(job_doc.get("executed_phases", []))
        assert "subdomain_discovery" in executed
        assert "content_discovery" in executed
        assert "api_surface" in executed
        assert "param_discovery" in executed

        # 5. Assert: GoWitness runs after URL extraction and gets more than
        #    the bare host root, without duplicate targets.
        assert "https://example.com" in gowitness_targets
        assert any(url != "https://example.com" for url in gowitness_targets), gowitness_targets
        assert len(gowitness_targets) == len(set(gowitness_targets))

    finally:
        await teardown_real_test_db(client, db, old_db, old_is_mock)


# ==============================================================================
# E2E Test 2: All Passive Tools Missing -> Seed Root Probed & Job Completes
# ==============================================================================

@pytest.mark.asyncio
async def test_e2e_run_discovery_job_all_passive_tools_missing_probes_seed_root():
    """
    Runs run_discovery_job when ALL passive discovery tools (subfinder, assetfinder,
    chaos, amass) are missing / uninstalled. Asserts:
      - Warning event naming all missing tools is emitted
      - The seed root domain ('example.com') is ALWAYS included and probed
      - Job completes with status 'completed'
      - No exception escapes
    """
    client, db, old_db, old_is_mock = await setup_real_test_db()
    try:
        project_id = ObjectId()
        job_id = ObjectId()

        await db.projects.insert_one({
            "_id": project_id,
            "name": "E2E Passive Missing Test",
            "seed_domains": ["*.example.com"],
            "scope": {
                "in_scope": ["*.example.com", "example.com"],
                "out_of_scope": [],
            },
            "rate_limits": {"rate": 50},
            "assume_tools_installed": False,
            "created_at": datetime.utcnow(),
        })

        await db.jobs.insert_one({
            "_id": job_id,
            "project_id": str(project_id),
            "provider_name": "Unified Discovery",
            "scan_mode": "fast",
            "status": "pending",
            "logs": [],
            "created_at": datetime.utcnow(),
        })

        # Fake active stages (DNSx and HTTPx) to probe the seed root
        async def fake_dnsx(targets, **kwargs):
            for t in targets:
                yield {
                    "type": "asset",
                    "data": {
                        "domain": t,
                        "status": "resolved",
                        "resolved_ip": "93.184.216.34",
                        "metadata": {"dns": {"cname": []}},
                    },
                }
            yield {"type": "scan_summary", "provider": "DNSx", "resolved": len(targets)}

        async def fake_httpx(targets, **kwargs):
            for t in targets:
                yield {
                    "type": "asset",
                    "data": {
                        "domain": t,
                        "url": f"https://{t}",
                        "status": "live",
                        "status_code": 200,
                        "title": "Seed Root Live Page",
                        "technologies": ["Nginx"],
                        "open_ports": [443],
                        "metadata": {"status_code": 200, "url": f"https://{t}"},
                    },
                }

        # Passive tools return False for is_tool_available; active tools return True
        def mock_is_tool_available(tool_name: str) -> bool:
            if tool_name in ("subfinder", "assetfinder", "chaos", "amass"):
                return False
            if tool_name in ("dnsx", "httpx"):
                return True
            return False

        broadcast_events = []
        orig_broadcast = manager.broadcast

        async def capture_broadcast(j_id, msg):
            broadcast_events.append(msg)
            return await orig_broadcast(j_id, msg)

        with patch("app.core.tools.is_tool_available", side_effect=mock_is_tool_available), \
             patch("app.providers.unified_discovery_provider.is_tool_available", side_effect=mock_is_tool_available), \
             patch("app.providers.dnsx_provider.DnsxProvider.discover", side_effect=fake_dnsx), \
             patch("app.providers.httpx_provider.HttpxProvider.discover", side_effect=fake_httpx), \
             patch.object(manager, "broadcast", side_effect=capture_broadcast):

            # Run job with wildcard seed
            await run_discovery_job(
                job_id=str(job_id),
                project_id=str(project_id),
                provider_name="Unified Discovery",
                seed_domains=["*.example.com"],
            )

        # 1. Assert: Job status is 'completed'
        job_doc = await db.jobs.find_one({"_id": job_id})
        assert job_doc is not None
        assert job_doc["status"] == "completed", f"Job status was not completed: {job_doc.get('status')}"

        # 2. Assert: Warning event was emitted naming all missing passive tools
        warning_events = [e for e in broadcast_events if e.get("type") == "warning_event" and e.get("warning") == "all_passive_tools_missing"]
        assert len(warning_events) == 1, f"Expected 1 all_passive_tools_missing warning event, got: {warning_events}"
        missing_tools = warning_events[0].get("missing_tools", [])
        assert set(missing_tools) == {"subfinder", "assetfinder", "chaos", "amass"}

        # 3. Assert: Seed root domain 'example.com' was probed and stored in db.assets
        root_asset = await db.assets.find_one({
            "project_id": str(project_id),
            "type": "subdomain",
            "$or": [{"value": "example.com"}, {"domain": "example.com"}],
        })
        assert root_asset is not None, "Root domain 'example.com' was not probed or stored when passive tools were missing!"
        assert root_asset["status"] == "live"
        assert root_asset.get("metadata", {}).get("status_code") == 200

    finally:
        await teardown_real_test_db(client, db, old_db, old_is_mock)


# ==============================================================================
# E2E Test 3: Diff & Alert Exception Isolation (Never Fails Scan Job)
# ==============================================================================

@pytest.mark.asyncio
async def test_e2e_diff_and_alerts_exception_isolation_never_fails_job():
    """
    Requirement 2: The diff computation and alert dispatch block must be fully
    isolated: any exception there (including ImportError) is logged and emitted
    as a stage_error event but must NEVER fail or change the status of the scan job.
    """
    client, db, old_db, old_is_mock = await setup_real_test_db()
    try:
        project_id = ObjectId()
        job_id = ObjectId()

        await db.projects.insert_one({
            "_id": project_id,
            "name": "E2E Diff Isolation Test",
            "seed_domains": ["example.com"],
            "scope": {"in_scope": ["example.com"], "out_of_scope": []},
            "assume_tools_installed": False,
            "created_at": datetime.utcnow(),
        })

        await db.jobs.insert_one({
            "_id": job_id,
            "project_id": str(project_id),
            "provider_name": "Unified Discovery",
            "status": "pending",
            "logs": [],
            "created_at": datetime.utcnow(),
        })

        broadcast_events = []
        orig_broadcast = manager.broadcast

        async def capture_broadcast(j_id, msg):
            broadcast_events.append(msg)
            return await orig_broadcast(j_id, msg)

        # Mock compute_and_save_diff to simulate an ImportError or runtime crash
        with patch("app.core.tools.is_tool_available", return_value=False), \
             patch("app.providers.unified_discovery_provider.is_tool_available", return_value=False), \
             patch("app.services.diff_engine.compute_and_save_diff", side_effect=ImportError("Simulated missing module in diff engine")), \
             patch.object(manager, "broadcast", side_effect=capture_broadcast):

            await run_discovery_job(
                job_id=str(job_id),
                project_id=str(project_id),
                provider_name="Unified Discovery",
                seed_domains=["example.com"],
            )

        # Assert: Job completed successfully despite diff ImportError
        job_doc = await db.jobs.find_one({"_id": job_id})
        assert job_doc is not None
        assert job_doc["status"] == "completed", f"Job status was {job_doc.get('status')}, expected 'completed'"

        # Assert: stage_error event was broadcast for diff_and_alerts
        stage_errors = [e for e in broadcast_events if e.get("type") == "stage_error" and e.get("stage") == "diff_and_alerts"]
        assert len(stage_errors) >= 1
        assert stage_errors[0].get("stage") == "diff_and_alerts"
        assert "Simulated missing module" in stage_errors[0].get("error", "")

    finally:
        await teardown_real_test_db(client, db, old_db, old_is_mock)


# ==============================================================================
# E2E Test 4: Abort Pipeline When DNS Resolution Yields No Resolvable Hosts
# ==============================================================================

@pytest.mark.asyncio
async def test_e2e_dns_resolution_no_resolvable_hosts_aborts():
    """
    Requirement 4: Abort only when DNS resolution yields no resolvable hosts.
    When dnsx is available and resolves 0 hosts, the pipeline aborts cleanly.
    """
    client, db, old_db, old_is_mock = await setup_real_test_db()
    try:
        project_id = ObjectId()
        job_id = ObjectId()

        await db.projects.insert_one({
            "_id": project_id,
            "name": "E2E DNS Resolution Abort Test",
            "seed_domains": ["nonexistent-test-domain.invalid"],
            "scope": {"in_scope": ["nonexistent-test-domain.invalid"], "out_of_scope": []},
            "assume_tools_installed": False,
            "created_at": datetime.utcnow(),
        })

        await db.jobs.insert_one({
            "_id": job_id,
            "project_id": str(project_id),
            "provider_name": "Unified Discovery",
            "status": "pending",
            "logs": [],
            "created_at": datetime.utcnow(),
        })

        # DNSx returns 0 resolved hosts
        async def fake_dnsx_empty(targets, **kwargs):
            yield {"type": "scan_summary", "provider": "DNSx", "resolved": 0, "nxdomain": len(targets), "wildcards_filtered": 0}

        def mock_is_tool_available(tool_name: str) -> bool:
            if tool_name == "dnsx":
                return True
            return False

        with patch("app.core.tools.is_tool_available", side_effect=mock_is_tool_available), \
             patch("app.providers.unified_discovery_provider.is_tool_available", side_effect=mock_is_tool_available), \
             patch("app.providers.dnsx_provider.DnsxProvider.discover", side_effect=fake_dnsx_empty):

            await run_discovery_job(
                job_id=str(job_id),
                project_id=str(project_id),
                provider_name="Unified Discovery",
                seed_domains=["nonexistent-test-domain.invalid"],
            )

        job_doc = await db.jobs.find_one({"_id": job_id})
        assert job_doc is not None
        assert job_doc["status"] == "completed"

        # Check logs contain the abort message
        logs_str = " ".join(job_doc.get("logs", []))
        assert "DNS resolution yielded no resolvable hosts" in logs_str

    finally:
        await teardown_real_test_db(client, db, old_db, old_is_mock)
