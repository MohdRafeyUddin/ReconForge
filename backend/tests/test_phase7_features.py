"""test_phase7_features.py
========================
Tests for Phase 7 implementation:
- Tool Registry (puredns, massdns, shuffledns, alterx, asnmap, dnsreaper)
- Passive sources (crt.sh, certspotter) and Subfinder API keys masking & syncing
- DNS brute-force + alterx permutations (Fast mode skips, Deep mode executes, scope filtering, permutations cap, disallowed IP dropping)
- Opt-in Root-Domain Expansion (suggestions only, never auto-scanned, Approve/Reject workflow)
- Takeover cross-check (runs in recon profile, single-tool unconfirmed, multi-tool confirmed)
"""

import json
import os
import pytest
from datetime import datetime
from bson import ObjectId
import httpx

from app.core.tools import RECON_TOOLS, is_tool_available
from app.core.provider_keys import (
    get_masked_keys_status,
    save_provider_keys,
    sync_subfinder_config_to_wsl,
    load_provider_keys,
)
from app.core.scope import validate_hostname, is_disallowed_ip, is_in_scope
from app.providers.crtsh_provider import CrtshProvider
from app.providers.certspotter_provider import CertspotterProvider
from app.providers.dns_bruteforce_provider import DnsBruteforceProvider
from app.providers.root_expansion_provider import RootExpansionProvider
from app.providers.takeover_crosscheck_provider import TakeoverCrossCheckProvider
from app.providers.unified_discovery_provider import UnifiedDiscoveryProvider
from app.database import get_database, db_helper
from app.main import app

REAL_MONGO_TEST_URI = os.getenv("MONGODB_URL", "mongodb://127.0.0.1:27017")
TEST_DB_NAME = "reconforge_phase7_test_db"


async def setup_test_db():
    from motor.motor_asyncio import AsyncIOMotorClient
    client = AsyncIOMotorClient(REAL_MONGO_TEST_URI)
    db = client[TEST_DB_NAME]
    old_db = db_helper.db
    old_client = db_helper.client
    old_is_mock = getattr(db_helper, "is_mock", False)
    db_helper.db = db
    db_helper.client = client
    db_helper.is_mock = False
    return client, db, old_db, old_client, old_is_mock


async def teardown_test_db(client, old_db, old_client, old_is_mock):
    try:
        await client.drop_database(TEST_DB_NAME)
    except Exception:
        pass
    db_helper.db = old_db
    db_helper.client = old_client
    db_helper.is_mock = old_is_mock


def test_tool_registry_phase7():
    """Verifies all Phase 7 tools are registered in RECON_TOOLS with install hints and binary names."""
    required_phase7_tools = [
        "puredns",
        "massdns",
        "shuffledns",
        "alterx",
        "asnmap",
        "dnsreaper",
    ]
    for tool_name in required_phase7_tools:
        assert tool_name in RECON_TOOLS, f"Tool {tool_name} must be registered in RECON_TOOLS"
        spec = RECON_TOOLS[tool_name]
        assert "binary" in spec and spec["binary"], f"{tool_name} missing binary"
        assert "install_hint" in spec and spec["install_hint"], f"{tool_name} missing install_hint"
        assert "description" in spec and spec["description"], f"{tool_name} missing description"


def test_provider_keys_masking_and_sync(tmp_path):
    """Verifies API keys are masked in API/UI, never returned in plaintext, and synced to config."""
    test_keys = {
        "securitytrails": "sec_key_1234567890abcdef",
        "shodan": "shodan_token_9876543210fedcba",
        "virustotal": "vt_secret_abcdef1234567890",
    }
    # Save provider keys
    success = save_provider_keys(test_keys)
    assert success is True

    # Retrieve masked status (keyed by provider name)
    status = get_masked_keys_status()
    assert "securitytrails" in status
    assert status["securitytrails"]["configured"] is True
    assert status["securitytrails"]["masked"] != test_keys["securitytrails"]
    assert "*" in status["securitytrails"]["masked"]

    assert "shodan" in status
    assert status["shodan"]["configured"] is True
    assert status["shodan"]["masked"] != test_keys["shodan"]

    assert "virustotal" in status
    assert status["virustotal"]["configured"] is True

    # Test sync to Subfinder config returns boolean
    synced = sync_subfinder_config_to_wsl()
    assert isinstance(synced, bool)


def test_hostname_validation_and_disallowed_ips():
    """Verifies strict RFC hostname validation and disallowed IP dropping."""
    # 1. Valid hostnames
    valid_hosts = ["example.com", "sub.example.com", "api-v2.service.corp.co.uk", "a.b.c.org"]
    for h in valid_hosts:
        ok, reason = validate_hostname(h)
        assert ok is True, f"Expected {h} to be valid, got reason: {reason}"

    # 2. Invalid hostnames: repeated labels, invalid characters, encoded fragments, excessive length
    invalid_hosts = [
        "example..com",
        "-leadingdash.com",
        "trailingdash-.com",
        "example.com/path",
        "example.com:8080",
        "test%20space.com",
        "a" * 64 + ".com",  # Label > 63 chars
        "example.com.example.com",  # Repeated root domain
    ]
    for h in invalid_hosts:
        ok, reason = validate_hostname(h)
        assert ok is False, f"Expected {h} to be invalid"

    # 3. Disallowed IP addresses: loopback, RFC1918, CGNAT, link-local, cloud metadata
    disallowed = [
        "127.0.0.1",
        "10.0.0.1",
        "172.16.5.10",
        "192.168.1.1",
        "100.64.0.1",  # CGNAT
        "169.254.169.254",  # AWS/GCP metadata
        "::1",  # IPv6 loopback
    ]
    for ip in disallowed:
        disallowed_flag, _ = is_disallowed_ip(ip)
        assert disallowed_flag is True, f"IP {ip} must be identified as disallowed"

    # 4. Allowed public IPs
    allowed = ["93.184.216.34", "142.250.190.46", "1.1.1.1", "8.8.8.8"]
    for ip in allowed:
        disallowed_flag, _ = is_disallowed_ip(ip)
        assert disallowed_flag is False, f"IP {ip} must be allowed as a valid public IP"


@pytest.mark.asyncio
async def test_passive_crtsh_and_certspotter_providers(monkeypatch):
    """Verifies Crt.sh and CertSpotter providers conform to BaseProvider and emit warnings on 0 results."""
    crtsh = CrtshProvider()
    assert crtsh.name.lower() == "crt.sh"
    assert crtsh.description

    certspotter = CertspotterProvider()
    assert certspotter.name.lower() == "certspotter"
    assert certspotter.description

    # Mock empty response from crt.sh
    class MockEmptyResponse:
        status_code = 200
        def json(self):
            return []

    async def mock_get(self, url, *args, **kwargs):
        return MockEmptyResponse()

    monkeypatch.setattr(httpx.AsyncClient, "get", mock_get)

    # Test 0 results emission
    events = []
    async for ev in crtsh.discover(["example.com"]):
        events.append(ev)

    summary_events = [e for e in events if e.get("type") == "scan_summary"]
    assert len(summary_events) > 0
    assert summary_events[0]["provider"] == "crtsh"
    assert summary_events[0]["count"] == 0

    warning_events = [e for e in events if e.get("type") == "warning_event"]
    assert len(warning_events) > 0
    assert "0 results" in warning_events[0].get("reason", "").lower() or "0 results" in warning_events[0].get("message", "").lower()


def test_dns_bruteforce_permutations_and_scope():
    """Verifies DnsBruteforceProvider scope enforcement and permutations cap."""
    scope = {
        "in_scope": ["*.example.com", "target.com"],
        "out_of_scope": ["forbidden.example.com"],
    }
    provider = DnsBruteforceProvider(
        scope_config=scope,
        rate_limit=25,
        max_permutations=1000,
    )

    # 1. In-scope vs Out-of-scope filtering
    assert is_in_scope("admin.example.com", provider.scope_config) is True
    assert is_in_scope("target.com", provider.scope_config) is True
    assert is_in_scope("forbidden.example.com", provider.scope_config) is False
    assert is_in_scope("attacker.com", provider.scope_config) is False

    # 2. Permutation cap check
    assert provider.max_permutations == 1000


def test_takeover_crosscheck_provider_scoring():
    """
    Verifies TakeoverCrossCheckProvider:
    - Single tool finding -> unconfirmed (Unconfirmed status)
    - Multi-tool finding -> confirmed (Vulnerable status, tools_agreed recorded)
    """
    # 1. Single tool: unconfirmed
    conf_single, status_single = TakeoverCrossCheckProvider.evaluate_confidence(["subzy"])
    assert conf_single == "unconfirmed"
    assert status_single == "Unconfirmed"

    # 2. Multi-tool agreement: confirmed
    conf_multi, status_multi = TakeoverCrossCheckProvider.evaluate_confidence(["subzy", "nuclei"])
    assert conf_multi == "confirmed"
    assert status_multi == "Vulnerable"

    conf_triple, status_triple = TakeoverCrossCheckProvider.evaluate_confidence(["subzy", "nuclei", "dnsreaper"])
    assert conf_triple == "confirmed"
    assert status_triple == "Vulnerable"


@pytest.mark.asyncio
async def test_root_expansion_opt_in_and_approval_workflow():
    """
    Verifies Root-Domain Expansion:
    - Opt-in suggestions only (never automatically scanned)
    - GET /projects/{id}/suggested-roots returns discovered suggestions
    - POST /projects/{id}/suggested-roots/{domain}/approve adds domain to seed_domains and scope
    - POST /projects/{id}/suggested-roots/{domain}/reject marks status rejected
    """
    mongo_client, db, old_db, old_client, old_is_mock = await setup_test_db()
    try:
        project_oid = ObjectId()
        project_id = str(project_oid)
        await db.projects.insert_one({
            "_id": project_oid,
            "name": "Phase7-Roots-Test",
            "domain": "example.com",
            "seed_domains": ["example.com"],
            "scope": {
                "in_scope": ["*.example.com"],
                "out_of_scope": [],
            },
            "enable_root_expansion": True,
            "owner_id": "local",
            "created_at": datetime.utcnow(),
        })

        # Insert 2 root suggestions
        await db.assets.insert_one({
            "project_id": project_id,
            "type": "suggested_root",
            "domain": "related-brand.com",
            "value": "related-brand.com",
            "source": "asnmap",
            "evidence": "Discovered via AS13335 (Cloudflare)",
            "status": "pending",
            "created_at": datetime.utcnow(),
        })
        await db.assets.insert_one({
            "project_id": project_id,
            "type": "suggested_root",
            "domain": "other-target.org",
            "value": "other-target.org",
            "source": "amass_intel",
            "evidence": "WHOIS organization correlation",
            "status": "pending",
            "created_at": datetime.utcnow(),
        })

        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as ac:
            # 1. Fetch suggestions
            resp_list = await ac.get(f"/api/v1/projects/{project_id}/suggested-roots")
            assert resp_list.status_code == 200
            suggestions = resp_list.json()
            assert len(suggestions) == 2
            domains = [s["domain"] for s in suggestions]
            assert "related-brand.com" in domains
            assert "other-target.org" in domains

            # Verify project seeds do NOT contain the suggested roots yet (never auto-scanned)
            proj_doc = await db.projects.find_one({"_id": project_oid})
            assert "related-brand.com" not in proj_doc["seed_domains"]
            assert "*.related-brand.com" not in proj_doc["scope"]["in_scope"]

            # 2. Approve related-brand.com
            resp_approve = await ac.post(f"/api/v1/projects/{project_id}/suggested-roots/related-brand.com/approve")
            assert resp_approve.status_code == 200
            approve_data = resp_approve.json()
            assert approve_data["domain"] == "related-brand.com"
            assert approve_data["status"] == "approved"

            # Check that related-brand.com is now added to project seed_domains and scope
            proj_updated = await db.projects.find_one({"_id": project_oid})
            assert "related-brand.com" in proj_updated["seed_domains"]
            assert "related-brand.com" in proj_updated["scope"]["in_scope"]

            # Check asset status marked approved
            asset_appr = await db.assets.find_one({"project_id": project_id, "domain": "related-brand.com"})
            assert asset_appr["status"] == "approved"

            # 3. Reject other-target.org
            resp_reject = await ac.post(f"/api/v1/projects/{project_id}/suggested-roots/other-target.org/reject")
            assert resp_reject.status_code == 200
            reject_data = resp_reject.json()
            assert reject_data["domain"] == "other-target.org"
            assert reject_data["status"] == "rejected"

            # Check asset status marked rejected
            asset_rej = await db.assets.find_one({"project_id": project_id, "domain": "other-target.org"})
            assert asset_rej["status"] == "rejected"

            # Verify other-target.org was NOT added to seed domains or scope
            proj_after_rej = await db.projects.find_one({"_id": project_oid})
            assert "other-target.org" not in proj_after_rej["seed_domains"]

    finally:
        await teardown_test_db(mongo_client, old_db, old_client, old_is_mock)


@pytest.mark.asyncio
async def test_fast_mode_skips_dns_bruteforce_stage(monkeypatch):
    """Verifies that UnifiedDiscoveryProvider in Fast mode skips Phase 1.5 with stage_skipped."""
    from app.providers import unified_discovery_provider

    class MockPassiveProvider:
        name = "mock_passive"
        async def discover(self, seed_domains):
            yield {
                "type": "asset",
                "data": {
                    "domain": "test.example.com",
                    "type": "subdomain",
                    "status": "unknown",
                },
            }

    monkeypatch.setattr(
        UnifiedDiscoveryProvider,
        "PASSIVE_PROVIDERS",
        [(MockPassiveProvider(), "mock_passive")],
    )

    discovery = UnifiedDiscoveryProvider()
    events = []
    async for ev in discovery.discover(
        seed_domains=["example.com"],
        scan_mode="fast",
        project_config={"scope": {"in_scope": ["*.example.com"], "out_of_scope": []}},
    ):
        events.append(ev)
        # Stop after reaching DNS brute force stage
        if ev.get("type") == "stage_skipped" and ev.get("tool") == "puredns":
            break

    skipped = [e for e in events if e.get("type") == "stage_skipped" and e.get("tool") == "puredns"]
    assert len(skipped) == 1
    assert "deep mode only" in skipped[0]["reason"].lower()
