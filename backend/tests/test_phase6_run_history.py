"""
Phase 6 + Run History and Local Mode Security Test Suite
=========================================================
Tests:
- Run history persistence (scan_runs and run_assets) on real MongoDB
- Run comparison (added/removed/retained per type)
- Raw tool outputs gzip compression, reading, and path traversal rejection
- Risk scoring severity floors, category caps, diminishing returns, and 0 findings
- Hunt-priority score calculation, factor capping, and independence from risk
- Single-user local mode: DNS-rebinding Host check and Origin enforcement
- Harmless auth stubs
"""

import gzip
import os
import shutil
import pytest
from datetime import datetime, timedelta
from bson import ObjectId
from fastapi.testclient import TestClient

from app.database import get_database, connect_to_mongo, close_mongo_connection, db_helper
from app.services.run_history import (
    record_run_history,
    record_run_asset,
    compare_runs,
    save_raw_tool_output,
    read_raw_tool_output,
    RUNS_BASE_DIR,
)
from app.services.risk_scoring import (
    calculate_risk_score,
    compute_host_risk_and_hunt,
    load_hunt_weights,
    load_weights,
)
from app.main import app

REAL_MONGO_TEST_URI = os.getenv("MONGODB_URL", "mongodb://127.0.0.1:27017")
TEST_DB_NAME = "reconforge_phase6_test_db"


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
    client.close()
    db_helper.db = old_db
    db_helper.client = old_client
    db_helper.is_mock = old_is_mock


# ==============================================================================
# Part A: Run History Tests
# ==============================================================================

@pytest.mark.asyncio
async def test_run_history_record_and_query_on_real_mongo():
    client, db, old_db, old_client, old_is_mock = await setup_test_db()
    try:
        project_id = str(ObjectId())
        job_id = str(ObjectId())

        # 1. Seed project with custom headers
        await db.projects.insert_one({
            "_id": ObjectId(project_id),
            "name": "Phase6 Test Project",
            "seed_domains": ["target.example.com"],
            "scope": {"in_scope": ["*.example.com"], "out_of_scope": ["out.example.com"]},
            "rate_limits": {"global_rps": 15},
            "custom_headers": {"X-Bug-Bounty": "secret_token_123", "Authorization": "Bearer secret_jwt"},
            "scan_profile": "deep",
            "owner_id": "local",
        })

        # 2. Seed completed job
        t_start = datetime.utcnow() - timedelta(seconds=45)
        t_finish = datetime.utcnow()
        await db.jobs.insert_one({
            "_id": ObjectId(job_id),
            "project_id": project_id,
            "status": "completed",
            "scan_mode": "deep",
            "started_at": t_start,
            "finished_at": t_finish,
            "logs": ["[*] Scan started", "[√] Scan completed"],
        })

        # 3. Seed some assets for this project & job
        await db.assets.insert_many([
            {"project_id": project_id, "type": "subdomain", "value": "sub1.example.com", "domain": "sub1.example.com"},
            {"project_id": project_id, "type": "subdomain", "value": "sub2.example.com", "domain": "sub2.example.com"},
            {"project_id": project_id, "type": "live_host", "value": "https://sub1.example.com", "domain": "sub1.example.com", "status": "live"},
            {"project_id": project_id, "type": "port", "value": "sub1.example.com:443", "domain": "sub1.example.com"},
            {"project_id": project_id, "type": "url", "value": "https://sub1.example.com/api/v1/test", "domain": "sub1.example.com", "discovered_by": "katana"},
        ])

        # Record assets in run_assets
        await record_run_asset(db, project_id, job_id, "subdomain", "sub1.example.com", domain="sub1.example.com")
        await record_run_asset(db, project_id, job_id, "subdomain", "sub2.example.com", domain="sub2.example.com")
        await record_run_asset(db, project_id, job_id, "live_host", "https://sub1.example.com", domain="sub1.example.com", status="live")

        stage_markers = [
            {"stage": "passive_recon", "status": "completed", "reason": "Gathered 2 subdomains"},
            {"stage": "nuclei", "status": "skipped", "reason": "recon profile"},
        ]
        raw_outputs = {
            "subfinder": "sub1.example.com\nsub2.example.com\nBearer secret_jwt",
        }

        # 4. Record run history
        run_doc = await record_run_history(
            db=db,
            job_id=job_id,
            project_id=project_id,
            stage_markers=stage_markers,
            raw_outputs=raw_outputs,
        )

        assert run_doc is not None
        assert run_doc["job_id"] == job_id
        assert run_doc["project_id"] == project_id
        assert run_doc["status"] == "completed"
        assert run_doc["scan_mode"] == "deep"
        assert run_doc["duration_sec"] >= 40
        assert len(run_doc["stage_markers"]) == 2

        # Verify config snapshot has safe header names only (NEVER secret values)
        config_snap = run_doc.get("config_snapshot", {})
        header_names = config_snap.get("custom_header_names", [])
        assert "X-Bug-Bounty" in header_names
        assert "Authorization" in header_names
        # Ensure secret strings are not anywhere in config_snapshot
        assert "secret_token_123" not in str(config_snap)
        assert "secret_jwt" not in str(config_snap)

        # Verify scan_runs in MongoDB
        db_run = await db.scan_runs.find_one({"job_id": job_id})
        assert db_run is not None
        assert db_run["counts"]["subdomains"] == 2

        # Verify run_assets in MongoDB
        assets_cursor = db.run_assets.find({"job_id": job_id})
        r_assets = await assets_cursor.to_list(10)
        assert len(r_assets) == 3

    finally:
        await teardown_test_db(client, old_db, old_client, old_is_mock)


@pytest.mark.asyncio
async def test_run_comparison_added_and_removed():
    client, db, old_db, old_client, old_is_mock = await setup_test_db()
    try:
        project_id = str(ObjectId())
        job_a = str(ObjectId())
        job_b = str(ObjectId())

        # Seed run_assets for Run A
        await record_run_asset(db, project_id, job_a, "subdomain", "common.example.com")
        await record_run_asset(db, project_id, job_a, "subdomain", "old.example.com")
        await record_run_asset(db, project_id, job_a, "port", "common.example.com:80")

        # Seed run_assets for Run B
        await record_run_asset(db, project_id, job_b, "subdomain", "common.example.com")
        await record_run_asset(db, project_id, job_b, "subdomain", "new.example.com")
        await record_run_asset(db, project_id, job_b, "port", "common.example.com:443")

        # Compare Run A vs Run B
        result = await compare_runs(db, project_id, job_a, job_b)
        assert result["job_a"] == job_a
        assert result["job_b"] == job_b

        # Subdomain differences
        sub_summary = result["summary"]["subdomain"]
        assert sub_summary["added_count"] == 1
        assert sub_summary["removed_count"] == 1
        assert sub_summary["retained_count"] == 1
        assert "new.example.com" in result["added"]["subdomain"]
        assert "old.example.com" in result["removed"]["subdomain"]

        # Port differences
        port_summary = result["summary"]["port"]
        assert port_summary["added_count"] == 1
        assert port_summary["removed_count"] == 1
        assert "common.example.com:443" in result["added"]["port"]
        assert "common.example.com:80" in result["removed"]["port"]

    finally:
        await teardown_test_db(client, old_db, old_client, old_is_mock)


def test_raw_tool_output_gzip_and_path_traversal():
    project_id = "test_proj_123"
    job_id = "test_job_456"
    tool_name = "subfinder"
    raw_content = "sub1.example.com\nsub2.example.com\napi.example.com\nBearer super_secret_token"

    # 1. Save raw tool output (with redaction)
    file_path = save_raw_tool_output(project_id, job_id, tool_name, raw_content)
    assert file_path is not None
    assert os.path.exists(file_path)
    assert file_path.endswith(".txt.gz")

    try:
        # Read raw tool output
        decompressed = read_raw_tool_output(project_id, job_id, tool_name)
        assert decompressed is not None
        assert "sub1.example.com" in decompressed
        # Verify secret token was redacted
        assert "super_secret_token" not in decompressed
        assert "[REDACTED]" in decompressed

        # 2. Path traversal attempts must return None
        assert read_raw_tool_output("../etc", job_id, tool_name) is None
        assert read_raw_tool_output(project_id, "../../etc", tool_name) is None
        assert read_raw_tool_output(project_id, job_id, "../../passwd") is None
        assert read_raw_tool_output(project_id, job_id, "tool/../secret") is None

    finally:
        # Clean up created storage
        proj_dir = os.path.join(RUNS_BASE_DIR, project_id)
        if os.path.exists(proj_dir):
            shutil.rmtree(proj_dir, ignore_errors=True)


# ==============================================================================
# Part B: Risk Scoring Fixes
# ==============================================================================

def test_risk_scoring_severity_floors_and_caps():
    weights = load_weights()
    hunt_weights = load_hunt_weights()

    # 1. Critical finding -> floor >= 90
    h_crit = {"domain": "crit.example.com", "status": "live", "open_ports": [80, 443]}
    findings_crit = [
        {"domain": "crit.example.com", "metadata": {"source": "nuclei", "severity": "critical", "template_id": "cve-2024-9999"}}
    ]
    risk_crit, _, _ = compute_host_risk_and_hunt(h_crit, findings_crit, [], set(), weights, hunt_weights)
    assert risk_crit["score"] >= 90
    assert risk_crit["level"] == "Critical"

    # 2. High finding -> floor >= 70
    h_high = {"domain": "high.example.com", "status": "live", "open_ports": [80]}
    findings_high = [
        {"domain": "high.example.com", "metadata": {"source": "nuclei", "severity": "high", "template_id": "cve-2024-1111"}}
    ]
    risk_high, _, _ = compute_host_risk_and_hunt(h_high, findings_high, [], set(), weights, hunt_weights)
    assert risk_high["score"] >= 70
    assert risk_high["level"] == "High"

    # 3. Diminishing returns: 10 repeated findings with same template_id
    h_dup = {"domain": "dup.example.com", "status": "live", "open_ports": [80]}
    findings_dup = [
        {"domain": "dup.example.com", "metadata": {"source": "nuclei", "severity": "medium", "template_id": "xss-reflected"}}
        for _ in range(10)
    ]
    risk_dup, _, _ = compute_host_risk_and_hunt(h_dup, findings_dup, [], set(), weights, hunt_weights)
    # 10 medium findings with decay (0.5^count) & category caps should not overflow to 100
    assert risk_dup["score"] < 80

    # 4. Zero findings case (e.g. recon profile)
    h_zero = {"domain": "recon.example.com", "status": "live", "open_ports": [80, 443]}
    risk_zero, _, _ = compute_host_risk_and_hunt(h_zero, [], [], set(), weights, hunt_weights)
    assert risk_zero["score"] < 40
    assert risk_zero["level"] in ("Low", "Info", "Informational")


def test_hunt_priority_calculation_and_independence_from_risk():
    weights = load_weights()
    hunt_weights = load_hunt_weights()

    host_doc = {
        "domain": "dev-admin-api.internal.example.com",
        "status": "live",
        "status_code": 401,
        "is_interesting": True,
        "open_ports": [80, 443],
        "metadata": {
            "status_code": 401,
            "technologies": ["Spring Boot", "GraphQL"],
            "katana": {
                "endpoints": ["/api/v1/users", "/graphql"],
                "js_files": ["https://dev-admin-api.internal.example.com/main.js"],
            },
        },
    }

    # Zero vulnerability findings (recon mode), but host is new and has high interest factors
    risk_info, hunt_prio, hunt_reasons = compute_host_risk_and_hunt(
        host_doc,
        asset_findings=[],
        all_project_assets=[
            {"project_id": "p1", "type": "content_path", "domain": "dev-admin-api.internal.example.com", "metadata": {"status_code": 401}},
            {"project_id": "p1", "type": "url", "domain": "dev-admin-api.internal.example.com", "metadata": {"url": "https://dev-admin-api.internal.example.com/test?id=1&name=2"}},
        ],
        new_or_changed_set={"dev-admin-api.internal.example.com"},
        weights=weights,
        hunt_weights=hunt_weights,
    )

    # Risk score should be low because zero vulnerabilities were detected
    assert risk_info["score"] <= 35

    # BUT hunt priority should be high due to sensitive naming, 401, GraphQL, new host, parameters
    assert hunt_prio >= 50, f"Expected hunt_priority >= 50, got {hunt_prio}"
    assert len(hunt_reasons) >= 3
    reasons_str = " ".join(hunt_reasons)
    assert "401" in reasons_str or "Sensitive naming" in reasons_str or "New/changed" in reasons_str


# ==============================================================================
# Security & Single-User Local Mode Tests
# ==============================================================================

def test_security_guard_middleware_dns_rebinding_and_origin():
    client = TestClient(app)

    # 1. Valid local Host header -> 200 OK
    resp_valid = client.get("/", headers={"Host": "127.0.0.1:8000"})
    assert resp_valid.status_code == 200

    resp_localhost = client.get("/", headers={"Host": "localhost:8000"})
    assert resp_localhost.status_code == 200

    # 2. DNS-rebinding attempt with external Host header -> 400 Bad Request
    resp_evil_host = client.get("/", headers={"Host": "attacker.evil.com"})
    assert resp_evil_host.status_code == 400
    assert "DNS-rebinding protection" in resp_evil_host.text

    # 3. State-changing request with forbidden Origin -> 403 Forbidden
    resp_evil_origin = client.post(
        "/api/v1/auth/login",
        headers={"Host": "127.0.0.1:8000", "Origin": "http://evil-attacker.com"}
    )
    assert resp_evil_origin.status_code == 403
    assert "Forbidden Origin" in resp_evil_origin.text

    # 4. State-changing request with allowed Origin -> passes through security guard
    resp_good_origin = client.post(
        "/api/v1/auth/login",
        headers={"Host": "127.0.0.1:8000", "Origin": "http://localhost:5173"}
    )
    assert resp_good_origin.status_code == 200


def test_auth_harmless_stubs_never_401():
    client = TestClient(app)

    # /api/v1/auth/me returns local user and never 401
    resp_me = client.get("/api/v1/auth/me")
    assert resp_me.status_code == 200
    data_me = resp_me.json()
    assert data_me["username"] == "local"
    assert data_me["id"] == "local"

    # /api/v1/auth/login returns local token
    resp_login = client.post("/api/v1/auth/login")
    assert resp_login.status_code == 200
    data_login = resp_login.json()
    assert data_login["access_token"] == "local-token"

    # /api/v1/auth/register returns local user
    resp_reg = client.post("/api/v1/auth/register", json={"username": "tester"})
    assert resp_reg.status_code == 200
    data_reg = resp_reg.json()
    assert data_reg["id"] == "local"
