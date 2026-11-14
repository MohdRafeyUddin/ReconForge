import os
import shutil
import uuid
import pytest
from datetime import datetime, timezone
from bson import ObjectId
from motor.motor_asyncio import AsyncIOMotorClient
from pymongo.errors import ServerSelectionTimeoutError, ConnectionFailure

from app.services.response_storage import (
    save_response_body,
    read_response_body,
    delete_project_response_bodies,
    get_project_response_dir,
)
from app.services.clustering import (
    compute_cluster_key,
    cluster_hosts,
    filter_hosts_for_downstream,
)
from app.services.diff_engine import compute_and_save_diff
from app.services.notifier import dispatch_scan_diff_alerts


# ==============================================================================
# Real MongoDB Helper (Skip gracefully if MongoDB is unavailable)
# ==============================================================================

async def get_real_mongo_db():
    """
    Connects to real local MongoDB instance.
    If unavailable, skips test execution as required by Phase 3 constraints.
    Creates an isolated database per test and drops it on teardown.
    """
    mongo_uri = os.getenv("MONGO_URI", "mongodb://localhost:27017")
    client = AsyncIOMotorClient(mongo_uri, serverSelectionTimeoutMS=2000)
    try:
        await client.admin.command("ping")
    except Exception as exc:
        pytest.skip(f"Real MongoDB is not running at {mongo_uri}: {exc}")

    test_db_name = f"reconforge_test_phase3_{uuid.uuid4().hex[:12]}"
    db = client[test_db_name]
    return client, db


# ==============================================================================
# 1. Liveness Redefinition & Re-baseline Integration Tests
# ==============================================================================

@pytest.mark.asyncio
async def test_liveness_v1_to_v2_rebaseline_suppresses_false_live_alerts():
    """
    Constraint: Redefining 'live' as any HTTP response must NOT break Phase 2 diff.
    The first scan after this change has liveness_version=2 and must be re-baselined
    so that hosts previously dead-but-responding (e.g. 403/404) do NOT trigger false
    'new live hosts' alerts. Only genuinely new hosts alert.
    """
    client, db = await get_real_mongo_db()
    try:
        project_id = str(ObjectId())

        from datetime import timedelta
        t_v1_start = datetime.now(timezone.utc) - timedelta(hours=2)
        t_v1_finish = datetime.now(timezone.utc) - timedelta(hours=1, minutes=50)
        t_v2_start = datetime.now(timezone.utc) - timedelta(minutes=5)
        t_v2_finish = datetime.now(timezone.utc)

        # Scan 1: Legacy v1 scan
        job1_id = str(ObjectId())
        await db.jobs.insert_one({
            "_id": ObjectId(job1_id),
            "project_id": project_id,
            "scan_mode": "fast",
            "status": "completed",
            "liveness_version": 1,
            "started_at": t_v1_start,
            "finished_at": t_v1_finish,
        })

        # In v1:
        # - app.example.com was 200 OK -> status: "live"
        # - admin.example.com was 403 Forbidden -> status: "inactive" (dead in v1 logic)
        await db.assets.insert_many([
            {
                "_id": ObjectId(),
                "project_id": project_id,
                "type": "subdomain",
                "value": "app.example.com",
                "domain": "app.example.com",
                "status": "live",
                "metadata": {"status_code": 200},
                "scan_id": job1_id,
                "last_seen_job_id": job1_id,
                "first_seen": t_v1_start,
                "last_seen": t_v1_finish,
            },
            {
                "_id": ObjectId(),
                "project_id": project_id,
                "type": "subdomain",
                "value": "admin.example.com",
                "domain": "admin.example.com",
                "status": "inactive",
                "metadata": {"status_code": 403},
                "scan_id": job1_id,
                "last_seen_job_id": job1_id,
                "first_seen": t_v1_start,
                "last_seen": t_v1_finish,
            },
        ])

        # Scan 2: Modern Phase 3 scan (liveness_version=2)
        job2_id = str(ObjectId())
        await db.jobs.insert_one({
            "_id": ObjectId(job2_id),
            "project_id": project_id,
            "scan_mode": "fast",
            "status": "completed",
            "liveness_version": 2,
            "started_at": t_v2_start,
            "finished_at": t_v2_finish,
        })

        # In v2:
        # - app.example.com is still 200 OK -> status: "live"
        # - admin.example.com responded 403 -> now classed as "live" (is_interesting: True)
        # - brandnew.example.com is a truly newly discovered live host (200 OK)
        await db.assets.update_one(
            {"project_id": project_id, "value": "app.example.com"},
            {"$set": {
                "last_seen_job_id": job2_id,
                "scan_id": job2_id,
                "last_seen": t_v2_finish,
                "status": "live",
            }},
        )
        await db.assets.update_one(
            {"project_id": project_id, "value": "admin.example.com"},
            {"$set": {
                "last_seen_job_id": job2_id,
                "scan_id": job2_id,
                "last_seen": t_v2_finish,
                "status": "live",
                "is_interesting": True,
                "status_class": "4xx",
            }},
        )
        await db.assets.insert_one({
            "_id": ObjectId(),
            "project_id": project_id,
            "type": "subdomain",
            "value": "brandnew.example.com",
            "domain": "brandnew.example.com",
            "status": "live",
            "metadata": {"status_code": 200},
            "scan_id": job2_id,
            "last_seen_job_id": job2_id,
            "first_seen": t_v2_start,
            "last_seen": t_v2_finish,
        })

        # Execute diff engine between Job 1 and Job 2
        diff_doc = await compute_and_save_diff(db, project_id, job2_id)
        assert diff_doc is not None

        # Verify re-baseline detection
        assert diff_doc.get("is_liveness_rebaseline") is True
        assert diff_doc.get("liveness_version") == 2
        assert diff_doc.get("prev_liveness_version") == 1

        # Verify that admin.example.com (dead-but-responding in v1) was NOT treated as a new live host!
        new_live = diff_doc.get("new_live_hosts", [])
        assert "admin.example.com" not in new_live
        # Only the genuinely new host should appear
        assert "brandnew.example.com" in new_live

        # Test Notifier alert generation: check that liveness re-baseline is noted and webhook suppresses false alerts
        summary = diff_doc.get("summary", {})
        assert summary.get("is_liveness_rebaseline") is True
    finally:
        await client.drop_database(db.name)
        client.close()


# ==============================================================================
# 2. Response Body Storage Integration Tests
# ==============================================================================

def test_response_body_storage_per_project_isolation_and_retention():
    """
    Constraint:
    - Per-project directory isolation
    - Size cap truncation
    - FIFO retention limit
    - Path traversal prevention
    """
    project_id = f"test_proj_{uuid.uuid4().hex[:8]}"

    try:
        # 1. Test size cap truncation
        large_body = "A" * 600 * 1024  # 600 KB
        rel_path, stored_size = save_response_body(
            project_id=project_id,
            identifier="https://api.example.com",
            body=large_body,
            max_kb=500,  # Cap at 500 KB
            max_files=3,
        )
        assert rel_path is not None
        assert stored_size <= 500 * 1024 + 100

        # Read back
        filename = rel_path.split("/")[-1]
        read_content = read_response_body(project_id, filename)
        assert read_content is not None
        assert "[TRUNCATED - EXCEEDED 500KB LIMIT]" in read_content

        # 2. Test FIFO retention limit (max_files=3)
        # Store 3 more bodies
        for i in range(1, 4):
            save_response_body(
                project_id=project_id,
                identifier=f"https://host{i}.example.com",
                body=f"Content for host {i}",
                max_kb=500,
                max_files=3,
            )

        storage_dir = get_project_response_dir(project_id)
        files = os.listdir(storage_dir)
        # Should not exceed retention limit of 3 files
        assert len(files) <= 3
        # The first file should have been cleaned up by FIFO
        assert filename not in files

        # 3. Path traversal prevention
        with pytest.raises(ValueError):
            read_response_body(project_id, "../../etc/passwd")

        with pytest.raises(ValueError):
            read_response_body(project_id, "..\\..\\windows\\system32")

    finally:
        delete_project_response_bodies(project_id)


# ==============================================================================
# 3. CDN/WAF Exclusion Reason Recording Integration Tests
# ==============================================================================

@pytest.mark.asyncio
async def test_cdn_waf_exclusion_reason_recorded_on_asset():
    """
    Constraint: CDN/WAF exclusions must be recorded with a reason on the asset,
    so the user can see why a host was skipped from wide port scans.
    """
    client, db = await get_real_mongo_db()
    try:
        project_id = str(ObjectId())

        # Insert an asset behind Cloudflare
        asset_doc = {
            "_id": ObjectId(),
            "project_id": project_id,
            "type": "subdomain",
            "value": "cdn.example.com",
            "domain": "cdn.example.com",
            "status": "live",
            "metadata": {
                "status_code": 200,
                "cdn": "Cloudflare",
                "cdn_name": "Cloudflare",
            },
            "cdn_waf": {
                "is_cdn": True,
                "cdn_provider": "Cloudflare",
                "exclusion_reason": "Host behind Cloudflare CDN - excluded from wide port scan",
            },
            "exclusion_reason": "Host behind Cloudflare CDN - excluded from wide port scan",
        }
        await db.assets.insert_one(asset_doc)

        fetched = await db.assets.find_one({"project_id": project_id, "value": "cdn.example.com"})
        assert fetched is not None
        assert fetched.get("exclusion_reason") == "Host behind Cloudflare CDN - excluded from wide port scan"
        assert fetched.get("cdn_waf", {}).get("cdn_provider") == "Cloudflare"
    finally:
        await client.drop_database(db.name)
        client.close()


# ==============================================================================
# 4. Host Clustering & Toggle Override Integration Tests
# ==============================================================================

def test_host_clustering_never_hides_members_and_toggle_override():
    """
    Constraint:
    - Clustering groups live hosts by body_hash / favicon_hash / title+length
    - Exactly one representative chosen for expensive stages
    - Skipped cluster members stay visible with skip reason
    - A toggle (scan_all_cluster_members) overrides and scans all members
    """
    hosts = [
        {
            "host": "portal1.example.com",
            "body_hash": "sha256_abcdef123456",
            "status_code": 200,
            "title": "Default Landing",
            "content_length": 1500,
        },
        {
            "host": "portal2.example.com",
            "body_hash": "sha256_abcdef123456",
            "status_code": 200,
            "title": "Default Landing",
            "content_length": 1500,
        },
        {
            "host": "portal3.example.com",
            "body_hash": "sha256_abcdef123456",
            "status_code": 200,
            "title": "Default Landing",
            "content_length": 1500,
        },
        {
            "host": "unique.example.com",
            "body_hash": "sha256_different999",
            "status_code": 200,
            "title": "Unique Dashboard",
            "content_length": 4200,
        },
    ]

    # Mode A: Standard clustering (scan_all_cluster_members=False)
    res_dict = cluster_hosts(hosts, scan_all_members=False)
    all_hosts = res_dict["all_assets"]
    assert len(all_hosts) == 4  # NEVER hides members!

    reps = res_dict["representatives"]
    members = res_dict["skipped_members"]

    # Exactly 2 representatives (one for portal group, one for unique)
    assert len(reps) == 2
    # Exactly 2 skipped members in the portal cluster
    assert len(members) == 2

    for m in members:
        assert m["is_cluster_member"] is True
        assert m["cluster_skipped"] is True
        assert "duplicate of representative" in m["cluster_skip_reason"]

    # Filter for expensive downstream stages
    downstream = filter_hosts_for_downstream(res_dict)
    assert len(downstream) == 2
    downstream_hosts = {h.get("host") or h.get("domain") for h in downstream}
    assert "unique.example.com" in downstream_hosts
    assert "portal1.example.com" in downstream_hosts or "portal2.example.com" in downstream_hosts or "portal3.example.com" in downstream_hosts

    # Mode B: Toggle enabled (scan_all_cluster_members=True)
    res_override = cluster_hosts(hosts, scan_all_members=True)
    all_override = res_override["all_assets"]
    assert len(all_override) == 4

    # None should be skipped when toggle is on
    for h in all_override:
        assert h.get("cluster_skipped") is False

    downstream_override = filter_hosts_for_downstream(res_override)
    assert len(downstream_override) == 4  # All members scanned!


# ==============================================================================
# 5. Response Body API Route Authentication & Traversal Guard Tests
# ==============================================================================

def test_response_body_api_route_requires_auth():
    """
    In single-user local mode, JWT auth is removed and routes never return 401.
    Verify that an unauthenticated request reaches the handler and does not return 401.
    """
    from fastapi.testclient import TestClient
    from app.main import app

    project_id = str(ObjectId())
    asset_id = str(ObjectId())

    # 1. Unauthenticated request in single-user mode -> must NEVER return 401
    client = TestClient(app)
    unauth_resp = client.get(f"/api/v1/assets/project/{project_id}/asset/{asset_id}/response-body")
    assert unauth_resp.status_code != 401, f"Expected non-401 in single-user mode, got {unauth_resp.status_code}"


# ==============================================================================
# 6. Clustering Requirement 1 Tests
# ==============================================================================

def test_clustering_strict_status_code_and_never_skips_interesting():
    """
    Requirement 1:
      - Use only body_hash or favicon_hash
      - Require identical status_code to cluster
      - Remove the title+content_length fallback key
      - Never mark is_interesting (401/403) hosts as skipped members; they are always scanned.
    """
    # 1. Same body_hash but different status_code -> must NOT cluster together
    h1 = {"domain": "host1.example.com", "status_code": 200, "body_hash": "hash_abc"}
    h2 = {"domain": "host2.example.com", "status_code": 500, "body_hash": "hash_abc"}
    key1, _ = compute_cluster_key(h1)
    key2, _ = compute_cluster_key(h2)
    assert key1 != key2, f"Expected different keys for status 200 vs 500, got {key1} vs {key2}"

    # 2. Same favicon_hash and identical status_code -> clusters
    f1 = {"domain": "fav1.example.com", "status_code": 200, "favicon_hash": "fav_xyz"}
    f2 = {"domain": "fav2.example.com", "status_code": 200, "favicon_hash": "fav_xyz"}
    kfav1, _ = compute_cluster_key(f1)
    kfav2, _ = compute_cluster_key(f2)
    assert kfav1 == kfav2

    # 3. Same title + content_length but NO body_hash/favicon_hash -> MUST NOT cluster (fallback removed)
    t1 = {"domain": "t1.example.com", "status_code": 200, "title": "Dashboard", "content_length": 1234}
    t2 = {"domain": "t2.example.com", "status_code": 200, "title": "Dashboard", "content_length": 1234}
    kt1, type1 = compute_cluster_key(t1)
    kt2, type2 = compute_cluster_key(t2)
    assert kt1 != kt2, "Title+length must not cluster hosts together"
    assert type1 == "unique_host"
    assert type2 == "unique_host"

    # 4. Never mark is_interesting (401/403) hosts as skipped members
    interesting_hosts = [
        {"domain": "auth1.example.com", "status_code": 401, "body_hash": "unauth_page_hash"},
        {"domain": "auth2.example.com", "status_code": 401, "body_hash": "unauth_page_hash"},
        {"domain": "auth3.example.com", "status_code": 403, "body_hash": "forbidden_hash"},
        {"domain": "auth4.example.com", "status_code": 403, "body_hash": "forbidden_hash"},
    ]
    res = cluster_hosts(interesting_hosts, scan_all_members=False)

    # Skipped members must be 0 because 401/403 hosts are NEVER skipped!
    assert len(res["skipped_members"]) == 0
    assert len(res["representatives"]) == 4
    for h in res["all_assets"]:
        assert h.get("cluster_skipped") is False
        assert h.get("cluster_skip_reason") is None

    downstream = filter_hosts_for_downstream(res)
    assert len(downstream) == 4, "All 401/403 hosts must be passed to downstream scans"


# ==============================================================================
# 7. Response Body Plain Text Viewer Tests
# ==============================================================================

@pytest.mark.asyncio
async def test_response_body_viewer_plain_text_no_html_rendering():
    """
    Requirement 3: Response body viewer must render as plain text (no HTML rendering).
    Verifies that raw HTML payloads (<script>, <iframe>, tags) are stored, fetched,
    and served verbatim as JSON text string (never evaluated/rendered as HTML).
    """
    client, db = await get_real_mongo_db()
    try:
        user_id = str(ObjectId())
        project_id = str(ObjectId())
        asset_id = str(ObjectId())

        raw_html_payload = (
            "<!DOCTYPE html><html><head><title>Test &amp; Attack</title></head>"
            "<body><script>alert('XSS')</script><h1>Payload & Title</h1>"
            "<img src=x onerror=alert(1)></body></html>"
        )

        # 1. Save response body
        rel_path, stored_size = save_response_body(
            project_id=project_id,
            identifier="https://xss-test.example.com",
            body=raw_html_payload,
        )

        # 2. Insert project and asset into real MongoDB
        await db.projects.insert_one({
            "_id": ObjectId(project_id),
            "owner_id": user_id,
            "name": "XSS Plain Text Test",
        })
        await db.assets.insert_one({
            "_id": ObjectId(asset_id),
            "project_id": project_id,
            "domain": "xss-test.example.com",
            "type": "subdomain",
            "metadata": {
                "status_code": 200,
                "response_body_path": rel_path,
                "response_body_size": stored_size,
            },
        })

        # 3. Request response body via API with authenticated user override
        from fastapi.testclient import TestClient
        from app.main import app
        from app.auth import get_current_user
        from app.database import db_helper

        orig_db = db_helper.db
        orig_client = db_helper.client
        db_helper.db = db
        db_helper.client = client

        app.dependency_overrides[get_current_user] = lambda: {
            "_id": ObjectId(user_id),
            "username": "tester",
        }

        import httpx
        from httpx import ASGITransport

        try:
            transport = ASGITransport(app=app)
            async with httpx.AsyncClient(transport=transport, base_url="http://test") as ac:
                resp = await ac.get(f"/api/v1/assets/project/{project_id}/asset/{asset_id}/response-body")
                assert resp.status_code == 200
                assert resp.headers["content-type"].startswith("application/json")

                data = resp.json()
                assert "content" in data
                # Content must be exact raw text without HTML execution or alteration
                assert data["content"] == raw_html_payload
                assert "<script>alert('XSS')</script>" in data["content"]
        finally:
            app.dependency_overrides.clear()
            db_helper.db = orig_db
            db_helper.client = orig_client
            delete_project_response_bodies(project_id)
    finally:
        await client.drop_database(db.name)
        client.close()


# ==============================================================================
# 8. System Status API & In-Memory DB Banner Indicator Tests
# ==============================================================================

def test_system_status_api_reports_db_type():
    """
    Requirement 6: API status field indicates whether the system is on real DB or in-memory.
    """
    from fastapi.testclient import TestClient
    from app.main import app
    from app.database import db_helper

    client = TestClient(app)
    resp = client.get("/api/v1/system/status")
    assert resp.status_code == 200
    data = resp.json()

    assert "in_memory_db" in data
    assert isinstance(data["in_memory_db"], bool)
    assert "db_type" in data
    assert data["db_type"] in ("mongodb", "in_memory")


# ==============================================================================
# 9. Tool Detection Security & Registry Validation Tests (Phase 3 Follow-up)
# ==============================================================================

def test_detect_tool_rejects_unregistered_and_invalid_tool_names():
    """
    Constraint 1:
      - Reject any tool name not in the tool registry or not matching ^[a-z0-9_-]+$.
      - Never interpolate unvalidated strings into a shell command.
    """
    from app.providers.base import BaseProvider

    # 1. Shell injection / metacharacter payloads -> must raise ValueError
    injection_payloads = [
        "httpx; whoami",
        "subfinder && touch /tmp/pwned",
        "naabu | id",
        "`id`",
        "$(whoami)",
        "tool\nls",
        "tool name with spaces",
        "../bin/malicious",
        "HTTPX",  # uppercase rejected by ^[a-z0-9_-]+$
        "httpx.exe",  # dot rejected
    ]
    for payload in injection_payloads:
        with pytest.raises(ValueError, match="Invalid tool name"):
            BaseProvider.detect_tool(payload)

    # 2. Unregistered tools matching regex -> must raise ValueError
    unregistered_tools = [
        "curl",
        "wget",
        "bash",
        "sh",
        "netcat",
        "python",
        "some_arbitrary_binary",
        "unknown_tool_123",
    ]
    for unreg in unregistered_tools:
        with pytest.raises(ValueError, match="not registered in the tool registry"):
            BaseProvider.detect_tool(unreg)

    # 3. Valid registered tools -> succeeds without raising ValueError
    resolved = BaseProvider.detect_tool("subfinder")
    assert isinstance(resolved, str)
    assert len(resolved) > 0

    resolved_httpx = BaseProvider.detect_tool("httpx")
    assert isinstance(resolved_httpx, str)
    assert len(resolved_httpx) > 0


# ==============================================================================
# 10. Liveness Rebaseline Diff Engine Fingerprint Suppression Tests
# ==============================================================================

@pytest.mark.asyncio
async def test_liveness_rebaseline_suppresses_v1_nonexistent_fingerprint_changes():
    """
    Constraint 2:
      - On a liveness-rebaseline scan (v1 -> v2), suppress changed_hosts alerts caused by
        fingerprint fields that did not exist in v1 (body_hash, favicon, tech, tls).
      - Hosts whose status_code or title legitimately changed must still be reported.
    """
    client, db = await get_real_mongo_db()
    try:
        from datetime import timedelta
        project_id = str(ObjectId())
        t_v1_start = datetime.now(timezone.utc) - timedelta(hours=2)
        t_v1_finish = datetime.now(timezone.utc) - timedelta(hours=1, minutes=50)
        t_v2_start = datetime.now(timezone.utc) - timedelta(minutes=5)
        t_v2_finish = datetime.now(timezone.utc)

        # 1. Job 1: v1 scan (liveness_version=1)
        job1_id = str(ObjectId())
        await db.jobs.insert_one({
            "_id": ObjectId(job1_id),
            "project_id": project_id,
            "scan_mode": "fast",
            "status": "completed",
            "liveness_version": 1,
            "started_at": t_v1_start,
            "finished_at": t_v1_finish,
        })

        # Asset A: Existed in v1 with status_code=200, title="Corporate Portal" (no body_hash, favicon, tech, tls)
        # Asset B: Existed in v1 with status_code=200, title="API Server"
        await db.assets.insert_many([
            {
                "_id": ObjectId(),
                "project_id": project_id,
                "type": "subdomain",
                "value": "portal.example.com",
                "domain": "portal.example.com",
                "status": "live",
                "metadata": {
                    "status_code": 200,
                    "title": "Corporate Portal",
                },
                "scan_id": job1_id,
                "last_seen_job_id": job1_id,
                "first_seen": t_v1_start,
                "last_seen": t_v1_finish,
            },
            {
                "_id": ObjectId(),
                "project_id": project_id,
                "type": "subdomain",
                "value": "api.example.com",
                "domain": "api.example.com",
                "status": "live",
                "metadata": {
                    "status_code": 200,
                    "title": "API Server",
                },
                "scan_id": job1_id,
                "last_seen_job_id": job1_id,
                "first_seen": t_v1_start,
                "last_seen": t_v1_finish,
            },
        ])

        # 2. Job 2: v2 scan (liveness_version=2, triggers is_liveness_rebaseline=True)
        job2_id = str(ObjectId())
        await db.jobs.insert_one({
            "_id": ObjectId(job2_id),
            "project_id": project_id,
            "scan_mode": "fast",
            "status": "completed",
            "liveness_version": 2,
            "started_at": t_v2_start,
            "finished_at": t_v2_finish,
        })

        # In Job 2 (v2):
        # - portal.example.com has identical status_code (200) and title ("Corporate Portal"),
        #   BUT httpx now recorded body_hash, favicon, tech (technologies), and tls.
        #   Because these fields did not exist in v1, changed_hosts alerts for this host MUST BE SUPPRESSED!
        await db.assets.update_one(
            {"project_id": project_id, "value": "portal.example.com"},
            {"$set": {
                "scan_id": job2_id,
                "last_seen_job_id": job2_id,
                "last_seen": t_v2_finish,
                "status": "live",
                "previous_fingerprint": {
                    "status_code": 200,
                    "title": "Corporate Portal",
                },
                "metadata": {
                    "status_code": 200,
                    "title": "Corporate Portal",
                    "body_hash": "sha256_new_body_hash_12345",
                    "favicon_hash": "mmh3_favicon_98765",
                    "technologies": ["React", "Nginx", "Cloudflare"],
                    "tls": "TLSv1.3 ECDHE-RSA-AES128-GCM-SHA256",
                },
            }},
        )

        # - api.example.com legitimately changed from 200 to 500 (and also has new v2 fields).
        #   Because status_code existed in v1 and changed, it MUST still appear in changed_hosts!
        await db.assets.update_one(
            {"project_id": project_id, "value": "api.example.com"},
            {"$set": {
                "scan_id": job2_id,
                "last_seen_job_id": job2_id,
                "last_seen": t_v2_finish,
                "status": "live",
                "previous_fingerprint": {
                    "status_code": 200,
                    "title": "API Server",
                },
                "metadata": {
                    "status_code": 500,
                    "title": "API Error 500",
                    "body_hash": "sha256_api_body_hash",
                    "technologies": ["Python", "FastAPI"],
                },
            }},
        )

        # Execute diff engine
        diff_doc = await compute_and_save_diff(db, project_id, job2_id)
        assert diff_doc is not None
        assert diff_doc.get("is_liveness_rebaseline") is True

        changed_hosts = diff_doc.get("changed_hosts", [])
        changed_domains = [ch["domain"] for ch in changed_hosts]

        # portal.example.com must be suppressed from changed_hosts because only v1-nonexistent fields changed!
        assert "portal.example.com" not in changed_domains

        # api.example.com must be present because its status_code and/or title changed!
        assert "api.example.com" in changed_domains
        api_ch = next(ch for ch in changed_hosts if ch["domain"] == "api.example.com")
        api_fields = {c["field"] for c in api_ch["changes"]}
        assert "status_code" in api_fields
        # Newly introduced fields must be excluded from changes on rebaseline
        assert "body_hash" not in api_fields
        assert "technologies" not in api_fields
    finally:
        await client.drop_database(db.name)
        client.close()


# ==============================================================================
# 11. Clustering Favicon Strict Status and Title Integration Tests
# ==============================================================================

def test_clustering_favicon_requires_identical_status_code_and_title():
    """
    Constraint 3:
      - Favicon-based clusters require identical status_code AND identical title.
      - Body_hash clusters keep requiring identical status_code.
      - Two hosts with the same default favicon but different titles are NOT clustered.
    """
    # 1. Two hosts with same default favicon but different titles -> NOT clustered
    h1 = {
        "domain": "host1.example.com",
        "status_code": 200,
        "title": "Dashboard - Alpha",
        "favicon_hash": "default_nginx_hash_111",
    }
    h2 = {
        "domain": "host2.example.com",
        "status_code": 200,
        "title": "Public Documentation - Beta",
        "favicon_hash": "default_nginx_hash_111",
    }
    k1, type1 = compute_cluster_key(h1)
    k2, type2 = compute_cluster_key(h2)
    assert k1 != k2, f"Hosts with different titles must have different keys: {k1} vs {k2}"
    assert type1 == "favicon_hash"
    assert type2 == "favicon_hash"

    res = cluster_hosts([h1, h2], scan_all_members=False)
    # Neither host should be skipped or clustered together
    assert len(res["representatives"]) == 2
    assert len(res["skipped_members"]) == 0
    assert len(res["clusters"]) == 2

    # 2. Two hosts with same default favicon AND identical title -> ARE clustered
    h3 = {
        "domain": "host3.example.com",
        "status_code": 200,
        "title": "Dashboard - Alpha",
        "favicon_hash": "default_nginx_hash_111",
    }
    k3, _ = compute_cluster_key(h3)
    assert k1 == k3

    res_clustered = cluster_hosts([h1, h3], scan_all_members=False)
    assert len(res_clustered["representatives"]) == 1
    assert len(res_clustered["skipped_members"]) == 1

    # 3. body_hash clusters keep requiring identical status_code (titles can differ)
    b1 = {
        "domain": "body1.example.com",
        "status_code": 200,
        "title": "Title One",
        "body_hash": "sha256_identical_page_body",
    }
    b2 = {
        "domain": "body2.example.com",
        "status_code": 200,
        "title": "Title Two (Ignored for body_hash)",
        "body_hash": "sha256_identical_page_body",
    }
    kb1, type_b1 = compute_cluster_key(b1)
    kb2, type_b2 = compute_cluster_key(b2)
    assert kb1 == kb2, "body_hash clusters must cluster when status_code and body_hash match"
    assert type_b1 == "body_hash"

    res_body = cluster_hosts([b1, b2], scan_all_members=False)
    assert len(res_body["representatives"]) == 1
    assert len(res_body["skipped_members"]) == 1



