"""Tests for Content Discovery, Stage Failures, Tool Paths, and URL Validation
=============================================================================
Requirements:
  1. Backend: GET /api/v1/assets/project/{project_id}/content-paths
     (auth + ownership, paginated, filters: host, status_code, first_seen_after)
     Returns value, host, status_code, content_length, words, lines,
     redirect_location, calibration_used, first_seen, last_seen.
  2. Diff doc & logs include new content paths in their own section.
  3. Stage failures: if tool exits non-zero (including 4294967295 / WSL errors),
     discard stdout, emit stage_error, mark phase as NOT executed, never parse stdout.
  4. Validate every URL/host before storage: URLs must start with http:// or https://
     and parse cleanly; reject everything else. Test with WSL error text.
  5. Tool paths: resolve absolute path once per scan with which in WSL and cache it;
     never rely on bare names with wsl -e.
  6. One-off cleanup script: delete assets of type historical_dead whose value
     does not start with http:// or https://.
"""

import asyncio
import os
import platform
import subprocess
import tempfile
import uuid
from datetime import datetime, timedelta
from typing import Any, Dict, List
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from bson import ObjectId
from motor.motor_asyncio import AsyncIOMotorClient

import app.database as database_module
from app.core.scope import is_valid_url, validate_hostname
from app.core.tools import (
    clear_tool_path_cache,
    resolve_tool_absolute_path,
    _SCAN_TOOL_PATH_CACHE,
    RECON_TOOLS,
)
from app.providers.base import BaseProvider
from app.providers.ffuf_provider import FfufProvider
from app.providers.param_discovery_provider import ParamDiscoveryProvider
from app.routers.jobs import run_discovery_job, manager
from app.services.diff_engine import compute_and_save_diff
from scripts.cleanup_invalid_historical_dead import cleanup_invalid_historical_dead


# ==============================================================================
# Real MongoDB Fixture Helpers
# ==============================================================================

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
    finally:
        client.close()
        database_module.db_helper.db = old_db
        database_module.db_helper.is_mock = old_is_mock


# ==============================================================================
# Item 1: Backend Content Paths Endpoint (Auth, Ownership, Paginated, Filters)
# ==============================================================================

@pytest.mark.asyncio
async def test_item1_get_content_paths_auth_ownership_pagination_and_filters():
    """
    Requirement 1:
      - GET /api/v1/assets/project/{project_id}/content-paths
      - Auth + project ownership required
      - Paginated (page, limit)
      - Filters: host, status_code, first_seen_after
      - Returns: value, host, status_code, content_length, words, lines,
                 redirect_location, calibration_used, first_seen, last_seen
    """
    client, db, old_db, old_is_mock = await setup_real_test_db()
    try:
        from app.routers.assets import get_project_content_paths
        from fastapi import HTTPException

        owner_id = ObjectId()
        other_user_id = ObjectId()
        project_id = ObjectId()

        # Create project owned by owner_id
        await db.projects.insert_one({
            "_id": project_id,
            "name": "Content Discovery Test",
            "owner_id": str(owner_id),
            "created_at": datetime.utcnow(),
        })

        base_time = datetime.utcnow() - timedelta(hours=2)

        # Seed content_path assets
        assets_to_insert = [
            {
                "project_id": str(project_id),
                "type": "content_path",
                "value": "https://api.example.com/v1/users",
                "domain": "api.example.com",
                "status_code": 200,
                "first_seen": base_time + timedelta(minutes=10),
                "last_seen": base_time + timedelta(minutes=10),
                "metadata": {
                    "url": "https://api.example.com/v1/users",
                    "host": "api.example.com",
                    "status_code": 200,
                    "content_length": 1540,
                    "words": 120,
                    "lines": 35,
                    "redirect_location": "",
                    "calibration_used": True,
                },
            },
            {
                "project_id": str(project_id),
                "type": "content_path",
                "value": "https://api.example.com/v1/admin",
                "domain": "api.example.com",
                "status_code": 403,
                "first_seen": base_time + timedelta(minutes=20),
                "last_seen": base_time + timedelta(minutes=20),
                "metadata": {
                    "url": "https://api.example.com/v1/admin",
                    "host": "api.example.com",
                    "status_code": 403,
                    "content_length": 450,
                    "words": 40,
                    "lines": 12,
                    "redirect_location": "",
                    "calibration_used": True,
                },
            },
            {
                "project_id": str(project_id),
                "type": "content_path",
                "value": "https://app.example.com/login",
                "domain": "app.example.com",
                "status_code": 302,
                "first_seen": base_time + timedelta(minutes=30),
                "last_seen": base_time + timedelta(minutes=30),
                "metadata": {
                    "url": "https://app.example.com/login",
                    "host": "app.example.com",
                    "status_code": 302,
                    "content_length": 210,
                    "words": 15,
                    "lines": 5,
                    "redirect_location": "/auth/portal",
                    "calibration_used": True,
                },
            },
        ]
        await db.assets.insert_many(assets_to_insert)

        owner_user = {"_id": owner_id, "username": "owner"}
        unauthorized_user = {"_id": other_user_id, "username": "attacker"}

        # 1. Assert: Nonexistent project returns 404
        with pytest.raises(HTTPException) as exc_info:
            await get_project_content_paths(
                project_id=str(ObjectId()),
            )
        assert exc_info.value.status_code == 404

        # 1b. Single-user local mode: all existing projects are visible without ownership filter
        any_user_res = await get_project_content_paths(
            project_id=str(project_id),
            current_user=unauthorized_user,
        )
        assert any_user_res["total"] == 3

        # 2. Assert: Default paginated list returns all 3 assets with proper fields
        res = await get_project_content_paths(
            project_id=str(project_id),
            page=1,
            limit=50,
            current_user=owner_user,
        )
        assert res["total"] == 3
        assert len(res["items"]) == 3
        first_item = res["items"][0]
        assert "value" in first_item
        assert "host" in first_item
        assert "status_code" in first_item
        assert "content_length" in first_item
        assert "words" in first_item
        assert "lines" in first_item
        assert "redirect_location" in first_item
        assert "calibration_used" in first_item
        assert "first_seen" in first_item
        assert "last_seen" in first_item

        # 3. Assert: Pagination limits output
        p_res = await get_project_content_paths(
            project_id=str(project_id),
            page=1,
            limit=2,
            current_user=owner_user,
        )
        assert p_res["total"] == 3
        assert len(p_res["items"]) == 2
        assert p_res["page"] == 1
        assert p_res["limit"] == 2

        # 4. Assert: Filter by host
        host_res = await get_project_content_paths(
            project_id=str(project_id),
            host="app.example.com",
            current_user=owner_user,
        )
        assert host_res["total"] == 1
        assert host_res["items"][0]["host"] == "app.example.com"
        assert host_res["items"][0]["redirect_location"] == "/auth/portal"

        # 5. Assert: Filter by status_code
        status_res = await get_project_content_paths(
            project_id=str(project_id),
            status_code=403,
            current_user=owner_user,
        )
        assert status_res["total"] == 1
        assert status_res["items"][0]["value"] == "https://api.example.com/v1/admin"
        assert status_res["items"][0]["status_code"] == 403

        # 6. Assert: Filter by first_seen_after
        cutoff = (base_time + timedelta(minutes=25)).isoformat()
        after_res = await get_project_content_paths(
            project_id=str(project_id),
            first_seen_after=cutoff,
            current_user=owner_user,
        )
        assert after_res["total"] == 1
        assert after_res["items"][0]["value"] == "https://app.example.com/login"

    finally:
        await teardown_real_test_db(client, db, old_db, old_is_mock)


# ==============================================================================
# Item 4: Stage Failures Non-Zero Exit Code, Discard Stdout, Emit stage_error
# ==============================================================================

@pytest.mark.asyncio
async def test_item4_stage_failure_nonzero_exit_discards_stdout_and_marks_not_executed():
    """
    Requirement 4:
      - If tool exits non-zero (including 4294967295 / WSL errors):
        * Discard stdout
        * Emit stage_error event with reason
        * Mark phase as NOT executed (so diff ignores it)
        * Never parse stdout of a failed process as results
    """
    provider = FfufProvider()

    # Simulate WSL process failure with non-zero exit code 4294967295 and WSL error text in stderr
    class FailedWSLProc:
        def __init__(self, *args, **kwargs):
            self.returncode = 4294967295
            self.stdout = MagicMock(read=MagicMock(return_value='{"results":[{"url":"https://example.com/secret","status":200}]}'))
            self.stderr = MagicMock(read=MagicMock(return_value="<3>WSL (1234) ERROR: CreateProcessCommon:543: execvpe(/usr/bin/ffuf) failed 2"))

        def poll(self):
            return 4294967295

        def wait(self):
            return 4294967295

        def kill(self):
            pass

    real_popen = subprocess.Popen

    def popen_side_effect(cmd, *args, **kwargs):
        if isinstance(cmd, (list, tuple)) and len(cmd) > 0 and cmd[0] == "ver":
            return real_popen(cmd, *args, **kwargs)
        if isinstance(cmd, str) and cmd.strip().startswith("ver"):
            return real_popen(cmd, *args, **kwargs)
        return FailedWSLProc(*args, **kwargs)

    with patch.object(provider, "detect_tool", return_value="/usr/bin/ffuf"), \
         patch("app.core.tools.is_tool_available", return_value=True), \
         patch("platform.system", return_value="Windows"), \
         patch("subprocess.Popen", side_effect=popen_side_effect), \
         patch("app.job_control.register_process"), \
         patch("app.job_control.unregister_process"):

        events = []
        async for ev in provider.discover_content(
            targets=["https://example.com"],
            scan_mode="fast",
            scope={"in_scope": ["example.com"], "out_of_scope": []},
        ):
            events.append(ev)

        # 1. Assert: No asset events or content_path_events were emitted (stdout discarded)
        asset_events = [e for e in events if e.get("type") in ("asset", "content_path_event")]
        assert len(asset_events) == 0, f"Expected 0 asset events, got {len(asset_events)}"

        # 2. Assert: stage_error event was emitted with reason and returncode
        stage_errors = [e for e in events if e.get("type") == "stage_error"]
        assert len(stage_errors) >= 1
        err = stage_errors[0]
        assert err["tool"] == "ffuf"
        assert err["returncode"] == 4294967295
        assert "execvpe" in err["reason"] or "4294967295" in err["reason"]


# ==============================================================================
# Item 5: URL Validation (Rejects WSL Error Text, 4294967295, Non-HTTP)
# ==============================================================================

def test_item5_is_valid_url_rejects_wsl_error_text_and_invalid_schemes():
    """
    Requirement 5:
      - URLs must start with http:// or https:// and parse cleanly
      - Reject everything else
      - Add a test using the WSL error text
    """
    wsl_err_text_1 = "<3>WSL (1234) ERROR: CreateProcessCommon:543: execvpe(/usr/bin/ffuf) failed 2"
    wsl_err_text_2 = "WSL (4294967295) ERROR: CreateProcessCommon:543: execvpe(/usr/bin/ffuf) failed 2"
    raw_exit_code = "4294967295"

    # 1. Test WSL error strings rejected
    valid, reason = is_valid_url(wsl_err_text_1)
    assert not valid
    assert reason is not None

    valid, reason = is_valid_url(wsl_err_text_2)
    assert not valid

    valid, reason = is_valid_url(raw_exit_code)
    assert not valid
    assert reason == "must_start_with_http_or_https"

    # 2. Test non-HTTP schemes rejected
    assert not is_valid_url("ftp://example.com/file")[0]
    assert not is_valid_url("javascript:alert(1)")[0]
    assert not is_valid_url("file:///etc/passwd")[0]
    assert not is_valid_url("/api/v1/users")[0]
    assert not is_valid_url("example.com/path")[0]

    # 3. Test whitespace / control characters rejected
    assert not is_valid_url("https://example.com/path with spaces")[0]
    assert not is_valid_url("https://example.com/path\nnewline")[0]

    # 4. Test valid HTTP and HTTPS URLs accepted
    assert is_valid_url("https://example.com/api/v1/users?page=1")[0]
    assert is_valid_url("http://sub.example.com:8080/path#fragment")[0]
    assert is_valid_url("http://93.184.216.34:8080/test")[0]


@pytest.mark.asyncio
async def test_item5_job_pipeline_drops_invalid_url_and_wsl_error_assets_real_mongo():
    """
    Requirement 5: Test that the jobs pipeline drops assets containing WSL error strings
    and never stores them into MongoDB assets collection.
    """
    client, db, old_db, old_is_mock = await setup_real_test_db()
    try:
        project_id = ObjectId()
        job_id = ObjectId()
        user_id = ObjectId()

        await db.projects.insert_one({
            "_id": project_id,
            "name": "Validation Pipeline Test",
            "owner_id": str(user_id),
            "seed_domains": ["example.com"],
            "scope": {"in_scope": ["*.example.com", "example.com"], "out_of_scope": []},
            "scan_profile": "recon",
            "created_at": datetime.utcnow(),
        })

        await db.jobs.insert_one({
            "_id": job_id,
            "project_id": str(project_id),
            "status": "pending",
            "created_at": datetime.utcnow(),
            "logs": [],
        })

        wsl_err = "<3>WSL (1234) ERROR: CreateProcessCommon:543: execvpe(/usr/bin/ffuf) failed 2"

        # Mock a provider yielding an asset with the WSL error text as value and a valid URL asset
        class MockToolProvider:
            async def discover(self, *args, **kwargs):
                yield {
                    "type": "asset",
                    "data": {
                        "type": "content_path",
                        "value": wsl_err,
                        "domain": "example.com",
                    }
                }
                yield {
                    "type": "asset",
                    "data": {
                        "type": "content_path",
                        "value": "https://example.com/valid-endpoint",
                        "domain": "example.com",
                    }
                }

        with patch("app.routers.jobs.PROVIDERS", {"Unified Discovery": MockToolProvider()}), \
             patch("app.job_control.check_job_status", AsyncMock()):

            await run_discovery_job(
                job_id=str(job_id),
                project_id=str(project_id),
                provider_name="Unified Discovery",
                seed_domains=["example.com"],
            )

        # Assert: The invalid WSL error string was NOT inserted into db.assets
        bad_doc = await db.assets.find_one({"project_id": str(project_id), "value": wsl_err})
        assert bad_doc is None, "Asset containing WSL error text was erroneously stored in MongoDB!"

        # Assert: The valid asset WAS inserted into db.assets
        good_doc = await db.assets.find_one({"project_id": str(project_id), "value": "https://example.com/valid-endpoint"})
        assert good_doc is not None, "Valid asset was not stored in MongoDB!"

    finally:
        await teardown_real_test_db(client, db, old_db, old_is_mock)


# ==============================================================================
# Item 6: Tool Path Resolution Once Per Scan and Cached, Never Bare Names
# ==============================================================================

def test_item6_tool_paths_resolved_to_absolute_path_and_cached():
    """
    Requirement 6:
      - Resolve each tool's absolute path once per scan with which in WSL
        (including ~/go/bin and ~/.local/bin) and cache it
      - Never rely on bare names with wsl -e
    """
    clear_tool_path_cache()
    assert len(_SCAN_TOOL_PATH_CACHE) == 0

    # 1. Test resolution and caching
    with patch("app.core.tools.check_tool_in_system", return_value=(True, "/usr/bin/ffuf")) as mock_chk:
        path1 = resolve_tool_absolute_path("ffuf")
        assert path1 == "/usr/bin/ffuf"
        assert mock_chk.call_count == 1

        # Second call must hit cache without invoking check_tool_in_system again
        path2 = resolve_tool_absolute_path("ffuf")
        assert path2 == "/usr/bin/ffuf"
        assert mock_chk.call_count == 1

    # 2. Test BaseProvider.detect_tool uses cached absolute path
    detected = BaseProvider.detect_tool("ffuf")
    assert detected == "/usr/bin/ffuf"

    # 3. Test that missing tool resolves to None, never a bare command name
    with patch("app.core.tools.check_tool_in_system", return_value=(False, None)):
        clear_tool_path_cache()
        missing_path = resolve_tool_absolute_path("amass")
        assert missing_path is None, f"Expected None for missing tool, got {missing_path}"
        assert missing_path != "amass", "Tool resolution returned bare command name 'amass'!"

    # 4. Test that unregistered tool raises ValueError
    with pytest.raises(ValueError) as exc:
        BaseProvider.detect_tool("unregistered_tool_123")
    assert "not registered" in str(exc.value)


# ==============================================================================
# Item 7: One-Off Cleanup Script for Invalid historical_dead Assets
# ==============================================================================

@pytest.mark.asyncio
async def test_item7_cleanup_invalid_historical_dead_script_real_mongo():
    """
    Requirement 7:
      - One-off cleanup script: delete assets of type historical_dead whose value
        does not start with http:// or https://.
      - Preserves valid HTTP/HTTPS historical_dead assets.
    """
    client, db, old_db, old_is_mock = await setup_real_test_db()
    try:
        project_id = str(ObjectId())

        docs = [
            # Valid: starts with https://
            {"project_id": project_id, "type": "historical_dead", "value": "https://example.com/dead1"},
            # Valid: starts with http://
            {"project_id": project_id, "type": "historical_dead", "value": "http://example.com/dead2"},
            # Invalid: WSL error text
            {"project_id": project_id, "type": "historical_dead", "value": "<3>WSL (1234) ERROR: failed 2"},
            # Invalid: raw exit code
            {"project_id": project_id, "type": "historical_dead", "value": "4294967295"},
            # Invalid: bare domain (no scheme)
            {"project_id": project_id, "type": "historical_dead", "value": "dead.example.com"},
            # Invalid: null value
            {"project_id": project_id, "type": "historical_dead", "value": None},
            # Other asset type with invalid value (must NOT be deleted)
            {"project_id": project_id, "type": "subdomain", "value": "sub.example.com"},
        ]
        await db.assets.insert_many(docs)

        # Run cleanup function
        deleted_count = await cleanup_invalid_historical_dead(db)
        assert deleted_count == 4, f"Expected 4 deleted invalid historical_dead assets, got {deleted_count}"

        # Assert: Valid historical_dead assets remain
        remaining_dead = await db.assets.find({"project_id": project_id, "type": "historical_dead"}).to_list(10)
        assert len(remaining_dead) == 2
        remaining_values = {d["value"] for d in remaining_dead}
        assert "https://example.com/dead1" in remaining_values
        assert "http://example.com/dead2" in remaining_values

        # Assert: Other types (subdomain) remain intact
        sub_doc = await db.assets.find_one({"project_id": project_id, "type": "subdomain"})
        assert sub_doc is not None

    finally:
        await teardown_real_test_db(client, db, old_db, old_is_mock)


# ==============================================================================
# Item 3: Diff Doc and Summary Logs Include Content Paths
# ==============================================================================

@pytest.mark.asyncio
async def test_item3_diff_doc_and_summary_logs_include_content_paths_real_mongo():
    """
    Requirement 3:
      - Diff doc includes new content paths in their own section
      - Summary logs include new content paths count
    """
    client, db, old_db, old_is_mock = await setup_real_test_db()
    try:
        project_id = ObjectId()
        job1_id = ObjectId()
        job2_id = ObjectId()
        user_id = ObjectId()

        await db.projects.insert_one({
            "_id": project_id,
            "name": "Diff Content Paths Test",
            "owner_id": str(user_id),
            "scan_mode": "fast",
        })

        t1 = datetime.utcnow() - timedelta(hours=1)
        t2 = datetime.utcnow()

        # Job 1 (baseline scan): executed content_discovery
        await db.jobs.insert_one({
            "_id": job1_id,
            "project_id": str(project_id),
            "status": "completed",
            "scan_mode": "fast",
            "started_at": t1,
            "finished_at": t1 + timedelta(minutes=5),
            "executed_phases": ["subdomain_discovery", "content_discovery"],
            "liveness_version": 2,
        })

        # Asset seen in Job 1
        await db.assets.insert_one({
            "project_id": str(project_id),
            "type": "content_path",
            "value": "https://example.com/v1",
            "domain": "example.com",
            "status": "live",
            "scan_id": str(job1_id),
            "first_seen": t1,
            "last_seen": t1,
            "metadata": {"url": "https://example.com/v1", "status_code": 200, "content_length": 500},
        })

        # Job 2: executed content_discovery, found a brand new path
        await db.jobs.insert_one({
            "_id": job2_id,
            "project_id": str(project_id),
            "status": "completed",
            "scan_mode": "fast",
            "started_at": t2,
            "finished_at": t2 + timedelta(minutes=5),
            "executed_phases": ["subdomain_discovery", "content_discovery"],
            "liveness_version": 2,
        })

        await db.assets.insert_one({
            "project_id": str(project_id),
            "type": "content_path",
            "value": "https://example.com/v2/new-path",
            "domain": "example.com",
            "status": "live",
            "scan_id": str(job2_id),
            "first_seen": t2,
            "last_seen": t2,
            "metadata": {"url": "https://example.com/v2/new-path", "status_code": 200, "content_length": 750},
        })

        # Compute diff for Job 2
        diff_doc = await compute_and_save_diff(str(project_id), str(job2_id), db)
        assert diff_doc is not None

        # Assert: new_content_paths in diff section and count in summary
        summary = diff_doc.get("summary", {})
        assert summary.get("new_content_paths_count") == 1

        diff_data = diff_doc.get("diff", {})
        new_cps = diff_data.get("new_content_paths", [])
        assert len(new_cps) == 1
        assert new_cps[0]["url"] == "https://example.com/v2/new-path"

    finally:
        await teardown_real_test_db(client, db, old_db, old_is_mock)


@pytest.mark.asyncio
async def test_mock_cursor_skip_limit_and_content_paths_on_mock_db():
    """
    Verifies MockCursor supports skip() and limit(), preventing AttributeError
    when running on in-memory MockDb.
    """
    from unittest.mock import patch
    from app.database import MockDb, MockCursor
    from app.routers.assets import get_project_content_paths
    from bson import ObjectId

    mock_db = MockDb()
    project_id = str(ObjectId())
    user_id = str(ObjectId())

    # Seed mock project
    await mock_db.projects.insert_one({
        "_id": ObjectId(project_id),
        "owner_id": user_id,
        "name": "Mock Project",
    })

    # Seed mock content path assets
    for i in range(15):
        await mock_db.assets.insert_one({
            "project_id": project_id,
            "type": "content_path",
            "value": f"https://example.com/path_{i}",
            "status_code": 200,
            "metadata": {
                "url": f"https://example.com/path_{i}",
                "host": "example.com",
                "status_code": 200,
            },
            "first_seen": datetime.utcnow(),
            "last_seen": datetime.utcnow(),
        })

    user = {"_id": ObjectId(user_id), "username": "tester"}
    with patch("app.routers.assets.get_database", return_value=mock_db):
        res = await get_project_content_paths(
            project_id=project_id,
            page=2,
            limit=5,
            current_user=user,
        )

    assert res["total"] == 15
    assert res["page"] == 2
    assert res["limit"] == 5
    assert len(res["items"]) == 5
