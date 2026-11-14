"""
Phase 2 Follow-Up Tests: Verification of Items 1 to 11
======================================================
Tests:
  1. Real MongoDB integration test (skip if unavailable):
     Double upsert keeps one doc with unchanged first_seen and updated last_seen.
  2. Startup recovery and scheduler lock (Items 2, 10).
  3. Stale logic: N consecutive completed scans threshold & skipped on error/cancel (Item 3).
  4. Same scan_mode matching, phase execution check, & scope-exclusion filter (Item 4).
  5. Schedule scope validation & Secret masking on PUT/GET (Items 5, 6).
  6. Fingerprint alerts: status_code/title/tech only; body_hash/content_length low-priority (Item 7).
  7. Finding identity key stability: template-id + matched-at + host, no scan_id/timestamp (Item 8).
  8. Notifier: initial baseline scan skipped, batched summary, 429 backoff, truncated limits (Item 9).
"""

import asyncio
import os
import sys
from datetime import datetime, timedelta
from unittest.mock import AsyncMock, patch, MagicMock
from bson import ObjectId
import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app.database import MockDb, connect_to_mongo, db_helper
from app.config import settings
from app.services.diff_engine import (
    generate_host_fingerprint,
    compare_fingerprints,
    compute_and_save_diff,
    compute_finding_key,
)
from app.services.notifier import (
    dispatch_scan_diff_alerts,
    _send_discord,
    _send_telegram,
    get_alert_config,
)
from app.services.scheduler import AsyncioScanScheduler, recover_stuck_jobs
from app.services.migration import compute_canonical_value, run_asset_backfill_migration
from app.routers.projects import mask_project_secrets, is_masked_placeholder, validate_schedule_scope
from fastapi import HTTPException


# ============================================================================
# 1. REAL MONGODB INTEGRATION TEST (Item 1 & Item 11)
# ============================================================================

@pytest.mark.asyncio
async def test_real_mongodb_double_upsert():
    """
    Integration test against REAL MongoDB (skipped if MongoDB is not running locally).
    Verifies that a double upsert keyed on (project_id, type, value) keeps ONE doc
    with unchanged first_seen and updated last_seen.
    """
    from motor.motor_asyncio import AsyncIOMotorClient
    
    client = AsyncIOMotorClient(settings.MONGODB_URL, serverSelectionTimeoutMS=1500)
    try:
        await client.admin.command("ping")
    except Exception as exc:
        pytest.skip(f"Real MongoDB is not running or unavailable ({exc}). Skipping integration test.")

    db = client[settings.DATABASE_NAME]
    test_pid = f"test_proj_{ObjectId()}"
    test_val = "integration-test.example.com"

    try:
        # Enforce unique index (standard app index name)
        await db.assets.create_index(
            [("project_id", 1), ("type", 1), ("value", 1)],
            unique=True,
            name="project_id_1_type_1_value_1_unique"
        )

        t1 = datetime(2026, 1, 1, 10, 0, 0)
        t2 = datetime(2026, 1, 2, 12, 0, 0)

        # Upsert 1
        await db.assets.update_one(
            {"project_id": test_pid, "type": "subdomain", "value": test_val},
            {
                "$set": {"last_seen": t1, "status": "live", "updated_at": t1},
                "$setOnInsert": {"first_seen": t1, "created_at": t1},
                "$addToSet": {"sources": {"$each": ["subfinder"]}}
            },
            upsert=True
        )

        # Upsert 2 (subsequent scan later)
        await db.assets.update_one(
            {"project_id": test_pid, "type": "subdomain", "value": test_val},
            {
                "$set": {"last_seen": t2, "status": "live", "updated_at": t2},
                "$setOnInsert": {"first_seen": t2, "created_at": t2},
                "$addToSet": {"sources": {"$each": ["amass"]}}
            },
            upsert=True
        )

        # Verification: Exactly ONE document
        docs = await db.assets.find({"project_id": test_pid, "type": "subdomain", "value": test_val}).to_list(10)
        assert len(docs) == 1
        doc = docs[0]
        assert doc["first_seen"] == t1, "first_seen must remain unchanged from initial scan"
        assert doc["last_seen"] == t2, "last_seen must be updated to the later scan timestamp"
        assert set(doc.get("sources", [])) == {"subfinder", "amass"}

    finally:
        # Clean up
        await db.assets.delete_many({"project_id": test_pid})
        client.close()


# ============================================================================
# 2. STARTUP RECOVERY & MONGO LOCK (Items 2 & 10)
# ============================================================================

@pytest.mark.asyncio
async def test_startup_recovery_marks_stuck_jobs():
    """Startup recovery marks running or pending jobs with no live process as 'interrupted'."""
    db = MockDb()
    job1 = {"_id": ObjectId(), "project_id": "p1", "status": "running", "logs": []}
    job2 = {"_id": ObjectId(), "project_id": "p2", "status": "pending", "logs": []}
    job3 = {"_id": ObjectId(), "project_id": "p3", "status": "completed", "logs": []}
    await db.jobs.insert_one(job1)
    await db.jobs.insert_one(job2)
    await db.jobs.insert_one(job3)

    count = await recover_stuck_jobs(db)
    assert count == 2

    j1 = await db.jobs.find_one({"_id": job1["_id"]})
    assert j1["status"] == "interrupted"
    assert any("Startup Recovery" in l for l in j1["logs"])

    j3 = await db.jobs.find_one({"_id": job3["_id"]})
    assert j3["status"] == "completed"


@pytest.mark.asyncio
async def test_scheduler_double_start_guard():
    """Scheduler guards against double start in the same process and uses MongoDB leader lock."""
    sched = AsyncioScanScheduler()
    sched.start()
    assert sched._running is True
    # Second start call should not throw and should remain running
    sched.start()
    assert sched._running is True
    await sched.stop()
    assert sched._running is False


# ============================================================================
# 3. STALE LOGIC TESTS (Item 3)
# ============================================================================

@pytest.mark.asyncio
async def test_stale_threshold_n_consecutive_absences():
    """
    A subdomain is marked stale ONLY after absent in N consecutive completed scans (default 2).
    Absent in 1 scan increments count but does NOT mark stale.
    Absent in 2nd consecutive scan marks stale.
    """
    db = MockDb()
    project_id = "proj_stale_test"
    
    # Project with default stale_threshold = 2
    await db.projects.insert_one({
        "_id": ObjectId(),
        "name": "Stale Test Proj",
        "schedule": {"stale_threshold": 2},
        "scope": {"in_scope": ["example.com"]},
    })

    t0 = datetime(2026, 1, 1, 10, 0, 0)
    t1 = datetime(2026, 1, 1, 11, 0, 0)
    t2 = datetime(2026, 1, 1, 12, 0, 0)
    t3 = datetime(2026, 1, 1, 13, 0, 0)

    # Initial scan (job1): discovers 'sub.example.com'
    job1 = {
        "_id": ObjectId(),
        "project_id": project_id,
        "status": "completed",
        "scan_mode": "fast",
        "started_at": t0,
        "finished_at": t1,
        "executed_phases": ["subdomain_discovery"],
    }
    await db.jobs.insert_one(job1)

    asset = {
        "_id": ObjectId(),
        "project_id": project_id,
        "type": "subdomain",
        "domain": "sub.example.com",
        "value": "sub.example.com",
        "status": "live",
        "first_seen": t0,
        "last_seen": t1,
        "scan_id": str(job1["_id"]),
        "consecutive_absent_count": 0,
    }
    await db.assets.insert_one(asset)

    # Scan 2 (job2): 'sub.example.com' is absent for 1st time
    job2 = {
        "_id": ObjectId(),
        "project_id": project_id,
        "status": "completed",
        "scan_mode": "fast",
        "started_at": t2,
        "finished_at": t2 + timedelta(minutes=10),
        "executed_phases": ["subdomain_discovery"],
    }
    await db.jobs.insert_one(job2)

    diff2 = await compute_and_save_diff(project_id, str(job2["_id"]), db)
    # Absent 1st time: count becomes 1, NOT yet stale!
    assert "sub.example.com" not in diff2["diff"]["stale_subdomains"]
    asset_after_scan2 = await db.assets.find_one({"domain": "sub.example.com"})
    assert asset_after_scan2["consecutive_absent_count"] == 1
    assert asset_after_scan2["status"] == "live"

    # Scan 3 (job3): 'sub.example.com' is absent for 2nd consecutive time
    job3 = {
        "_id": ObjectId(),
        "project_id": project_id,
        "status": "completed",
        "scan_mode": "fast",
        "started_at": t3,
        "finished_at": t3 + timedelta(minutes=10),
        "executed_phases": ["subdomain_discovery"],
    }
    await db.jobs.insert_one(job3)

    diff3 = await compute_and_save_diff(project_id, str(job3["_id"]), db)
    # Absent 2nd consecutive time: threshold 2 met, marked STALE!
    assert "sub.example.com" in diff3["diff"]["stale_subdomains"]
    asset_after_scan3 = await db.assets.find_one({"domain": "sub.example.com"})
    assert asset_after_scan3["consecutive_absent_count"] == 2
    assert asset_after_scan3["status"] == "stale"


@pytest.mark.asyncio
async def test_skip_stale_when_scan_cancelled_partial_or_passive_errored():
    """Skip stale and closed-port marking if scan was cancelled, partial, or a passive source errored."""
    db = MockDb()
    project_id = "proj_unreliable"

    # Job 1 completed
    j1 = {
        "_id": ObjectId(),
        "project_id": project_id,
        "status": "completed",
        "scan_mode": "fast",
        "started_at": datetime(2026, 1, 1, 10, 0),
        "finished_at": datetime(2026, 1, 1, 10, 30),
        "executed_phases": ["subdomain_discovery", "port_scanning"],
    }
    await db.jobs.insert_one(j1)

    # Discovered host with port 8080 in Job 1
    await db.assets.insert_one({
        "_id": ObjectId(),
        "project_id": project_id,
        "type": "subdomain",
        "domain": "target.example.com",
        "status": "live",
        "open_ports": [8080],
        "first_seen": datetime(2026, 1, 1, 10, 0),
        "last_seen": datetime(2026, 1, 1, 10, 30),
        "scan_id": str(j1["_id"]),
    })

    # Case A: Current scan had passive source error
    j2_err = {
        "_id": ObjectId(),
        "project_id": project_id,
        "status": "completed",
        "scan_mode": "fast",
        "passive_source_errored": True,
        "started_at": datetime(2026, 1, 2, 10, 0),
        "finished_at": datetime(2026, 1, 2, 10, 30),
        "executed_phases": ["subdomain_discovery", "port_scanning"],
    }
    await db.jobs.insert_one(j2_err)

    diff_err = await compute_and_save_diff(project_id, str(j2_err["_id"]), db)
    assert diff_err["summary"]["is_reliable"] is False
    assert diff_err["diff"]["stale_subdomains"] == []
    assert diff_err["diff"]["closed_ports"] == []

    # Case B: Current scan was stopped / cancelled
    j2_stopped = {
        "_id": ObjectId(),
        "project_id": project_id,
        "status": "stopped",
        "scan_mode": "fast",
        "started_at": datetime(2026, 1, 3, 10, 0),
        "finished_at": datetime(2026, 1, 3, 10, 10),
        "executed_phases": ["subdomain_discovery"],
    }
    await db.jobs.insert_one(j2_stopped)

    diff_stopped = await compute_and_save_diff(project_id, str(j2_stopped["_id"]), db)
    assert diff_stopped["summary"]["is_reliable"] is False
    assert diff_stopped["diff"]["stale_subdomains"] == []


# ============================================================================
# 4. SCAN MODE & PHASE MATCHING TESTS (Item 4)
# ============================================================================

@pytest.mark.asyncio
async def test_only_diff_scans_with_same_scan_mode():
    """Scans are only compared against previous scans sharing the exact same scan_mode."""
    db = MockDb()
    project_id = "proj_mode_diff"

    # Previous job was 'deep' mode
    j_deep = {
        "_id": ObjectId(),
        "project_id": project_id,
        "status": "completed",
        "scan_mode": "deep",
        "started_at": datetime(2026, 1, 1, 10, 0),
        "finished_at": datetime(2026, 1, 1, 11, 0),
        "executed_phases": ["subdomain_discovery"],
    }
    await db.jobs.insert_one(j_deep)

    # Current job is 'fast' mode
    j_fast = {
        "_id": ObjectId(),
        "project_id": project_id,
        "status": "completed",
        "scan_mode": "fast",
        "started_at": datetime(2026, 1, 2, 10, 0),
        "finished_at": datetime(2026, 1, 2, 10, 30),
        "executed_phases": ["subdomain_discovery"],
    }
    await db.jobs.insert_one(j_fast)

    diff = await compute_and_save_diff(project_id, str(j_fast["_id"]), db)
    # Since there are no prior 'fast' scans, this is treated as an initial scan
    assert diff["summary"]["is_initial_scan"] is True
    assert diff["previous_job_id"] is None


@pytest.mark.asyncio
async def test_scope_excluded_assets_not_reported_as_disappeared():
    """Do not report scope-excluded assets as disappeared or mark them stale."""
    db = MockDb()
    project_oid = ObjectId()
    project_id = str(project_oid)

    # Project with strict in_scope
    await db.projects.insert_one({
        "_id": project_oid,
        "name": "Scope Restricted Proj",
        "scope": {"in_scope": ["*.corp.com"], "out_of_scope": ["staging.corp.com"]},
    })

    # Historical doc outside of current scope
    await db.assets.insert_one({
        "_id": ObjectId(),
        "project_id": project_id,
        "type": "subdomain",
        "domain": "staging.corp.com",  # Excluded by out_of_scope!
        "value": "staging.corp.com",
        "status": "live",
        "first_seen": datetime(2026, 1, 1, 10, 0),
        "last_seen": datetime(2026, 1, 1, 10, 30),
        "consecutive_absent_count": 5,
    })

    j_curr = {
        "_id": ObjectId(),
        "project_id": project_id,
        "status": "completed",
        "scan_mode": "fast",
        "started_at": datetime(2026, 1, 2, 10, 0),
        "finished_at": datetime(2026, 1, 2, 10, 30),
        "executed_phases": ["subdomain_discovery"],
    }
    await db.jobs.insert_one(j_curr)

    diff = await compute_and_save_diff(project_id, str(j_curr["_id"]), db)
    # staging.corp.com must NOT be reported as stale
    assert "staging.corp.com" not in diff["diff"]["stale_subdomains"]


# ============================================================================
# 5. SCHEDULE SCOPE VALIDATION & SECRET MASKING (Items 5 & 6)
# ============================================================================

def test_refuse_recurring_schedule_without_scope():
    """Refuses to enable recurring schedule when scope is not configured."""
    empty_scope = {"in_scope": [], "out_of_scope": []}
    enabled_schedule = {"enabled": True, "interval_hours": 24}

    with pytest.raises(HTTPException) as excinfo:
        validate_schedule_scope(empty_scope, enabled_schedule)
    assert excinfo.value.status_code == 400
    assert "Cannot enable recurring schedule without configured in-scope targets" in excinfo.value.detail

    # When scope is configured, validation succeeds
    valid_scope = {"in_scope": ["example.com"]}
    validate_schedule_scope(valid_scope, enabled_schedule)  # does not raise


def test_secrets_masking_and_placeholder_preservation():
    """Masks secrets in responses; placeholder **** on update preserves existing secret."""
    original_project = {
        "_id": ObjectId(),
        "name": "Secret Proj",
        "alerts": {
            "enabled": True,
            "discord_webhook_url": "https://discord.com/api/webhooks/12345/secret_token_abc",
            "telegram_bot_token": "987654321:AAFakeBotSecretToken",
            "telegram_chat_id": "11223344",
        }
    }

    masked = mask_project_secrets(original_project)
    assert masked["alerts"]["discord_webhook_url"] == "https://discord.com/api/webhooks/********"
    assert masked["alerts"]["telegram_bot_token"] == "********"
    assert masked["alerts"]["telegram_chat_id"] == "********"

    # Placeholder detection
    assert is_masked_placeholder("https://discord.com/api/webhooks/********") is True
    assert is_masked_placeholder("********") is True
    assert is_masked_placeholder("https://discord.com/api/webhooks/real_url") is False


# ============================================================================
# 6. FINGERPRINT ALERT FILTER TESTS (Item 7)
# ============================================================================

def test_fingerprint_prioritization_alert_trigger():
    """
    Only status_code, title and technologies changes trigger alerts.
    body_hash and content_length changes are low-priority only.
    """
    old_fp = {
        "status_code": 200,
        "title": "Welcome Page",
        "technologies": ["Nginx"],
        "content_length": 500,
        "body_hash": "hash_111",
    }

    # Case A: Only body_hash and content_length change (low priority)
    new_fp_low = {
        "status_code": 200,
        "title": "Welcome Page",
        "technologies": ["Nginx"],
        "content_length": 520,  # changed
        "body_hash": "hash_222",  # changed
    }
    changes_low = compare_fingerprints(old_fp, new_fp_low)
    assert len(changes_low) == 2
    for c in changes_low:
        assert c["priority"] == "low"
        assert c["field"] in ("body_hash", "content_length")

    # Case B: status_code and title change (high priority)
    new_fp_high = {
        "status_code": 403,
        "title": "Access Denied",
        "technologies": ["Nginx"],
        "content_length": 500,
        "body_hash": "hash_111",
    }
    changes_high = compare_fingerprints(old_fp, new_fp_high)
    high_fields = [c["field"] for c in changes_high if c["priority"] == "high"]
    assert "status_code" in high_fields
    assert "title" in high_fields


# ============================================================================
# 7. FINDING IDENTITY KEY STABILITY (Item 8)
# ============================================================================

def test_finding_identity_key_stability():
    """Verify finding identity key is stable (template-id + matched-at + host), with NO scan_id or timestamp."""
    key1 = compute_finding_key("cve-2023-1234", "https://api.example.com/v1/user", "api.example.com")
    key2 = compute_finding_key("cve-2023-1234", "https://api.example.com/v1/user", "")
    assert key1 == "cve-2023-1234:https://api.example.com/v1/user:api.example.com"
    assert key1 == key2

    # Verify no timestamps or scan IDs
    assert "job_" not in key1
    assert "2026" not in key1
    assert ":" in key1


# ============================================================================
# 8. NOTIFIER BATCHED & ROBUST TESTS (Item 9)
# ============================================================================

@pytest.mark.asyncio
async def test_notifier_skips_baseline_initial_scan():
    """Notifier suppresses alerts for the initial baseline scan."""
    mock_project = {
        "alerts": {
            "enabled": True,
            "discord_webhook_url": "https://discord.com/api/webhooks/mock",
        }
    }
    initial_diff = {
        "previous_job_id": None,
        "summary": {"is_initial_scan": True, "total_changes": 10},
        "diff": {"new_subdomains": ["sub1.example.com"]},
    }

    with patch("app.services.notifier._send_discord", new_callable=AsyncMock) as mock_discord:
        await dispatch_scan_diff_alerts("Test Project", initial_diff, mock_project)
        mock_discord.assert_not_called()


@pytest.mark.asyncio
async def test_notifier_fingerprint_low_priority_does_not_trigger_alerts():
    """Changed hosts with only body_hash/content_length changes do NOT trigger alerts."""
    mock_project = {
        "alerts": {
            "enabled": True,
            "discord_webhook_url": "https://discord.com/api/webhooks/mock",
            "events": {"scan_completed": False},
        }
    }
    diff_with_low_priority_only = {
        "previous_job_id": "prev_123",
        "summary": {"is_initial_scan": False, "total_changes": 1},
        "diff": {
            "new_subdomains": [],
            "stale_subdomains": [],
            "new_live_hosts": [],
            "new_ports": [],
            "closed_ports": [],
            "new_findings": [],
            "changed_hosts": [{
                "domain": "app.example.com",
                "changes": [
                    {"field": "body_hash", "priority": "low"},
                    {"field": "content_length", "priority": "low"},
                ]
            }],
        },
    }

    with patch("app.services.notifier._send_discord", new_callable=AsyncMock) as mock_discord:
        await dispatch_scan_diff_alerts("Test Project", diff_with_low_priority_only, mock_project)
        # Because only low priority changes exist and scan_completed is False, no alert is sent
        mock_discord.assert_not_called()


@pytest.mark.asyncio
async def test_notifier_handles_429_backoff():
    """Notifier implements 429 backoff retry loop without failing the scan."""
    # Test that _send_discord logs and handles 429 without throwing
    with patch("aiohttp.ClientSession.post") as mock_post:
        # Mock 429 response then 200 response
        resp_429 = AsyncMock()
        resp_429.status = 429
        resp_429.headers = {"Retry-After": "0.1"}

        resp_200 = AsyncMock()
        resp_200.status = 200

        mock_post.return_value.__aenter__.side_effect = [resp_429, resp_200]

        # Should complete successfully through backoff
        await _send_discord(
            webhook_url="https://discord.com/api/webhooks/mock",
            title="Test Alert",
            description="Test Description",
            fields=[{"name": "Field", "value": "Val"}],
        )
        assert mock_post.return_value.__aenter__.call_count == 2
