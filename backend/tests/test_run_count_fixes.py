"""Run-history/count fixes — real MongoDB required."""

import os
import uuid
from datetime import datetime
from unittest.mock import patch

import pytest
from bson import ObjectId
from motor.motor_asyncio import AsyncIOMotorClient

import app.database as database_module
from app.routers.assets import get_dashboard_stats
from app.routers.jobs import run_targeted_job
from app.services.risk_scoring import recalculate_all_scores
from app.services.run_history import record_run_asset, record_run_history


async def setup_real_test_db():
    mongo_uri = os.getenv("MONGO_URI", "mongodb://localhost:27017")
    client = AsyncIOMotorClient(mongo_uri, serverSelectionTimeoutMS=2000)
    try:
        await client.admin.command("ping")
    except Exception as exc:
        pytest.skip(f"Real MongoDB is not running at {mongo_uri}: {exc}")

    test_db_name = f"reconforge_counts_{uuid.uuid4().hex[:8]}"
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


async def seed_mixed_assets(db, project_id, job_id):
    """Two live HTTP hosts, one resolved host, one passive candidate, four URLs."""
    await record_run_asset(
        db, project_id, job_id, "subdomain", "app.example.com",
        domain="app.example.com", status="live",
        metadata={"url": "https://app.example.com", "status_code": 200},
    )
    await record_run_asset(
        db, project_id, job_id, "subdomain", "admin.example.com",
        domain="admin.example.com", status="live",
        metadata={"url": "https://admin.example.com", "status_code": 403},
    )
    await record_run_asset(
        db, project_id, job_id, "subdomain", "resolved.example.com",
        domain="resolved.example.com", status="resolved",
        metadata={"dnsx": {"a": ["203.0.113.10"]}},
    )
    await record_run_asset(
        db, project_id, job_id, "subdomain", "candidate.example.com",
        domain="candidate.example.com", status="candidate",
        metadata={"passive_candidate": True, "passive_candidate_sources": ["subfinder"]},
    )
    # URL-type assets: status live must never inflate host counts.
    for asset_type, value in (
        ("historical_url", "https://app.example.com/old"),
        ("content_path", "https://app.example.com/admin"),
        ("js_file", "https://app.example.com/app.js"),
        ("param", "https://app.example.com/search?q=1"),
    ):
        await record_run_asset(
            db, project_id, job_id, asset_type, value,
            domain="app.example.com", status="live",
            metadata={"url": value, "status_code": 200},
        )


@pytest.mark.asyncio
async def test_run_counts_hosts_only_and_urls_separate_real_mongo():
    client, db, old_db, old_is_mock = await setup_real_test_db()
    try:
        project_id = str(ObjectId())
        job_id = str(ObjectId())
        await db.projects.insert_one({"_id": ObjectId(project_id), "name": "Counts"})
        await db.jobs.insert_one({
            "_id": ObjectId(job_id),
            "project_id": project_id,
            "status": "completed",
            "scan_mode": "full",
            "job_kind": "full",
            "started_at": datetime.utcnow(),
            "finished_at": datetime.utcnow(),
            "executed_phases": ["subdomain_discovery", "web_probing"],
            "phase_durations": [],
        })
        await seed_mixed_assets(db, project_id, job_id)

        run_doc = await record_run_history(db=db, job_id=job_id, project_id=project_id)
        counts = run_doc["counts"]

        assert counts["resolved_hosts"] == 3
        assert counts["subdomains"] == 3
        assert counts["passive_candidates"] == 1
        assert counts["live_hosts"] == 2
        assert counts["live"] == 2
        # URL-type assets are counted separately, never as hosts.
        assert counts["urls_total"] == 4
        assert counts["urls"]["historical"] == 1
        assert counts["urls"]["content_paths"] == 1
        assert counts["urls"]["js_files"] == 1
        assert counts["urls"]["params"] == 1
        assert counts["content_paths"] == 1
        assert counts["js_files"] == 1
        assert counts["params"] == 1

        stored = await db.scan_runs.find_one({"job_id": job_id})
        assert stored["counts"]["live_hosts"] == 2
        assert stored["counts"]["passive_candidates"] == 1
        assert stored["counts"]["urls_total"] == 4
    finally:
        await teardown_real_test_db(client, db, old_db, old_is_mock)


@pytest.mark.asyncio
async def test_dashboard_stats_use_same_host_definitions_real_mongo():
    client, db, old_db, old_is_mock = await setup_real_test_db()
    try:
        project_id = ObjectId()
        await db.projects.insert_one({"_id": project_id, "name": "Dashboard Counts"})
        base = {"project_id": str(project_id)}
        await db.assets.insert_many([
            {**base, "type": "subdomain", "domain": "app.example.com", "status": "live",
             "metadata": {"url": "https://app.example.com", "status_code": 200}},
            {**base, "type": "subdomain", "domain": "admin.example.com", "status": "live",
             "metadata": {"url": "https://admin.example.com", "status_code": 403}},
            {**base, "type": "subdomain", "domain": "resolved.example.com", "status": "resolved",
             "metadata": {"dnsx": {"a": ["203.0.113.11"]}}},
            {**base, "type": "subdomain", "domain": "candidate.example.com", "status": "candidate",
             "metadata": {"passive_candidate": True, "passive_candidate_sources": ["amass"]}},
            {**base, "type": "historical_url", "value": "https://app.example.com/old",
             "domain": "app.example.com", "status": "live",
             "metadata": {"url": "https://app.example.com/old", "status_code": 200}},
            {**base, "type": "content_path", "value": "https://app.example.com/admin",
             "domain": "app.example.com", "status": "live",
             "metadata": {"url": "https://app.example.com/admin", "status_code": 200}},
            {**base, "type": "js_file", "value": "https://app.example.com/app.js",
             "domain": "app.example.com", "status": "live",
             "metadata": {"url": "https://app.example.com/app.js"}},
        ])

        stats = await get_dashboard_stats(str(project_id))
        assert stats["resolved_hosts"] == 3
        assert stats["total_subdomains"] == 3
        assert stats["passive_candidates"] == 1
        assert stats["live_hosts"] == 2
        assert stats["urls_total"] == 3
        assert stats["urls"]["historical"] == 1
        assert stats["urls"]["content_paths"] == 1
        assert stats["urls"]["js_files"] == 1
    finally:
        await teardown_real_test_db(client, db, old_db, old_is_mock)


@pytest.mark.asyncio
async def test_hunt_priority_scoring_excludes_urls_and_passive_candidates_real_mongo():
    client, db, old_db, old_is_mock = await setup_real_test_db()
    try:
        project_id = ObjectId()
        pid = str(project_id)
        await db.projects.insert_one({"_id": project_id, "name": "Hunt Filter"})
        live_host_id = ObjectId()
        candidate_id = ObjectId()
        url_id = ObjectId()
        await db.assets.insert_many([
            {"_id": live_host_id, "project_id": pid, "type": "subdomain",
             "domain": "app.example.com", "status": "live", "open_ports": [443],
             "metadata": {"url": "https://app.example.com", "status_code": 200}},
            {"_id": candidate_id, "project_id": pid, "type": "subdomain",
             "domain": "candidate.example.com", "status": "candidate",
             "metadata": {"passive_candidate": True, "passive_candidate_sources": ["subfinder"]}},
            {"_id": url_id, "project_id": pid, "type": "content_path",
             "domain": "app.example.com", "value": "https://app.example.com/admin",
             "status": "live", "metadata": {"url": "https://app.example.com/admin", "status_code": 200}},
        ])

        scored = await recalculate_all_scores(pid)
        assert [s["asset"] for s in scored] == ["app.example.com"]

        host_doc = await db.assets.find_one({"_id": live_host_id})
        candidate_doc = await db.assets.find_one({"_id": candidate_id})
        url_doc = await db.assets.find_one({"_id": url_id})
        assert host_doc.get("hunt_priority") is not None
        assert candidate_doc.get("hunt_priority") is None
        assert url_doc.get("hunt_priority") is None
    finally:
        await teardown_real_test_db(client, db, old_db, old_is_mock)


@pytest.mark.asyncio
async def test_skipped_phase_is_recorded_not_executed_or_timed_real_mongo():
    from app.providers.ffuf_provider import FfufProvider

    async def fake_discover_content(self, targets, **kwargs):
        yield {
            "type": "stage_skipped",
            "stage": "Content Discovery (ffuf)",
            "tool": "ffuf",
            "reason": "switch: ffuf disabled",
        }
        yield {
            "type": "scan_summary",
            "provider": "ffuf",
            "status": "SKIPPED",
            "count": 0,
            "reason": "switch: ffuf disabled",
        }

    client, db, old_db, old_is_mock = await setup_real_test_db()
    try:
        project_id = ObjectId()
        job_id = ObjectId()
        await db.projects.insert_one({
            "_id": project_id,
            "name": "Skipped Phase",
            "scope": {"in_scope": ["example.com"], "out_of_scope": []},
        })
        await db.jobs.insert_one({
            "_id": job_id,
            "project_id": str(project_id),
            "provider_name": "Targeted ffuf",
            "scan_mode": "targeted",
            "job_kind": "targeted",
            "status": "pending",
            "logs": [],
            "executed_phases": [],
            "phase_durations": [],
        })

        with patch.object(FfufProvider, "discover_content", fake_discover_content):
            await run_targeted_job(
                str(job_id), str(project_id), "ffuf",
                ["https://example.com"], None, 30,
            )

        job_doc = await db.jobs.find_one({"_id": job_id})
        assert job_doc["status"] == "completed"
        assert "content_discovery" not in (job_doc.get("executed_phases") or [])
        assert job_doc.get("phase_durations") == []
        assert any(
            sp.get("tool") == "ffuf" and "switch" in str(sp.get("reason"))
            for sp in (job_doc.get("skipped_phases") or [])
        )

        run_doc = await db.scan_runs.find_one({"job_id": str(job_id)})
        assert run_doc is not None
        assert "content_discovery" not in (run_doc.get("executed_phases") or [])
        assert run_doc.get("phase_durations") == []
        assert run_doc.get("skipped_phases")
    finally:
        await teardown_real_test_db(client, db, old_db, old_is_mock)
