"""Stage 1 — single full scan, per-phase switches, targeted runs.

Real MongoDB is required for every test that touches the database. The suite
skips only when MongoDB itself is unreachable.
"""

import asyncio
import os
import shutil
import uuid
from datetime import datetime, timedelta
from unittest.mock import AsyncMock

import httpx
import pytest
from bson import ObjectId
from motor.motor_asyncio import AsyncIOMotorClient

import app.database as database_module
from app.core.scan_options import PHASE_SWITCH_DEFAULTS, normalize_phase_switches
from app.main import app
from app.services.diff_engine import compute_and_save_diff, get_executed_phases
from app.services.run_history import RUNS_BASE_DIR, compare_runs


async def setup_real_test_db():
    mongo_uri = os.getenv("MONGO_URI", "mongodb://localhost:27017")
    client = AsyncIOMotorClient(mongo_uri, serverSelectionTimeoutMS=2000)
    try:
        await client.admin.command("ping")
    except Exception as exc:
        pytest.skip(f"Real MongoDB is not running at {mongo_uri}: {exc}")

    test_db_name = f"reconforge_stage1_{uuid.uuid4().hex[:8]}"
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


def api_client() -> httpx.AsyncClient:
    return httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://testserver",
    )


async def wait_for_job(db, job_id, timeout: float = 5.0):
    deadline = asyncio.get_event_loop().time() + timeout
    last = None
    while asyncio.get_event_loop().time() < deadline:
        last = await db.jobs.find_one({"_id": ObjectId(job_id)})
        if last and last.get("status") in ("completed", "failed"):
            return last
        await asyncio.sleep(0.05)
    return last


# ==============================================================================
# Per-phase switch configuration
# ==============================================================================

@pytest.mark.asyncio
async def test_phase_switches_default_off_and_persist_real_mongo():
    client, db, old_db, old_is_mock = await setup_real_test_db()
    try:
        async with api_client() as ac:
            created = await ac.post("/api/v1/projects", json={
                "name": "Stage1 Switches",
                "seed_domains": ["example.com"],
                "scope": {"in_scope": ["example.com"], "out_of_scope": []},
            })
            assert created.status_code == 200, created.text
            project = created.json()
            switches = project.get("phase_switches") or {}
            assert set(switches.keys()) == set(PHASE_SWITCH_DEFAULTS.keys())
            assert all(sw.get("enabled") is False for sw in switches.values())
            assert switches["ffuf"]["time_cap_seconds"] == PHASE_SWITCH_DEFAULTS["ffuf"]["time_cap_seconds"]

            updated = await ac.put(f"/api/v1/projects/{project['id']}", json={
                "phase_switches": {
                    "ffuf": {"enabled": True, "time_cap_seconds": 123},
                    "wide_port_scan": {"enabled": True, "time_cap_seconds": 99999},
                }
            })
            assert updated.status_code == 200, updated.text
            body = updated.json()
            assert body["phase_switches"]["ffuf"]["enabled"] is True
            assert body["phase_switches"]["ffuf"]["time_cap_seconds"] == 123
            assert body["phase_switches"]["wide_port_scan"]["enabled"] is True
            # Time caps are clamped to 2 hours.
            assert body["phase_switches"]["wide_port_scan"]["time_cap_seconds"] == 7200
            for key in set(PHASE_SWITCH_DEFAULTS) - {"ffuf", "wide_port_scan"}:
                assert body["phase_switches"][key]["enabled"] is False

            stored = await db.projects.find_one({"_id": ObjectId(project["id"])})
            assert stored["phase_switches"]["ffuf"]["enabled"] is True
    finally:
        await teardown_real_test_db(client, db, old_db, old_is_mock)


def test_phase_switch_normalization_defaults_and_clamps():
    switches = normalize_phase_switches(None)
    assert all(sw["enabled"] is False for sw in switches.values())

    switches = normalize_phase_switches({
        "ffuf": {"enabled": 1, "time_cap_seconds": 0},
        "waymore": True,
        "unknown": {"enabled": True},
    })
    assert switches["ffuf"]["enabled"] is True
    assert switches["ffuf"]["time_cap_seconds"] == 1
    assert switches["waymore"]["enabled"] is True
    assert "unknown" not in switches


def test_switch_skipped_phases_are_not_inferred_as_executed():
    job = {
        "scan_mode": "full",
        "executed_phases": [
            "content_discovery",
            "param_discovery",
            "dns_bruteforce",
            "vulnerability_scan",
            "tech_routing",
        ],
        "logs": [
            "[!] FFUF content discovery disabled by project switch.",
            "[!] Parameter discovery disabled by project switch.",
            "[!] DNS Brute Force & Permutations disabled by project switch.",
            "[*] Active scanners disabled by project switch (Nuclei, Dalfox, OpenRedirex).",
        ],
    }
    phases = get_executed_phases(job)
    assert "content_discovery" not in phases
    assert "param_discovery" not in phases
    assert "dns_bruteforce" not in phases
    assert "vulnerability_scan" not in phases
    assert "tech_routing" not in phases


# ==============================================================================
# Single scan mode launcher
# ==============================================================================

@pytest.mark.asyncio
async def test_launch_job_accepts_legacy_scan_mode_and_stores_full_real_mongo(monkeypatch):
    client, db, old_db, old_is_mock = await setup_real_test_db()
    try:
        monkeypatch.setattr("app.routers.jobs.run_discovery_job", AsyncMock())

        async with api_client() as ac:
            created = await ac.post("/api/v1/projects", json={
                "name": "Legacy Mode",
                "seed_domains": ["example.com"],
                "scope": {"in_scope": ["example.com"], "out_of_scope": []},
            })
            project_id = created.json()["id"]

            launched = await ac.post(
                f"/api/v1/jobs/project/{project_id}/provider/Unified%20Discovery?scan_mode=deep"
            )
            assert launched.status_code == 200, launched.text
            job = launched.json()
            assert job["scan_mode"] == "full"
            assert job["job_kind"] == "full"

            stored = await db.jobs.find_one({"_id": ObjectId(job["id"])})
            assert stored["scan_mode"] == "full"
            assert stored["job_kind"] == "full"
    finally:
        await teardown_real_test_db(client, db, old_db, old_is_mock)


@pytest.mark.asyncio
async def test_scheduler_ignores_legacy_schedule_mode_real_mongo(monkeypatch):
    from app.services.scheduler import AsyncioScanScheduler

    client, db, old_db, old_is_mock = await setup_real_test_db()
    try:
        monkeypatch.setattr("app.routers.jobs.run_discovery_job", AsyncMock())
        project_id = ObjectId()
        await db.projects.insert_one({
            "_id": project_id,
            "name": "Legacy Schedule",
            "seed_domains": ["example.com"],
            "scope": {"in_scope": ["example.com"], "out_of_scope": []},
            "schedule": {
                "enabled": True,
                "interval_hours": 24,
                "scan_mode": "deep",
                "next_run": datetime.utcnow() - timedelta(minutes=1),
            },
            "phase_switches": normalize_phase_switches(None),
        })

        scheduler = AsyncioScanScheduler()
        await scheduler.check_due_schedules()
        await asyncio.sleep(0.1)

        job = await db.jobs.find_one({"project_id": str(project_id)})
        assert job is not None
        assert job["scan_mode"] == "full"
        assert job["job_kind"] == "full"
        assert "mode:" not in " ".join(job.get("logs") or []).lower()
        # Legacy schedule field is preserved, not deleted.
        refreshed = await db.projects.find_one({"_id": project_id})
        assert refreshed["schedule"]["scan_mode"] == "deep"
    finally:
        await teardown_real_test_db(client, db, old_db, old_is_mock)


# ==============================================================================
# Targeted runs
# ==============================================================================

@pytest.mark.asyncio
async def test_targeted_run_api_ffuf_scope_timeout_assets_and_history_real_mongo(monkeypatch):
    from app.providers.ffuf_provider import FfufProvider

    calls = []

    async def fake_discover_content(self, targets, **kwargs):
        calls.append({"targets": list(targets), "kwargs": kwargs})
        yield {"type": "log", "message": "[*] fake ffuf running"}
        yield {
            "type": "content_path_event",
            "data": {"url": "https://example.com/admin", "status_code": 401},
        }
        yield {
            "type": "asset",
            "data": {
                "domain": "example.com",
                "type": "content_path",
                "value": "https://example.com/admin",
                "status": "live",
                "status_code": 401,
                "status_class": "4xx",
                "is_interesting": True,
                "metadata": {
                    "url": "https://example.com/admin",
                    "host": "example.com",
                    "status_code": 401,
                    "content_length": 42,
                    "words": 3,
                    "lines": 2,
                    "redirect_location": "",
                    "calibration_used": True,
                    "source": "ffuf",
                },
                "discovered_by": "ffuf",
                "sources": ["ffuf"],
            },
        }
        yield {"type": "scan_summary", "provider": "ffuf", "status": "completed", "count": 1}

    monkeypatch.setattr(FfufProvider, "discover_content", fake_discover_content)

    client, db, old_db, old_is_mock = await setup_real_test_db()
    project_id = None
    try:
        project_id = ObjectId()
        await db.projects.insert_one({
            "_id": project_id,
            "name": "Targeted FFUF",
            "seed_domains": ["example.com"],
            "scope": {"in_scope": ["example.com"], "out_of_scope": []},
            "rate_limits": {"global_rps": 10, "per_tool": {"ffuf": 7}},
            "custom_headers": {"X-Bug-Bounty": "reconforge"},
            "phase_switches": normalize_phase_switches(None),
        })

        async with api_client() as ac:
            res = await ac.post(f"/api/v1/jobs/project/{project_id}/targeted", json={
                "tool": "ffuf",
                "hosts": ["https://example.com", "https://out.example.org"],
                "time_cap_seconds": 30,
            })
            assert res.status_code == 200, res.text
            job = res.json()
            assert job["job_kind"] == "targeted"
            assert job["scan_mode"] == "targeted"
            assert job["targeted"]["tool"] == "ffuf"
            assert job["targeted"]["hosts"] == ["https://example.com"]
            assert job["targeted"]["time_cap_seconds"] == 30

        job_doc = await wait_for_job(db, job["id"])
        assert job_doc["status"] == "completed"
        assert "content_discovery" in (job_doc.get("executed_phases") or [])
        assert job_doc.get("phase_durations")
        assert job_doc.get("targeted", {}).get("tool") == "ffuf"

        asset = await db.assets.find_one({
            "project_id": str(project_id),
            "type": "content_path",
            "value": "https://example.com/admin",
        })
        assert asset is not None
        assert asset["scan_id"] == job["id"]
        assert asset["metadata"]["status_code"] == 401
        assert asset["metadata"]["content_length"] == 42

        run_asset = await db.run_assets.find_one({
            "project_id": str(project_id),
            "job_id": job["id"],
            "type": "content_path",
        })
        assert run_asset is not None

        run_doc = await db.scan_runs.find_one({"job_id": job["id"]})
        assert run_doc is not None
        assert run_doc["run_kind"] == "targeted"
        assert run_doc["targeted"]["tool"] == "ffuf"
        assert run_doc.get("phase_durations")
        assert run_doc["counts"]["content_paths"] >= 1

        assert len(calls) == 1
        assert calls[0]["targets"] == ["https://example.com"]
        assert calls[0]["kwargs"]["rate_limit"] == 7
        assert calls[0]["kwargs"]["custom_headers"] == {"X-Bug-Bounty": "reconforge"}
        assert calls[0]["kwargs"]["ffuf_options"]["enabled"] is True
    finally:
        if project_id is not None:
            shutil.rmtree(os.path.join(RUNS_BASE_DIR, str(project_id)), ignore_errors=True)
        await teardown_real_test_db(client, db, old_db, old_is_mock)


@pytest.mark.asyncio
async def test_targeted_run_api_naabu_persists_ports_and_phase_real_mongo(monkeypatch):
    from app.providers.naabu_provider import NaabuProvider

    async def fake_discover(self, targets, **kwargs):
        yield {
            "type": "asset",
            "data": {
                "domain": "example.com",
                "type": "subdomain",
                "status": "live",
                "open_ports": [80, 443],
                "metadata": {"source": "naabu"},
                "discovered_by": "naabu",
                "sources": ["naabu"],
            },
        }
        yield {
            "type": "scan_summary",
            "provider": "naabu",
            "status": "completed",
            "hosts_with_open_ports": 1,
            "open_ports": 2,
            "count": 2,
        }

    monkeypatch.setattr(NaabuProvider, "discover", fake_discover)

    client, db, old_db, old_is_mock = await setup_real_test_db()
    project_id = None
    try:
        project_id = ObjectId()
        await db.projects.insert_one({
            "_id": project_id,
            "name": "Targeted Naabu",
            "seed_domains": ["example.com"],
            "scope": {"in_scope": ["example.com"], "out_of_scope": []},
            "rate_limits": {"global_rps": 10, "per_tool": {"naabu": 300}},
            "port_range": "1-2000",
            "phase_switches": normalize_phase_switches(None),
        })

        async with api_client() as ac:
            res = await ac.post(f"/api/v1/jobs/project/{project_id}/targeted", json={
                "tool": "naabu",
                "hosts": ["example.com"],
                "port_range": "1-2000",
                "time_cap_seconds": 30,
            })
            assert res.status_code == 200, res.text
            job = res.json()

        job_doc = await wait_for_job(db, job["id"])
        assert job_doc["status"] == "completed"
        assert "port_scanning" in (job_doc.get("executed_phases") or [])

        asset = await db.assets.find_one({
            "project_id": str(project_id),
            "type": "subdomain",
            "domain": "example.com",
        })
        assert asset is not None
        assert asset["open_ports"] == [80, 443]

        run_doc = await db.scan_runs.find_one({"job_id": job["id"]})
        assert run_doc is not None
        assert run_doc["counts"]["ports"] == 2
    finally:
        if project_id is not None:
            shutil.rmtree(os.path.join(RUNS_BASE_DIR, str(project_id)), ignore_errors=True)
        await teardown_real_test_db(client, db, old_db, old_is_mock)


@pytest.mark.asyncio
async def test_targeted_run_api_rejects_out_of_scope_invalid_tool_and_bad_range_real_mongo():
    client, db, old_db, old_is_mock = await setup_real_test_db()
    try:
        project_id = ObjectId()
        await db.projects.insert_one({
            "_id": project_id,
            "name": "Targeted Validation",
            "seed_domains": ["example.com"],
            "scope": {"in_scope": ["example.com"], "out_of_scope": []},
        })

        async with api_client() as ac:
            out_of_scope = await ac.post(f"/api/v1/jobs/project/{project_id}/targeted", json={
                "tool": "ffuf",
                "hosts": ["https://out.example.org"],
            })
            assert out_of_scope.status_code == 400

            bad_tool = await ac.post(f"/api/v1/jobs/project/{project_id}/targeted", json={
                "tool": "sqlmap",
                "hosts": ["https://example.com"],
            })
            assert bad_tool.status_code == 400

            bad_range = await ac.post(f"/api/v1/jobs/project/{project_id}/targeted", json={
                "tool": "naabu",
                "hosts": ["example.com"],
                "port_range": "1-1000; touch /tmp/pwned",
            })
            assert bad_range.status_code == 400

            empty = await ac.post(f"/api/v1/jobs/project/{project_id}/targeted", json={
                "tool": "arjun",
                "hosts": [],
            })
            assert empty.status_code == 400

            jobs = await db.jobs.find({"project_id": str(project_id)}).to_list(10)
            assert jobs == []
    finally:
        await teardown_real_test_db(client, db, old_db, old_is_mock)


# ==============================================================================
# Diff / run comparison phase gating
# ==============================================================================

@pytest.mark.asyncio
async def test_diff_skips_phases_not_executed_in_both_runs_real_mongo():
    client, db, old_db, old_is_mock = await setup_real_test_db()
    try:
        project_id = ObjectId()
        prev_job_id = ObjectId()
        current_job_id = ObjectId()
        now = datetime.utcnow()

        await db.projects.insert_one({
            "_id": project_id,
            "name": "Diff Phase Gating",
            "phase_switches": normalize_phase_switches(None),
        })
        await db.jobs.insert_one({
            "_id": prev_job_id,
            "project_id": str(project_id),
            "status": "completed",
            "scan_mode": "full",
            "job_kind": "full",
            "started_at": now - timedelta(hours=2),
            "finished_at": now - timedelta(hours=1, minutes=50),
            "executed_phases": ["subdomain_discovery", "port_scanning", "content_discovery"],
            "liveness_version": 2,
        })
        await db.jobs.insert_one({
            "_id": current_job_id,
            "project_id": str(project_id),
            "status": "completed",
            "scan_mode": "full",
            "job_kind": "full",
            "started_at": now - timedelta(minutes=5),
            "finished_at": now,
            "executed_phases": ["subdomain_discovery"],
            "liveness_version": 2,
        })

        await db.assets.insert_one({
            "project_id": str(project_id),
            "domain": "example.com",
            "value": "example.com",
            "type": "subdomain",
            "status": "live",
            "open_ports": [80, 443],
            "scan_id": str(current_job_id),
            "first_seen": now - timedelta(days=1),
            "last_seen": now,
            "metadata": {},
        })
        await db.assets.insert_one({
            "project_id": str(project_id),
            "domain": "example.com",
            "value": "https://example.com/current-only",
            "type": "content_path",
            "status": "live",
            "scan_id": str(current_job_id),
            "first_seen": now,
            "last_seen": now,
            "metadata": {
                "url": "https://example.com/current-only",
                "status_code": 200,
                "content_length": 10,
            },
        })

        diff = await compute_and_save_diff(str(project_id), str(current_job_id), db)
        assert diff is not None
        summary = diff["summary"]
        assert summary["new_content_paths_count"] == 0
        assert summary["closed_ports_count"] == 0
        assert diff["diff"]["new_content_paths"] == []
        assert diff["diff"]["closed_ports"] == []
    finally:
        await teardown_real_test_db(client, db, old_db, old_is_mock)


@pytest.mark.asyncio
async def test_compare_runs_gates_types_by_executed_phases_real_mongo():
    client, db, old_db, old_is_mock = await setup_real_test_db()
    try:
        project_id = ObjectId()
        run_a = f"run_a_{uuid.uuid4().hex[:6]}"
        run_b = f"run_b_{uuid.uuid4().hex[:6]}"

        await db.scan_runs.insert_many([
            {
                "job_id": run_a,
                "project_id": str(project_id),
                "status": "completed",
                "scan_mode": "full",
                "run_kind": "full",
                "executed_phases": ["subdomain_discovery", "content_discovery", "param_discovery"],
            },
            {
                "job_id": run_b,
                "project_id": str(project_id),
                "status": "completed",
                "scan_mode": "full",
                "run_kind": "full",
                "executed_phases": ["subdomain_discovery", "content_discovery"],
            },
        ])
        await db.run_assets.insert_many([
            {"project_id": str(project_id), "job_id": run_a, "type": "content_path", "value": "https://example.com/a", "status": "live"},
            {"project_id": str(project_id), "job_id": run_b, "type": "content_path", "value": "https://example.com/b", "status": "live"},
            {"project_id": str(project_id), "job_id": run_a, "type": "param", "value": "https://example.com?a=1", "status": "live"},
            {"project_id": str(project_id), "job_id": run_b, "type": "param", "value": "https://example.com?b=1", "status": "live"},
        ])

        result = await compare_runs(db, str(project_id), run_a, run_b)
        assert "content_path" in result["comparison"]
        # param_discovery did not run in run_b, so it must not be compared.
        assert "param" not in result["comparison"]
        assert "param" not in result["summary"]
        assert result["run_a_meta"]["run_kind"] == "full"
    finally:
        await teardown_real_test_db(client, db, old_db, old_is_mock)
