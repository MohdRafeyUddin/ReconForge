"""Job Stop must cancel the runner, not just flip the UI status."""

import asyncio
import os
import shutil
import uuid

import httpx
import pytest
from bson import ObjectId
from motor.motor_asyncio import AsyncIOMotorClient

import app.database as database_module
import app.routers.jobs as jobs_module
from app.main import app
from app.services.run_history import RUNS_BASE_DIR


async def setup_real_test_db():
    mongo_uri = os.getenv("MONGO_URI", "mongodb://localhost:27017")
    client = AsyncIOMotorClient(mongo_uri, serverSelectionTimeoutMS=2000)
    try:
        await client.admin.command("ping")
    except Exception as exc:
        pytest.skip(f"Real MongoDB is not running at {mongo_uri}: {exc}")
    test_db_name = f"reconforge_stop_{uuid.uuid4().hex[:8]}"
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


@pytest.mark.asyncio
async def test_pause_stops_persistence_and_resume_continues(monkeypatch):
    class SlowProvider:
        async def discover(self, seed_domains, **kwargs):
            for index in range(1000):
                await asyncio.sleep(0.05)
                yield {
                    "type": "asset",
                    "data": {
                        "domain": f"paused-{index}.example.test",
                        "type": "subdomain",
                        "status": "unknown",
                        "open_ports": [],
                        "metadata": {"source": "unified_discovery"},
                    },
                }

    monkeypatch.setitem(
        jobs_module.PROVIDERS, "Unified Discovery", SlowProvider()
    )

    client, db, old_db, old_is_mock = await setup_real_test_db()
    project_id = ObjectId()
    job_id = ObjectId()
    pid, jid = str(project_id), str(job_id)
    try:
        await db.projects.insert_one({
            "_id": project_id,
            "name": "Pause",
            "scope": {"in_scope": ["*.example.test"], "out_of_scope": []},
        })
        await db.jobs.insert_one({
            "_id": job_id,
            "project_id": pid,
            "provider_name": "Unified Discovery",
            "scan_mode": "full",
            "status": "running",
            "logs": [],
        })

        runner = asyncio.create_task(
            jobs_module.run_discovery_job(
                jid, pid, "Unified Discovery", ["example.test"]
            )
        )
        await asyncio.sleep(0.35)

        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="http://testserver",
        ) as ac:
            pause_res = await ac.post(f"/api/v1/jobs/{jid}/pause")
            assert pause_res.status_code == 200, pause_res.text
            assert pause_res.json()["status"] == "paused"

            await asyncio.sleep(2.0)
            paused_count = await db.assets.count_documents({"project_id": pid})
            await asyncio.sleep(0.6)
            assert await db.assets.count_documents({"project_id": pid}) == paused_count

            resume_res = await ac.post(f"/api/v1/jobs/{jid}/resume")
            assert resume_res.status_code == 200, resume_res.text
            assert resume_res.json()["status"] == "running"

            await asyncio.sleep(2.0)
            assert await db.assets.count_documents({"project_id": pid}) > paused_count

            stop_res = await ac.post(f"/api/v1/jobs/{jid}/stop")
            assert stop_res.status_code == 200, stop_res.text

        await asyncio.gather(runner, return_exceptions=True)
        job = await db.jobs.find_one({"_id": job_id})
        assert job["status"] == "stopped"
    finally:
        shutil.rmtree(os.path.join(RUNS_BASE_DIR, pid), ignore_errors=True)
        await teardown_real_test_db(client, db, old_db, old_is_mock)


@pytest.mark.asyncio
async def test_stop_cancels_job_runner_and_persistence(monkeypatch):
    class SlowProvider:
        async def discover(self, seed_domains, **kwargs):
            for index in range(1000):
                await asyncio.sleep(0.05)
                yield {
                    "type": "asset",
                    "data": {
                        "domain": f"slow-{index}.example.test",
                        "type": "subdomain",
                        "status": "unknown",
                        "open_ports": [],
                        "metadata": {"source": "unified_discovery"},
                    },
                }

    monkeypatch.setitem(
        jobs_module.PROVIDERS, "Unified Discovery", SlowProvider()
    )

    client, db, old_db, old_is_mock = await setup_real_test_db()
    project_id = ObjectId()
    job_id = ObjectId()
    pid, jid = str(project_id), str(job_id)
    try:
        await db.projects.insert_one({
            "_id": project_id,
            "name": "Cancellation",
            "scope": {"in_scope": ["*.example.test"], "out_of_scope": []},
        })
        await db.jobs.insert_one({
            "_id": job_id,
            "project_id": pid,
            "provider_name": "Unified Discovery",
            "scan_mode": "full",
            "status": "running",
            "logs": [],
        })

        runner = asyncio.create_task(
            jobs_module.run_discovery_job(
                jid, pid, "Unified Discovery", ["example.test"]
            )
        )
        await asyncio.sleep(0.35)

        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="http://testserver",
        ) as ac:
            res = await ac.post(f"/api/v1/jobs/{jid}/stop")
            assert res.status_code == 200, res.text
            assert res.json()["status"] == "stopped"

        await asyncio.gather(runner, return_exceptions=True)
        await asyncio.sleep(0.15)
        first_count = await db.assets.count_documents({"project_id": pid})

        # The runner must not keep consuming provider events after Stop.
        await asyncio.sleep(0.5)
        second_count = await db.assets.count_documents({"project_id": pid})
        assert second_count == first_count

        job = await db.jobs.find_one({"_id": job_id})
        assert job["status"] == "stopped"
    finally:
        shutil.rmtree(os.path.join(RUNS_BASE_DIR, pid), ignore_errors=True)
        await teardown_real_test_db(client, db, old_db, old_is_mock)
