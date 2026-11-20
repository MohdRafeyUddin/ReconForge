"""Project deletion removes data and project-scoped artifacts."""

import os
import shutil
import uuid

import httpx
import pytest
from bson import ObjectId
from motor.motor_asyncio import AsyncIOMotorClient

import app.database as database_module
from app.main import app
from app.providers.js_analysis_provider import JS_STORAGE_ROOT
from app.services.response_storage import get_project_storage_dir
from app.services.run_history import RUNS_BASE_DIR
from app.services.screenshot_storage import SCREENSHOT_ROOT


async def setup_real_test_db():
    mongo_uri = os.getenv("MONGO_URI", "mongodb://localhost:27017")
    client = AsyncIOMotorClient(mongo_uri, serverSelectionTimeoutMS=2000)
    try:
        await client.admin.command("ping")
    except Exception as exc:
        pytest.skip(f"Real MongoDB is not running at {mongo_uri}: {exc}")
    test_db_name = f"reconforge_delete_{uuid.uuid4().hex[:8]}"
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
async def test_delete_project_removes_data_and_files():
    client, db, old_db, old_is_mock = await setup_real_test_db()
    project_id = ObjectId()
    pid = str(project_id)
    job_id = ObjectId()
    dirs = [
        get_project_storage_dir(pid),
        os.path.join(RUNS_BASE_DIR, pid),
        os.path.join(SCREENSHOT_ROOT, pid),
        os.path.join(JS_STORAGE_ROOT, "js", pid),
    ]
    try:
        await db.projects.insert_one({"_id": project_id, "name": "Delete Me"})
        await db.assets.insert_one({"project_id": pid, "type": "subdomain", "domain": "x.example.test"})
        await db.jobs.insert_one({"_id": job_id, "project_id": pid, "status": "completed"})
        await db.run_assets.insert_one({"project_id": pid, "job_id": str(job_id), "type": "subdomain"})
        await db.scan_runs.insert_one({"project_id": pid, "job_id": str(job_id)})
        await db.scan_diffs.insert_one({"project_id": pid, "job_id": str(job_id)})
        for directory in dirs:
            os.makedirs(directory, exist_ok=True)
            with open(os.path.join(directory, "artifact.txt"), "w", encoding="utf-8") as handle:
                handle.write("data")

        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="http://testserver",
        ) as ac:
            res = await ac.delete(f"/api/v1/projects/{pid}")
            assert res.status_code == 200, res.text
            body = res.json()
            assert body["project_id"] == pid

        assert await db.projects.count_documents({"_id": project_id}) == 0
        for collection in ("assets", "jobs", "run_assets", "scan_runs", "scan_diffs"):
            assert await db[collection].count_documents({"project_id": pid}) == 0
        for directory in dirs:
            assert not os.path.exists(directory)
    finally:
        for directory in dirs:
            shutil.rmtree(directory, ignore_errors=True)
        await teardown_real_test_db(client, db, old_db, old_is_mock)


@pytest.mark.asyncio
async def test_reset_clears_scan_data_but_keeps_project():
    client, db, old_db, old_is_mock = await setup_real_test_db()
    project_id = ObjectId()
    pid = str(project_id)
    job_id = ObjectId()
    jid = str(job_id)
    dirs = [
        get_project_storage_dir(pid),
        os.path.join(RUNS_BASE_DIR, pid),
        os.path.join(SCREENSHOT_ROOT, pid),
        os.path.join(JS_STORAGE_ROOT, "js", pid),
    ]
    try:
        await db.projects.insert_one({"_id": project_id, "name": "Keep Me"})
        await db.assets.insert_one({"project_id": pid, "type": "subdomain", "domain": "x.example.test"})
        await db.jobs.insert_one({"_id": job_id, "project_id": pid, "status": "stopped"})
        await db.run_assets.insert_one({"project_id": pid, "job_id": jid, "type": "subdomain"})
        await db.scan_runs.insert_one({"project_id": pid, "job_id": jid})
        await db.scan_diffs.insert_one({"project_id": pid, "job_id": jid})
        for directory in dirs:
            os.makedirs(directory, exist_ok=True)

        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="http://testserver",
        ) as ac:
            res = await ac.post(f"/api/v1/jobs/{jid}/reset")
            assert res.status_code == 200, res.text
            assert res.json()["status"] == "reset"

        assert await db.projects.count_documents({"_id": project_id}) == 1
        for collection in ("assets", "jobs", "run_assets", "scan_runs", "scan_diffs"):
            assert await db[collection].count_documents({"project_id": pid}) == 0
        for directory in dirs:
            assert not os.path.exists(directory)
    finally:
        for directory in dirs:
            shutil.rmtree(directory, ignore_errors=True)
        await teardown_real_test_db(client, db, old_db, old_is_mock)
