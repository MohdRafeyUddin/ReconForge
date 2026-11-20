"""Stage 3 — Content Discovery endpoint filters and targeted-run flow."""

import os
import shutil
import uuid
from datetime import datetime, timedelta

import httpx
import pytest
from bson import ObjectId
from motor.motor_asyncio import AsyncIOMotorClient

import app.database as database_module
from app.main import app
from app.services.risk_scoring import recalculate_all_scores
from app.services.run_history import RUNS_BASE_DIR


async def setup_real_test_db():
    mongo_uri = os.getenv("MONGO_URI", "mongodb://localhost:27017")
    client = AsyncIOMotorClient(mongo_uri, serverSelectionTimeoutMS=2000)
    try:
        await client.admin.command("ping")
    except Exception as exc:
        pytest.skip(f"Real MongoDB is not running at {mongo_uri}: {exc}")

    test_db_name = f"reconforge_stage3_{uuid.uuid4().hex[:8]}"
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


def api_client():
    return httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://testserver",
    )


@pytest.mark.asyncio
async def test_content_paths_endpoint_filters_and_fields_real_mongo():
    client, db, old_db, old_is_mock = await setup_real_test_db()
    try:
        project_id = ObjectId()
        pid = str(project_id)
        await db.projects.insert_one({"_id": project_id, "name": "Content Filters"})

        old_ts = datetime(2026, 1, 1, 10, 0, 0)
        new_ts = datetime(2026, 1, 3, 10, 0, 0)
        await db.assets.insert_many([
            {
                "project_id": pid, "type": "content_path",
                "value": "https://a.example.test/admin", "domain": "a.example.test",
                "status": "live", "status_code": 200,
                "first_seen": old_ts, "last_seen": new_ts,
                "metadata": {
                    "url": "https://a.example.test/admin", "host": "a.example.test",
                    "status_code": 200, "content_length": 512, "words": 20,
                    "lines": 8, "redirect_location": "", "calibration_used": True,
                },
            },
            {
                "project_id": pid, "type": "content_path",
                "value": "https://a.example.test/private", "domain": "a.example.test",
                "status": "live", "status_code": 403,
                "first_seen": new_ts, "last_seen": new_ts,
                "metadata": {
                    "url": "https://a.example.test/private", "host": "a.example.test",
                    "status_code": 403, "content_length": 128, "words": 3,
                    "lines": 2, "redirect_location": "/login", "calibration_used": True,
                },
            },
            {
                "project_id": pid, "type": "content_path",
                "value": "https://b.example.test/old", "domain": "b.example.test",
                "status": "live", "status_code": 301,
                "first_seen": old_ts, "last_seen": old_ts,
                "metadata": {
                    "url": "https://b.example.test/old", "host": "b.example.test",
                    "status_code": 301, "content_length": 0, "words": 0,
                    "lines": 0, "redirect_location": "https://b.example.test/new",
                    "calibration_used": False,
                },
            },
        ])

        async with api_client() as ac:
            base = f"/api/v1/assets/project/{pid}/content-paths"

            all_res = await ac.get(base)
            assert all_res.status_code == 200, all_res.text
            all_body = all_res.json()
            assert all_body["total"] == 3
            item = all_body["items"][0]
            for key in (
                "value", "host", "status_code", "content_length", "words",
                "lines", "redirect_location", "calibration_used",
                "first_seen", "last_seen",
            ):
                assert key in item

            host_res = await ac.get(base, params={"host": "a.example.test"})
            assert host_res.json()["total"] == 2
            assert all(i["host"] == "a.example.test" for i in host_res.json()["items"])

            status_res = await ac.get(base, params={"status_code": 403})
            assert status_res.json()["total"] == 1
            assert status_res.json()["items"][0]["status_code"] == 403
            assert status_res.json()["items"][0]["redirect_location"] == "/login"

            after_res = await ac.get(base, params={"first_seen_after": "2026-01-02T00:00:00"})
            assert after_res.json()["total"] == 1
            assert after_res.json()["items"][0]["host"] == "a.example.test"
            assert after_res.json()["items"][0]["status_code"] == 403

            page_res = await ac.get(base, params={"page": 2, "limit": 1})
            page_body = page_res.json()
            assert page_body["total"] == 3
            assert page_body["page"] == 2
            assert page_body["limit"] == 1
            assert len(page_body["items"]) == 1
    finally:
        await teardown_real_test_db(client, db, old_db, old_is_mock)


@pytest.mark.asyncio
async def test_targeted_arjun_run_flow_records_phase_and_history_real_mongo(monkeypatch):
    from app.providers.param_discovery_provider import ParamDiscoveryProvider

    calls = []

    async def fake_discover(self, targets, **kwargs):
        calls.append({"targets": list(targets), "kwargs": kwargs})
        yield {
            "type": "param_event",
            "data": {
                "host": "app.example.test",
                "endpoint": "https://app.example.test/search",
                "param": "q",
                "url": "https://app.example.test/search?q=FUZZ",
            },
        }
        yield {
            "type": "asset",
            "data": {
                "domain": "app.example.test",
                "type": "param",
                "value": "https://app.example.test/search?q",
                "status": "live",
                "metadata": {
                    "endpoint": "https://app.example.test/search",
                    "param_name": "q",
                    "parameterized_url": "https://app.example.test/search?q=FUZZ",
                    "source": "param_discovery",
                },
                "discovered_by": "arjun",
                "sources": ["param_discovery"],
            },
        }
        yield {
            "type": "url_event",
            "data": {
                "url": "https://app.example.test/search?q=FUZZ",
                "source": "param_discovery",
                "sources": ["param_discovery"],
            },
        }
        yield {"type": "scan_summary", "provider": "arjun", "status": "completed", "count": 1}

    monkeypatch.setattr(ParamDiscoveryProvider, "discover", fake_discover)

    client, db, old_db, old_is_mock = await setup_real_test_db()
    project_id = ObjectId()
    try:
        pid = str(project_id)
        await db.projects.insert_one({
            "_id": project_id,
            "name": "Stage3 Targeted",
            "scope": {"in_scope": ["*.example.test"], "out_of_scope": []},
            "rate_limits": {"global_rps": 10, "per_tool": {"arjun": 5}},
        })

        async with api_client() as ac:
            res = await ac.post(f"/api/v1/jobs/project/{pid}/targeted", json={
                "tool": "arjun",
                "hosts": ["https://app.example.test", "https://out.example.org"],
                "time_cap_seconds": 30,
            })
            assert res.status_code == 200, res.text
            job = res.json()
            assert job["job_kind"] == "targeted"
            assert job["targeted"]["hosts"] == ["https://app.example.test"]

            job_res = await ac.get(f"/api/v1/jobs/{job['id']}")
            assert job_res.status_code == 200
            job_doc = job_res.json()
            assert job_doc["status"] == "completed"
            assert "param_discovery" in (job_doc.get("executed_phases") or [])
            assert job_doc.get("phase_durations")

        assert len(calls) == 1
        assert calls[0]["targets"] == ["https://app.example.test"]
        assert calls[0]["kwargs"]["rate_limit"] == 5

        param_asset = await db.assets.find_one({
            "project_id": pid,
            "type": "param",
            "value": "https://app.example.test/search?q",
        })
        assert param_asset is not None
        assert param_asset["scan_id"] == job["id"]

        run_assets = await db.run_assets.find({
            "project_id": pid, "job_id": job["id"], "type": "param",
        }).to_list(10)
        assert run_assets

        run_doc = await db.scan_runs.find_one({"job_id": job["id"]})
        assert run_doc is not None
        assert run_doc["run_kind"] == "targeted"
        assert run_doc.get("phase_durations")
    finally:
        shutil.rmtree(os.path.join(RUNS_BASE_DIR, str(project_id)), ignore_errors=True)
        await teardown_real_test_db(client, db, old_db, old_is_mock)


@pytest.mark.asyncio
async def test_content_paths_raise_hunt_priority_real_mongo():
    client, db, old_db, old_is_mock = await setup_real_test_db()
    try:
        project_id = ObjectId()
        pid = str(project_id)
        await db.projects.insert_one({"_id": project_id, "name": "Hunt Content"})

        base_host = {
            "project_id": pid,
            "type": "subdomain",
            "status": "live",
            "open_ports": [443],
            "metadata": {"status_code": 200, "url": "https://app.example.test"},
        }
        await db.assets.insert_many([
            {**base_host, "domain": "app.example.test", "metadata": {
                "status_code": 200, "url": "https://app.example.test",
                "technologies": ["nginx"],
            }},
            {**base_host, "domain": "other.example.test", "metadata": {
                "status_code": 200, "url": "https://other.example.test",
                "technologies": ["nginx"],
            }},
            {
                "project_id": pid,
                "type": "content_path",
                "domain": "app.example.test",
                "value": "https://app.example.test/admin",
                "status": "live",
                "status_code": 200,
                "metadata": {"host": "app.example.test", "url": "https://app.example.test/admin", "status_code": 200},
            },
            {
                "project_id": pid,
                "type": "content_path",
                "domain": "app.example.test",
                "value": "https://app.example.test/private",
                "status": "live",
                "status_code": 403,
                "metadata": {"host": "app.example.test", "url": "https://app.example.test/private", "status_code": 403},
            },
        ])

        scored = await recalculate_all_scores(pid)
        by_asset = {s["asset"]: s for s in scored}
        assert "app.example.test" in by_asset
        assert "other.example.test" in by_asset
        assert by_asset["app.example.test"]["hunt_priority"] > by_asset["other.example.test"]["hunt_priority"]

        reasons = " ".join(by_asset["app.example.test"].get("hunt_reasons") or [])
        assert "content paths" in reasons.lower()
    finally:
        await teardown_real_test_db(client, db, old_db, old_is_mock)


@pytest.mark.asyncio
async def test_targeted_js_files_persists_multiple_values_real_mongo(monkeypatch):
    from app.providers.subjs_provider import SubjsProvider

    async def fake_discover(self, targets, **kwargs):
        for js_url in (
            "https://app.example.test/a.js",
            "https://app.example.test/b.js",
        ):
            yield {
                "type": "asset",
                "data": {
                    "domain": js_url,
                    "type": "js_file",
                    "status": "live",
                    "metadata": {
                        "url": js_url,
                        "host": "app.example.test",
                        "size": "unknown",
                        "source": "subjs",
                    },
                    "discovered_by": "subjs",
                    "sources": ["subjs"],
                },
            }
            yield {
                "type": "js_event",
                "data": {
                    "url": js_url,
                    "host": "app.example.test",
                    "size": "unknown",
                    "source": "subjs",
                },
            }

    monkeypatch.setattr(SubjsProvider, "discover", fake_discover)

    client, db, old_db, old_is_mock = await setup_real_test_db()
    project_id = ObjectId()
    try:
        pid = str(project_id)
        await db.projects.insert_one({
            "_id": project_id,
            "name": "Targeted JS Files",
            "scope": {"in_scope": ["*.example.test"], "out_of_scope": []},
        })
        async with api_client() as ac:
            res = await ac.post(f"/api/v1/jobs/project/{pid}/targeted", json={
                "tool": "js_files",
                "hosts": ["https://app.example.test/"],
                "time_cap_seconds": 30,
            })
            assert res.status_code == 200, res.text
            job = res.json()
            job_doc = (await ac.get(f"/api/v1/jobs/{job['id']}")).json()
            assert job_doc["status"] == "completed", job_doc.get("logs")

        docs = await db.assets.find({
            "project_id": pid,
            "type": "js_file",
        }).to_list(10)
        assert {d.get("value") for d in docs} == {
            "https://app.example.test/a.js",
            "https://app.example.test/b.js",
        }
        assert all(d.get("value") for d in docs)
    finally:
        shutil.rmtree(os.path.join(RUNS_BASE_DIR, pid), ignore_errors=True)
        await teardown_real_test_db(client, db, old_db, old_is_mock)


@pytest.mark.asyncio
async def test_live_hosts_endpoint_excludes_resolved_only_real_mongo():
    client, db, old_db, old_is_mock = await setup_real_test_db()
    try:
        project_id = ObjectId()
        pid = str(project_id)
        await db.projects.insert_one({"_id": project_id, "name": "Live Hosts"})

        await db.assets.insert_many([
            {
                "project_id": pid, "type": "subdomain",
                "domain": "app.example.test", "status": "live",
                "metadata": {"url": "https://app.example.test", "dnsx": {"a": ["1.2.3.4"]}},
            },
            {
                "project_id": pid, "type": "subdomain",
                "domain": "api.example.test", "status": "live",
                "metadata": {"dnsx": {"a": ["1.2.3.5"]}},
            },
            {
                "project_id": pid, "type": "subdomain",
                "domain": "old.example.test", "status": "resolved",
                "metadata": {"dnsx": {"a": ["1.2.3.6"]}},
            },
            {
                "project_id": pid, "type": "subdomain",
                "domain": "candidate.example.test", "status": "candidate",
                "metadata": {},
            },
            {
                "project_id": pid, "type": "host",
                "domain": "host.example.test", "status": "live",
                "metadata": {"url": "http://host.example.test:8080"},
            },
        ])

        async with api_client() as ac:
            res = await ac.get(f"/api/v1/assets/project/{pid}/live-hosts")
            assert res.status_code == 200, res.text
            body = res.json()

            by_host = {item["host"]: item for item in body["hosts"]}
            assert set(by_host) == {
                "app.example.test", "api.example.test", "host.example.test",
            }
            assert by_host["app.example.test"]["url"] == "https://app.example.test"
            assert by_host["api.example.test"]["url"] == "https://api.example.test"
            assert by_host["host.example.test"]["url"] == "http://host.example.test:8080"
            assert body["dns_record_count"] == 3
    finally:
        await teardown_real_test_db(client, db, old_db, old_is_mock)


@pytest.mark.asyncio
async def test_host_urls_endpoint_returns_complete_prioritized_set_real_mongo():
    client, db, old_db, old_is_mock = await setup_real_test_db()
    try:
        project_id = ObjectId()
        pid = str(project_id)
        await db.projects.insert_one({"_id": project_id, "name": "Host URLs"})

        await db.assets.insert_many([
            {
                "project_id": pid, "type": "subdomain",
                "domain": "app.example.test", "status": "live",
                "metadata": {
                    "url": "https://app.example.test",
                    "katana": {
                        "urls": ["https://app.example.test/login"],
                        "endpoints": ["https://app.example.test/api/v1/users"],
                        "js_files": ["https://app.example.test/static/app.js"],
                    },
                },
            },
            {
                "project_id": pid, "type": "uro_url",
                "domain": "https://app.example.test/search?q=x",
                "value": "https://app.example.test/search?q=x",
                "status": "live", "metadata": {},
            },
            {
                "project_id": pid, "type": "content_path",
                "domain": "app.example.test",
                "value": "https://app.example.test/admin",
                "status": "live",
                "metadata": {"url": "https://app.example.test/admin"},
            },
            {
                "project_id": pid, "type": "historical_dead",
                "domain": "app.example.test",
                "value": "https://app.example.test/dead",
                "status": "dead", "metadata": {},
            },
            {
                "project_id": pid, "type": "content_path",
                "domain": "other.example.test",
                "value": "https://other.example.test/admin",
                "status": "live",
                "metadata": {"url": "https://other.example.test/admin"},
            },
        ])

        async with api_client() as ac:
            res = await ac.get(
                f"/api/v1/assets/project/{pid}/host-urls",
                params={"host": "app.example.test"},
            )
            assert res.status_code == 200, res.text
            body = res.json()

            expected = {
                "https://app.example.test",
                "https://app.example.test/login",
                "https://app.example.test/api/v1/users",
                "https://app.example.test/static/app.js",
                "https://app.example.test/search?q=x",
                "https://app.example.test/admin",
            }
            assert set(body["urls"]) == expected
            assert body["count"] == len(expected)
            assert body["urls"][0] == "https://app.example.test/search?q=x"
            assert body["urls"].index(
                "https://app.example.test/admin"
            ) < body["urls"].index("https://app.example.test/static/app.js")
    finally:
        await teardown_real_test_db(client, db, old_db, old_is_mock)
