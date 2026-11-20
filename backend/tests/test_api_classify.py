"""API URL classification, API inventory endpoint and targeted fuzz tests."""

import os
import uuid

import httpx
import pytest
from bson import ObjectId
from motor.motor_asyncio import AsyncIOMotorClient

import app.database as database_module
from app.main import app
from app.services.api_classify import classify_api_and_store, classify_api_url


async def setup_real_test_db():
    mongo_uri = os.getenv("MONGO_URI", "mongodb://localhost:27017")
    client = AsyncIOMotorClient(mongo_uri, serverSelectionTimeoutMS=2000)
    try:
        await client.admin.command("ping")
    except Exception as exc:
        pytest.skip(f"Real MongoDB is not running at {mongo_uri}: {exc}")
    test_db_name = f"reconforge_api_{uuid.uuid4().hex[:8]}"
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


def test_classify_api_url_patterns():
    cases = {
        "https://example.com/api/users": "rest",
        "https://example.com/api/v1/users?id=1": "rest",
        "https://example.com/v2/orders": "rest",
        "https://example.com/graphql": "graphql",
        "https://example.com/swagger.json": "openapi",
        "https://example.com/v3/api-docs": "openapi",
        "https://example.com/wp-json/wp/v2/posts": "rest",
        "https://example.com/odata/Users": "odata",
        "https://example.com/rpc": "rpc",
        "https://example.com/service.wsdl": "soap",
        "https://api.example.com": "rest",
    }
    for url, expected in cases.items():
        info = classify_api_url(url)
        assert info and info["api_type"] == expected, (url, info)

    param_info = classify_api_url("https://example.com/api/users?id=1&role=admin")
    assert param_info and param_info["params"] == ["id", "role"]

    assert classify_api_url("https://example.com/assets/app.js") is None
    assert classify_api_url("https://example.com/about") is None


@pytest.mark.asyncio
async def test_api_endpoints_endpoint_merges_dynamic_urls_real_mongo():
    client, db, old_db, old_is_mock = await setup_real_test_db()
    project_id = ObjectId()
    try:
        pid = str(project_id)
        await db.projects.insert_one({"_id": project_id, "name": "API"})
        await db.assets.insert_many([
            {
                "project_id": pid, "type": "content_path",
                "domain": "app.example.test",
                "value": "https://app.example.test/api/users",
                "metadata": {"url": "https://app.example.test/api/users", "source": "ffuf"},
            },
            {
                "project_id": pid, "type": "content_path",
                "domain": "app.example.test",
                "value": "https://app.example.test/assets/app.js",
                "metadata": {"url": "https://app.example.test/assets/app.js"},
            },
            {
                "project_id": pid, "type": "api_spec",
                "domain": "app.example.test",
                "value": "https://app.example.test/openapi.json",
                "metadata": {"url": "https://app.example.test/openapi.json", "format": "openapi_v3"},
            },
            {
                "project_id": pid, "type": "graphql_endpoint",
                "domain": "app.example.test",
                "value": "https://app.example.test/graphql",
                "metadata": {"url": "https://app.example.test/graphql"},
            },
            {
                "project_id": pid, "type": "param",
                "domain": "app.example.test",
                "value": "https://app.example.test/api/users?role=",
                "metadata": {
                    "endpoint": "https://app.example.test/api/users",
                    "param_name": "role",
                    "host": "app.example.test",
                    "source": "param_discovery",
                },
            },
        ])

        store_res = await classify_api_and_store(pid, {
            "https://app.example.test/api/users": {"app.example.test"},
        })
        assert store_res["total"] == 1

        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="http://testserver",
        ) as ac:
            res = await ac.get(f"/api/v1/assets/project/{pid}/api-endpoints")
            assert res.status_code == 200, res.text
            body = res.json()
            urls = {item["url"] for item in body["items"]}
            assert "https://app.example.test/api/users" in urls
            assert "https://app.example.test/openapi.json" in urls
            assert "https://app.example.test/graphql" in urls
            assert "https://app.example.test/assets/app.js" not in urls
            by_url = {item["url"]: item for item in body["items"]}
            assert by_url["https://app.example.test/graphql"]["api_type"] == "graphql"
            assert by_url["https://app.example.test/openapi.json"]["api_type"] == "openapi"
            assert "role" in by_url["https://app.example.test/api/users"]["params"]
    finally:
        await teardown_real_test_db(client, db, old_db, old_is_mock)


@pytest.mark.asyncio
async def test_targeted_ffuf_accepts_api_paths(monkeypatch):
    from app.providers.ffuf_provider import FfufProvider

    received = []

    async def fake_discover_content(self, targets, **kwargs):
        received.extend(targets)
        yield {"type": "scan_summary", "provider": "ffuf", "status": "completed", "count": 0}

    monkeypatch.setattr(FfufProvider, "discover_content", fake_discover_content)

    client, db, old_db, old_is_mock = await setup_real_test_db()
    project_id = ObjectId()
    try:
        pid = str(project_id)
        await db.projects.insert_one({
            "_id": project_id,
            "name": "API Fuzz",
            "scope": {"in_scope": ["*"], "out_of_scope": []},
        })
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="http://testserver",
        ) as ac:
            res = await ac.post(f"/api/v1/jobs/project/{pid}/targeted", json={
                "tool": "ffuf",
                "hosts": ["https://app.example.test/api"],
                "time_cap_seconds": 30,
            })
            assert res.status_code == 200, res.text
            job = res.json()
            job_doc = (await ac.get(f"/api/v1/jobs/{job['id']}")).json()
            assert job_doc["status"] == "completed", job_doc.get("logs")

        assert received == ["https://app.example.test/api"]
    finally:
        await teardown_real_test_db(client, db, old_db, old_is_mock)
