"""Selective body fetching/storage tests."""

import os
import uuid

import httpx
import pytest
from bson import ObjectId
from motor.motor_asyncio import AsyncIOMotorClient

import app.database as database_module
import app.services.body_fetch as body_fetch
from app.main import app


async def setup_real_test_db():
    mongo_uri = os.getenv("MONGO_URI", "mongodb://localhost:27017")
    client = AsyncIOMotorClient(mongo_uri, serverSelectionTimeoutMS=2000)
    try:
        await client.admin.command("ping")
    except Exception as exc:
        pytest.skip(f"Real MongoDB is not running at {mongo_uri}: {exc}")
    test_db_name = f"reconforge_body_fetch_{uuid.uuid4().hex[:8]}"
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
async def test_auto_store_bodies_dedupes_scope_and_caps(monkeypatch):
    calls = []

    async def fake_fetch(project_id, url, **kwargs):
        calls.append((project_id, url, kwargs))
        return {"ok": True, "stored": True, "url": url}

    monkeypatch.setattr(body_fetch, "fetch_and_store", fake_fetch)

    result = await body_fetch.auto_store_bodies(
        "project-1",
        [
            "https://a.example.com/one",
            "https://a.example.com/one",
            "https://b.other.com/two",
            "https://c.example.com/three",
            "https://d.example.com/four",
        ],
        scope={"in_scope": ["*.example.com"], "out_of_scope": []},
        limit=2,
        concurrency=1,
    )

    assert result["requested"] == 2
    assert result["stored"] == 2
    assert [call[1] for call in calls] == [
        "https://a.example.com/one",
        "https://c.example.com/three",
    ]
    assert all(call[0] == "project-1" for call in calls)


@pytest.mark.asyncio
async def test_fetch_body_endpoint_uses_project_scope_and_cap(monkeypatch):
    captured = {}

    async def fake_fetch(project_id, url, **kwargs):
        captured.update({"project_id": project_id, "url": url, **kwargs})
        return {
            "ok": True,
            "url": url,
            "status_code": 200,
            "content_type": "text/html",
            "body_preview": "<html>ok</html>",
        }

    monkeypatch.setattr(body_fetch, "fetch_and_store", fake_fetch)

    client, db, old_db, old_is_mock = await setup_real_test_db()
    project_id = ObjectId()
    try:
        pid = str(project_id)
        await db.projects.insert_one({
            "_id": project_id,
            "name": "Body Fetch",
            "scope": {"in_scope": ["*.example.test"], "out_of_scope": []},
            "response_body_max_kb": 123,
        })
        async with api_client() as ac:
            res = await ac.post(
                f"/api/v1/assets/project/{pid}/fetch-body",
                json={"url": "https://app.example.test/page", "force": True},
            )
            assert res.status_code == 200, res.text
            body = res.json()
            assert body["status_code"] == 200
            assert body["body_preview"] == "<html>ok</html>"

            empty = await ac.post(
                f"/api/v1/assets/project/{pid}/fetch-body",
                json={"url": ""},
            )
            assert empty.status_code == 400

        assert captured["url"] == "https://app.example.test/page"
        assert captured["max_kb"] == 123
        assert captured["force"] is True
        assert captured["scope"] == {"in_scope": ["*.example.test"], "out_of_scope": []}
    finally:
        await teardown_real_test_db(client, db, old_db, old_is_mock)
