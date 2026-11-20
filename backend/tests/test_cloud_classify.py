"""Cloud URL classification and cloud-services endpoint tests."""

import os
import uuid

import httpx
import pytest
from bson import ObjectId
from motor.motor_asyncio import AsyncIOMotorClient

import app.database as database_module
from app.main import app
from app.services.cloud_classify import classify_and_store, classify_cloud_url


async def setup_real_test_db():
    mongo_uri = os.getenv("MONGO_URI", "mongodb://localhost:27017")
    client = AsyncIOMotorClient(mongo_uri, serverSelectionTimeoutMS=2000)
    try:
        await client.admin.command("ping")
    except Exception as exc:
        pytest.skip(f"Real MongoDB is not running at {mongo_uri}: {exc}")
    test_db_name = f"reconforge_cloud_{uuid.uuid4().hex[:8]}"
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


def test_classify_cloud_url_patterns():
    s3 = classify_cloud_url("https://bucket.s3.amazonaws.com/file.txt")
    assert s3 and s3["provider"] == "aws" and s3["service"] == "s3"
    assert s3["bucket_name"] == "bucket"

    path_style = classify_cloud_url(
        "https://s3.us-east-1.amazonaws.com/my-bucket/app.js"
    )
    assert path_style and path_style["bucket_name"] == "my-bucket"

    cloudfront = classify_cloud_url("https://d111.cloudfront.net/")
    assert cloudfront and cloudfront["service"] == "cloudfront"

    ec2 = classify_cloud_url(
        "https://ec2-3-24-147-190.ap-southeast-2.compute.amazonaws.com/"
    )
    assert ec2 and ec2["service"] == "ec2"

    gcs = classify_cloud_url("https://storage.googleapis.com/my-gcs-bucket/x")
    assert gcs and gcs["provider"] == "gcp" and gcs["bucket_name"] == "my-gcs-bucket"

    azure = classify_cloud_url(
        "https://account.blob.core.windows.net/container/blob"
    )
    assert azure and azure["provider"] == "azure"

    assert classify_cloud_url("https://example.com/not-cloud") is None


@pytest.mark.asyncio
async def test_classify_store_and_cloud_services_endpoint_real_mongo():
    client, db, old_db, old_is_mock = await setup_real_test_db()
    project_id = ObjectId()
    try:
        pid = str(project_id)
        await db.projects.insert_one({"_id": project_id, "name": "Cloud"})

        result = await classify_and_store(pid, {
            "https://bucket.s3.amazonaws.com/a": {"app.example.test"},
            "https://d111.cloudfront.net/x": {"app.example.test"},
            "https://example.com/plain": {"app.example.test"},
        })
        assert result["total"] == 2
        assert result["by_provider"] == {"aws": 2}

        stored = await db.assets.find({
            "project_id": pid,
            "type": "cloud_service",
        }).to_list(10)
        assert len(stored) == 2
        by_host = {doc["domain"]: doc for doc in stored}
        assert by_host["bucket.s3.amazonaws.com"]["metadata"]["parent_hosts"] == [
            "app.example.test"
        ]

        await db.assets.insert_one({
            "project_id": pid,
            "type": "bucket",
            "domain": "other.s3.amazonaws.com",
            "value": "https://other.s3.amazonaws.com",
            "status": "live",
            "metadata": {
                "url": "https://other.s3.amazonaws.com",
                "provider": "aws",
                "public": True,
                "in_scope_keyword": "example",
            },
        })

        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="http://testserver",
        ) as ac:
            res = await ac.get(f"/api/v1/assets/project/{pid}/cloud-services")
            assert res.status_code == 200, res.text
            body = res.json()
            assert body["total"] == 3
            assert body["providers"]["aws"] == 3
    finally:
        await teardown_real_test_db(client, db, old_db, old_is_mock)
