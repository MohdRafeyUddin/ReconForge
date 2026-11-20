"""Stage 2 Phase 8 — JS storage, secret schema, buckets, Nuclei, OAST, diffs."""

import gzip
import hashlib
import json
import os
import shutil
import uuid
from datetime import datetime, timedelta

import httpx
import pytest
from bson import ObjectId
from motor.motor_asyncio import AsyncIOMotorClient

import app.database as database_module
from app.core.redaction import redact_cmd_args, redact_text
from app.main import app
from app.providers.js_analysis_provider import (
    JS_STORAGE_ROOT,
    JsAnalysisProvider,
    save_js_body,
    save_sourcemap_file_list,
)
from app.providers.cloud_enum_provider import CloudEnumProvider
from app.providers.secrets_provider import SecretsProvider
from app.providers.nuclei_provider import (
    NUCLEI_HOST_PASSES,
    NUCLEI_PASSES,
    NucleiProvider,
)
from app.providers.unified_discovery_provider import TECH_TAG_MAP
from app.routers.jobs import manager as ws_manager
from app.routers.reports import collect_export_urls
from app.services.diff_engine import compute_and_save_diff
from app.services.oast import OASTSession
from app.services.run_history import RUNS_BASE_DIR, record_run_asset, record_run_history


async def setup_real_test_db():
    mongo_uri = os.getenv("MONGO_URI", "mongodb://localhost:27017")
    client = AsyncIOMotorClient(mongo_uri, serverSelectionTimeoutMS=2000)
    try:
        await client.admin.command("ping")
    except Exception as exc:
        pytest.skip(f"Real MongoDB is not running at {mongo_uri}: {exc}")

    test_db_name = f"reconforge_stage2_{uuid.uuid4().hex[:8]}"
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


# ==============================================================================
# JS storage and recovered source-map list
# ==============================================================================

def test_js_body_stored_by_hash_and_sourcemap_list(tmp_path):
    project_id = f"p_{uuid.uuid4().hex[:8]}"
    body = b"const API='/api/v1/users';"
    rel = save_js_body(project_id, "a" * 64, body)
    try:
        assert rel == f"js/{project_id}/{'a' * 64}.js"
        full = os.path.join(JS_STORAGE_ROOT, rel)
        assert os.path.isfile(full)
        with open(full, "rb") as f:
            assert f.read() == body

        list_path = save_sourcemap_file_list(project_id, {
            "https://app.example.test/app.js": ["src/app.ts", "src/api.ts"],
        })
        assert list_path == f"js/{project_id}/sourcemap_recovered_files.json"
        with open(os.path.join(JS_STORAGE_ROOT, list_path), encoding="utf-8") as f:
            stored = json.load(f)
        assert stored["https://app.example.test/app.js"] == ["src/app.ts", "src/api.ts"]
    finally:
        shutil.rmtree(os.path.join(JS_STORAGE_ROOT, "js", project_id), ignore_errors=True)


# ==============================================================================
# Secret finding schema and masking (real MongoDB)
# ==============================================================================

@pytest.mark.asyncio
async def test_secret_finding_schema_identity_and_masking_real_mongo(monkeypatch):
    client, db, old_db, old_is_mock = await setup_real_test_db()
    project_id = ObjectId()
    js_rel = None
    try:
        pid = str(project_id)
        await db.projects.insert_one({"_id": project_id, "name": "Secrets"})
        raw_secret = "AKIAABCDEFGHIJKLMNOP"
        js_rel = save_js_body(pid, "b" * 64, f"const k='{raw_secret}';".encode("utf-8"))
        full_path = os.path.join(JS_STORAGE_ROOT, js_rel)
        await db.assets.insert_one({
            "project_id": pid,
            "type": "js_file",
            "value": "https://app.example.test/app.js",
            "domain": "app.example.test",
            "status": "live",
            "metadata": {
                "url": "https://app.example.test/app.js",
                "host": "app.example.test",
                "body_path": js_rel,
                "source": "js_analysis",
            },
        })

        record = json.dumps({
            "DetectorName": "AWS",
            "Verified": False,
            "Raw": raw_secret,
            "SourceMetadata": {"Data": {"Filesystem": {"file": full_path, "line": 4}}},
        })

        async def fake_run_tool(self, args, timeout):
            return 0, record, ""

        monkeypatch.setattr(
            SecretsProvider, "_strict_tool",
            lambda self, name: "/fake/trufflehog" if name == "trufflehog" else None,
        )
        monkeypatch.setattr(SecretsProvider, "_run_tool", fake_run_tool)

        provider = SecretsProvider()
        events = []
        async for ev in provider.scan(
            seed_domains=["example.test"],
            project_config={
                "project_id": pid,
                "scope": {"in_scope": ["*.example.test"], "out_of_scope": []},
                "secrets_scan": {"enabled": True, "max_files": 10, "timeout_seconds": 30},
            },
            scope={"in_scope": ["*.example.test"], "out_of_scope": []},
            extra_files=[{
                "path": js_rel,
                "url": "https://app.example.test/app.js",
                "host": "app.example.test",
                "source": "js_analysis",
            }],
        ):
            events.append(ev)

        assets = [e for e in events if e.get("type") == "asset"]
        assert len(assets) == 1
        data = assets[0]["data"]
        assert data["type"] == "secret_finding"
        meta = data["metadata"]
        assert meta["secret_type"] == "AWS"
        assert meta["location"].startswith("https://app.example.test/app.js:4")
        assert meta["masked_preview"].startswith("AKIA")
        assert meta["verified"] is False
        assert meta["identity_key"] == data["value"]
        assert len(meta["identity_key"]) == 32
        assert meta["value_hash"]
        assert raw_secret not in json.dumps(data)
        assert raw_secret not in json.dumps(events)

        # Stable identity key for same type+location+value hash
        parsed1 = SecretsProvider.parse_trufflehog_output([record], {full_path: {
            "url": "https://app.example.test/app.js", "host": "app.example.test"
        }})
        parsed2 = SecretsProvider.parse_trufflehog_output([record], {full_path: {
            "url": "https://app.example.test/app.js", "host": "app.example.test"
        }})
        assert parsed1[0]["key"] == parsed2[0]["key"]
    finally:
        if js_rel:
            shutil.rmtree(os.path.join(JS_STORAGE_ROOT, "js", str(project_id)), ignore_errors=True)
        await teardown_real_test_db(client, db, old_db, old_is_mock)


# ==============================================================================
# Bucket naming and read-only scope behaviour
# ==============================================================================

@pytest.mark.asyncio
async def test_cloud_enum_emits_bucket_type_in_registry_and_scope(monkeypatch):
    async def fake_run_tool(self, args, timeout):
        return 0, (
            "[+] Found: https://example-com-assets.s3.amazonaws.com (public)\n"
            "[+] Found: https://unrelated-bucket.s3.amazonaws.com (public)\n"
        ), ""

    monkeypatch.setattr(
        CloudEnumProvider, "_strict_tool",
        lambda self, name: "/fake/cloud_enum" if name == "cloud_enum" else None,
    )
    monkeypatch.setattr(CloudEnumProvider, "_run_tool", fake_run_tool)

    provider = CloudEnumProvider()
    scope = {"in_scope": ["*.example.test"], "out_of_scope": []}
    config = {
        "cloud_enum": {"enabled": True, "max_keywords": 5, "timeout_seconds": 30},
        "scope": scope,
    }
    events = []
    # "fast" proves the old deep-only gate is removed; opt-in config is the gate.
    async for ev in provider.enumerate(["example.test"], scan_mode="fast", project_config=config, scope=scope):
        events.append(ev)

    assets = [e for e in events if e.get("type") == "asset"]
    assert len(assets) == 1
    data = assets[0]["data"]
    assert data["type"] == "bucket"
    meta = data["metadata"]
    assert meta["bucket_name"] == "example-com-assets"
    assert meta["provider"] == "aws"
    assert meta["public"] is True
    assert meta["read_only"] is True
    assert meta["in_scope_keyword"]
    assert "unrelated" not in data["value"]
    assert not any(e.get("type") == "stage_error" for e in events)


# ==============================================================================
# Nuclei recon mode
# ==============================================================================

def test_nuclei_passes_have_no_default_login_and_tech_map_covers_spec():
    for p in NUCLEI_PASSES + NUCLEI_HOST_PASSES:
        assert "default-login" not in p.get("tags", "")
    for tech in ("jenkins", "grafana", "kibana", "tomcat", "phpmyadmin", "wordpress", "graphql", "swagger"):
        assert tech in TECH_TAG_MAP


@pytest.mark.asyncio
async def test_nuclei_run_passes_always_use_as_and_iserver(monkeypatch):
    import app.providers.nuclei_provider as np

    captured = {}
    oast_token = "SECRET-OAST-TOKEN-123456"

    class FakeProc:
        stdout = []
        returncode = 0
        def poll(self):
            return 0
        def wait(self, *args, **kwargs):
            return 0
        def terminate(self):
            pass
        def kill(self):
            pass

    def fake_popen(cmd, **kwargs):
        captured["cmd"] = list(cmd)
        return FakeProc()

    monkeypatch.setattr(np.subprocess, "Popen", fake_popen)

    provider = NucleiProvider()
    events = []
    async for ev in provider._run_passes(
        [{"name": "TestPass", "tags": "tech", "severity": "info"}],
        ["https://app.example.test"],
        "Nuclei Host Scan",
        rate_limit=10,
        oast_server="oast.example.test",
        oast_token=oast_token,
        template_dir="/tmp/templates",
    ):
        events.append(ev)

    cmd = captured.get("cmd") or []
    assert "-as" in cmd
    assert "-iserver" in cmd
    assert "oast.example.test" in cmd
    assert "-t" in cmd
    assert "/tmp/templates" in cmd

    # The full command is logged for every pass, but the OAST token is redacted.
    log_messages = [str(e.get("message") or "") for e in events if e.get("type") == "log"]
    assert any("Executing command" in m and "-as" in m for m in log_messages)
    assert all(oast_token not in m for m in log_messages)
    assert any("[REDACTED]" in m for m in log_messages)
    assert oast_token not in json.dumps(events, default=str)


# ==============================================================================
# OAST request correlation
# ==============================================================================

def test_oast_correlation_includes_originating_request_path():
    scope = {"in_scope": ["*.example.test"], "out_of_scope": []}
    interaction = {
        "protocol": "http",
        "raw-request": (
            "GET /api/callback?token=abc HTTP/1.1\r\n"
            "Host: app.example.test\r\n"
            "User-Agent: nuclei\r\n\r\n"
        ),
        "remote-address": "203.0.113.7",
    }
    finding = OASTSession.interaction_to_finding(interaction, scope, ["app.example.test"])
    assert finding is not None
    data = finding["data"]
    assert data["matched_url"] == "https://app.example.test/api/callback?token=abc"
    assert data["request_path"] == "/api/callback?token=abc"
    assert data["correlation"]["host"] == "app.example.test"
    assert data["remote_address"] == "203.0.113.7"


# ==============================================================================
# Diff integration and phase gating (real MongoDB)
# ==============================================================================

async def seed_phase8_diff_fixture(db, project_id, prev_job_id, current_job_id, phases_current, phases_prev, include_new=True):
    now = datetime.utcnow()
    await db.projects.insert_one({"_id": ObjectId(project_id), "name": "Phase8 Diff"})
    await db.jobs.insert_many([
        {
            "_id": ObjectId(prev_job_id),
            "project_id": project_id,
            "status": "completed",
            "scan_mode": "full",
            "job_kind": "full",
            "started_at": now - timedelta(hours=2),
            "finished_at": now - timedelta(hours=1, minutes=50),
            "executed_phases": phases_prev,
            "liveness_version": 2,
        },
        {
            "_id": ObjectId(current_job_id),
            "project_id": project_id,
            "status": "completed",
            "scan_mode": "full",
            "job_kind": "full",
            "started_at": now - timedelta(minutes=5),
            "finished_at": now,
            "executed_phases": phases_current,
            "liveness_version": 2,
        },
    ])
    if include_new:
        await db.assets.insert_many([
            {
                "project_id": project_id,
                "type": "secret_finding",
                "value": "a" * 32,
                "domain": "app.example.test",
                "status": "live",
                "scan_id": current_job_id,
                "first_seen": now,
                "last_seen": now,
                "metadata": {
                    "identity_key": "a" * 32,
                    "secret_type": "AWS",
                    "host": "app.example.test",
                    "location_url": "https://app.example.test/app.js",
                    "location": "https://app.example.test/app.js:4",
                    "line": 4,
                    "masked_preview": "AKIA****",
                    "value_hash": "deadbeef",
                },
            },
            {
                "project_id": project_id,
                "type": "bucket",
                "value": "https://example-com-assets.s3.amazonaws.com",
                "domain": "example-com-assets.s3.amazonaws.com",
                "status": "live",
                "scan_id": current_job_id,
                "first_seen": now,
                "last_seen": now,
                "metadata": {
                    "url": "https://example-com-assets.s3.amazonaws.com",
                    "host": "example-com-assets.s3.amazonaws.com",
                    "bucket_name": "example-com-assets",
                    "provider": "aws",
                    "public": True,
                    "in_scope_keyword": "example.test",
                },
            },
            {
                "project_id": project_id,
                "type": "recon_info",
                "value": "tech-detect:https://app.example.test/",
                "domain": "app.example.test",
                "status": "live",
                "scan_id": current_job_id,
                "first_seen": now,
                "last_seen": now,
                "metadata": {
                    "template_id": "tech-detect",
                    "template_name": "Technology Detection",
                    "matched_url": "https://app.example.test/",
                    "host": "app.example.test",
                    "severity": "info",
                },
            },
        ])


@pytest.mark.asyncio
async def test_diff_reports_new_secrets_buckets_recon_info_when_phases_ran_real_mongo():
    client, db, old_db, old_is_mock = await setup_real_test_db()
    try:
        project_id = str(ObjectId())
        prev_job_id = str(ObjectId())
        current_job_id = str(ObjectId())
        phases = ["subdomain_discovery", "secret_scan", "cloud_enum", "vulnerability_scan", "js_analysis"]
        await seed_phase8_diff_fixture(db, project_id, prev_job_id, current_job_id, phases, phases)

        diff = await compute_and_save_diff(project_id, current_job_id, db)
        summary = diff["summary"]
        assert summary["new_secret_findings_count"] == 1
        assert summary["new_buckets_count"] == 1
        assert summary["new_recon_info_count"] == 1
        assert diff["diff"]["new_secret_findings"][0]["masked_preview"] == "AKIA****"
        assert diff["diff"]["new_buckets"][0]["public"] is True
        assert diff["diff"]["new_recon_info"][0]["severity"] == "info"
        assert "AKIAABCDEFGHIJKLMNOP" not in json.dumps(diff, default=str)
    finally:
        await teardown_real_test_db(client, db, old_db, old_is_mock)


@pytest.mark.asyncio
async def test_diff_baselines_phase8_types_when_phases_did_not_run_in_both_real_mongo():
    client, db, old_db, old_is_mock = await setup_real_test_db()
    try:
        project_id = str(ObjectId())
        prev_job_id = str(ObjectId())
        current_job_id = str(ObjectId())
        await seed_phase8_diff_fixture(
            db, project_id, prev_job_id, current_job_id,
            phases_current=["subdomain_discovery"],
            phases_prev=["subdomain_discovery"],
        )

        diff = await compute_and_save_diff(project_id, current_job_id, db)
        summary = diff["summary"]
        assert summary["new_secret_findings_count"] == 0
        assert summary["new_buckets_count"] == 0
        assert summary["new_recon_info_count"] == 0
    finally:
        await teardown_real_test_db(client, db, old_db, old_is_mock)


# ==============================================================================
# Stage 2 fixes — HMAC value hashes, raw-output policy, scope, secret leaks
# ==============================================================================

def test_secret_value_hash_uses_local_hmac_key(monkeypatch, tmp_path):
    import app.providers.secrets_provider as sp

    key_path = tmp_path / "secret_values.key"
    monkeypatch.setattr(sp, "SECRET_HMAC_KEY_PATH", str(key_path))
    monkeypatch.setattr(sp, "_HMAC_KEY_CACHE", None)

    raw = "AKIAIOSFODNN7EXAMPLE"
    digest1 = sp._secret_value_hash(raw)
    digest2 = sp._secret_value_hash(raw)

    assert key_path.is_file()
    key_hex = key_path.read_text(encoding="utf-8").strip()
    assert len(key_hex) == 64
    assert digest1 == digest2
    assert digest1 != hashlib.sha256(raw.encode()).hexdigest()
    assert raw not in digest1


@pytest.mark.asyncio
async def test_sourcemapper_map_urls_are_scope_checked_before_fetch():
    provider = JsAnalysisProvider()
    scope = {"in_scope": ["*.example.test"], "out_of_scope": []}
    body = "x();\n//# sourceMappingURL=https://evil.test/app.map\n"

    allowed, urls, reason = await provider._sourcemap_targets_in_scope(
        "https://app.example.test/app.js", body, scope, 5
    )
    assert allowed is False
    assert urls == []
    assert "out_of_scope_map" in reason

    allowed_no_scope, urls_no_scope, reason_no_scope = await provider._sourcemap_targets_in_scope(
        "https://app.example.test/app.js", body, None, 5
    )
    assert allowed_no_scope is True
    assert urls_no_scope == ["https://evil.test/app.map"]
    assert reason_no_scope == "ok"


def test_redact_cmd_args_covers_oast_tokens_and_secret_flags():
    args = [
        "nuclei", "-interactsh-token", "SECRET-OAST-TOKEN",
        "-iserver", "oast.example.test", "--itoken=SECRET-ITOKEN",
        "-as", "-token", "ANOTHER-TOKEN",
    ]
    redacted = redact_cmd_args(args)
    joined = " ".join(redacted)
    assert "SECRET-OAST-TOKEN" not in joined
    assert "SECRET-ITOKEN" not in joined
    assert "ANOTHER-TOKEN" not in joined
    assert "oast.example.test" in joined
    assert "-as" in redacted
    assert joined.count("[REDACTED]") >= 3


@pytest.mark.asyncio
async def test_takeover_nuclei_is_tags_only_and_logs_redacted_command(monkeypatch):
    import app.providers.takeover_crosscheck_provider as tcp

    captured = {}

    class FakeProc:
        stdout = ""
        stderr = ""
        returncode = 0
        def communicate(self, timeout=None):
            return "", ""
        def poll(self):
            return 0
        def wait(self, *args, **kwargs):
            return 0
        def kill(self):
            pass
        def terminate(self):
            pass

    def fake_popen(cmd, **kwargs):
        captured["cmd"] = list(cmd)
        return FakeProc()

    monkeypatch.setattr(
        tcp, "get_tool_path",
        lambda name: "/usr/bin/nuclei" if name == "nuclei" else None,
    )
    monkeypatch.setattr(tcp.subprocess, "Popen", fake_popen)

    provider = tcp.TakeoverCrossCheckProvider()
    events = []
    async for ev in provider.check_takeovers(["app.example.test"]):
        events.append(ev)

    cmd = captured.get("cmd") or []
    assert "-tags" in cmd
    assert "takeover" in cmd
    assert "-as" not in cmd

    log_messages = [str(e.get("message") or "") for e in events if e.get("type") == "log"]
    assert any("Executing command" in m and "takeover" in m and "-as" not in m for m in log_messages)


class _FakeWS:
    def __init__(self):
        self.messages = []

    async def send_json(self, message):
        self.messages.append(message)


@pytest.mark.asyncio
async def test_planted_aws_secret_never_leaks_anywhere_real_mongo(monkeypatch):
    from app.providers.secrets_provider import SECRET_HMAC_KEY_PATH
    from app.providers.secrets_provider import _load_hmac_key as _ensure_key

    _ensure_key()

    fake_secret = "AKIAIOSFODNN7EXAMPLE"
    client, db, old_db, old_is_mock = await setup_real_test_db()
    project_id = ObjectId()
    job_id = ObjectId()
    js_rel = None
    fake_ws = _FakeWS()
    try:
        pid = str(project_id)
        job_str = str(job_id)
        await db.projects.insert_one({"_id": project_id, "name": "Leak Test"})
        await db.jobs.insert_one({
            "_id": job_id,
            "project_id": pid,
            "status": "completed",
            "scan_mode": "full",
            "job_kind": "full",
            "started_at": datetime.utcnow(),
            "finished_at": datetime.utcnow(),
            "logs": [],
        })

        js_rel = save_js_body(pid, "d" * 64, f"const AWS_KEY='{fake_secret}';\n".encode("utf-8"))
        js_full = os.path.join(JS_STORAGE_ROOT, js_rel)
        await db.assets.insert_one({
            "project_id": pid,
            "type": "js_file",
            "value": "https://app.example.test/app.js",
            "domain": "app.example.test",
            "status": "live",
            "metadata": {
                "url": "https://app.example.test/app.js",
                "host": "app.example.test",
                "body_path": js_rel,
                "source": "js_analysis",
            },
            "open_ports": [],
            "discovered_by": "js_analysis",
            "sources": ["js_analysis"],
        })

        scan_output = json.dumps({
            "DetectorName": "AWS",
            "Verified": False,
            "Raw": fake_secret,
            "SourceMetadata": {"Data": {"Filesystem": {"file": js_full, "line": 1}}},
        })

        async def fake_run_tool(self, args, timeout):
            return 0, scan_output, f"stderr echoes {fake_secret}"

        monkeypatch.setattr(
            SecretsProvider, "_strict_tool",
            lambda self, name: "/fake/trufflehog" if name == "trufflehog" else None,
        )
        monkeypatch.setattr(SecretsProvider, "_run_tool", fake_run_tool)

        provider = SecretsProvider()
        events = []
        scope = {"in_scope": ["*.example.test"], "out_of_scope": []}
        async for ev in provider.scan(
            seed_domains=["example.test"],
            project_config={
                "project_id": pid,
                "scope": scope,
                "secrets_scan": {"enabled": True, "max_files": 10, "timeout_seconds": 30},
            },
            scope=scope,
            extra_files=[{
                "path": js_rel,
                "url": "https://app.example.test/app.js",
                "host": "app.example.test",
                "source": "js_analysis",
            }],
        ):
            events.append(ev)

        secret_assets = [
            e["data"] for e in events
            if e.get("type") == "asset" and e["data"].get("type") == "secret_finding"
        ]
        assert len(secret_assets) == 1
        assert secret_assets[0]["metadata"]["masked_preview"].startswith("AKIA")
        assert fake_secret not in json.dumps(events, default=str)

        # Persist exactly like jobs.py: masked metadata + run_assets.
        now = datetime.utcnow()
        for data in secret_assets:
            doc = dict(data)
            doc.update({
                "project_id": pid,
                "scan_id": job_str,
                "first_seen": now,
                "last_seen": now,
                "created_at": now,
                "updated_at": now,
            })
            await db.assets.insert_one(doc)
            await record_run_asset(
                db, pid, job_str, doc["type"], doc["value"],
                domain=doc.get("domain", ""), status=doc.get("status", "live"),
                metadata=doc.get("metadata"),
            )

        log_messages = [str(e.get("message") or "") for e in events if e.get("type") == "log"]
        await db.jobs.update_one({"_id": job_id}, {"$set": {"logs": log_messages}})

        run_doc = await record_run_history(
            db, job_str, pid,
            raw_outputs={"trufflehog": scan_output, "gitleaks": scan_output},
        )
        assert run_doc is not None
        assert run_doc["raw_output_paths"] == {}

        # WebSocket broadcast must scrub a synthetic leak as well.
        ws_manager.active_connections[job_str] = {fake_ws}
        for ev in events:
            await ws_manager.broadcast(job_str, ev)
        await ws_manager.broadcast(job_str, {"type": "log", "message": f"leak: {fake_secret}"})
        await ws_manager.broadcast(job_str, {"type": "run", "data": run_doc})
        assert fake_secret not in json.dumps(fake_ws.messages, default=str)

        # API responses and exports
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as ac:
            responses = [
                await ac.get(f"/api/v1/assets/project/{pid}"),
                await ac.get(f"/api/v1/projects/{pid}/runs"),
                await ac.get(f"/api/v1/reports/project/{pid}/export/urls"),
                await ac.get(f"/api/v1/reports/project/{pid}/export/burp"),
            ]
        assert all(r.status_code == 200 for r in responses)
        assert fake_secret not in "".join(r.text for r in responses)

        # Direct export helper
        exported = collect_export_urls(list(await db.assets.find({"project_id": pid}).to_list(100)), scope)
        assert fake_secret not in json.dumps(exported)

        # MongoDB: every document in every collection
        for collection_name in await db.list_collection_names():
            async for doc in db[collection_name].find({}):
                assert fake_secret not in json.dumps(doc, default=str), collection_name

        # storage/runs: no raw secret-scanner output
        run_dir = os.path.join(RUNS_BASE_DIR, pid, job_str)
        if os.path.isdir(run_dir):
            for fname in os.listdir(run_dir):
                fpath = os.path.join(run_dir, fname)
                if not os.path.isfile(fpath):
                    continue
                try:
                    with gzip.open(fpath, "rt", encoding="utf-8", errors="replace") as f:
                        content = f.read()
                except Exception:
                    with open(fpath, "r", encoding="utf-8", errors="replace") as f:
                        content = f.read()
                assert fake_secret not in content

        # The planted secret only exists in the raw JS storage body.
        assert fake_secret in open(js_full, "r", encoding="utf-8", errors="replace").read()
    finally:
        ws_manager.active_connections.pop(str(job_id), None)
        if js_rel:
            shutil.rmtree(os.path.join(JS_STORAGE_ROOT, "js", str(project_id)), ignore_errors=True)
        shutil.rmtree(os.path.join(RUNS_BASE_DIR, str(project_id)), ignore_errors=True)
        await teardown_real_test_db(client, db, old_db, old_is_mock)
