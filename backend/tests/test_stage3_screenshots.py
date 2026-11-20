"""Stage 3 screenshots — builder, storage, serving, diff and targeted flow."""

import os
import platform
import shutil
import uuid
from datetime import datetime, timedelta

import httpx
import pytest
from bson import ObjectId
from motor.motor_asyncio import AsyncIOMotorClient

import app.database as database_module
import app.providers.gowitness_provider as gowitness_module
from app.main import app
from app.providers.gowitness_provider import GowitnessProvider
from app.providers.url_merge import select_screenshot_targets
from app.services.diff_engine import compute_and_save_diff
from app.services.run_history import RUNS_BASE_DIR, record_run_asset, record_run_history
from app.services.screenshot_storage import SCREENSHOT_ROOT, STORAGE_ROOT, get_run_dir

PNG_BYTES = bytes.fromhex(
    "89504e470d0a1a0a0000000d49484452000000010000000108060000001f15c489"
    "0000000d49444154789c6360000000020001e221bc330000000049454e44ae426082"
)


async def setup_real_test_db():
    mongo_uri = os.getenv("MONGO_URI", "mongodb://localhost:27017")
    client = AsyncIOMotorClient(mongo_uri, serverSelectionTimeoutMS=2000)
    try:
        await client.admin.command("ping")
    except Exception as exc:
        pytest.skip(f"Real MongoDB is not running at {mongo_uri}: {exc}")
    test_db_name = f"reconforge_stage3_shots_{uuid.uuid4().hex[:8]}"
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
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://testserver")


def test_gowitness_builder_matches_installed_cli():
    provider = GowitnessProvider()
    tool_path = provider.detect_tool("gowitness")
    if not tool_path:
        pytest.skip("gowitness is not installed/resolvable")

    is_windows = platform.system().lower() == "windows"
    cli = provider.verify_gowitness_cli(tool_path, is_windows=is_windows)
    assert cli["version"] in ("v2", "v3")
    assert cli["version_output"] or cli["help_output"]
    assert tool_path.startswith("/") or (len(tool_path) > 2 and tool_path[1] == ":")

    cmd = provider.build_gowitness_cmd(
        tool_path=tool_path,
        url="https://app.example.test",
        screenshot_path="/tmp/shots",
        version=cli["version"],
        is_windows=is_windows,
        timeout=15,
    )
    assert tool_path in cmd
    if cli["version"] == "v3":
        assert "scan" in cmd and "single" in cmd
        assert "-T" in cmd and "15" in cmd
        help_text = cli["help_output"]
        for flag in ("--screenshot-path", "--screenshot-format", "--write-none"):
            assert flag in help_text, f"installed v3 help lacks {flag}"
    else:
        assert "single" in cmd


class _FakeProc:
    def __init__(self, cmd, rc=0, stderr="", write_png=True):
        self.cmd = cmd
        self.returncode = rc
        self.stderr = stderr
        self.write_png = write_png
        self.pid = 4242

    def communicate(self, timeout=None):
        if self.write_png and "--screenshot-path" in self.cmd:
            target_dir = self.cmd[self.cmd.index("--screenshot-path") + 1]
            os.makedirs(target_dir, exist_ok=True)
            with open(os.path.join(target_dir, "shot.png"), "wb") as f:
                f.write(PNG_BYTES)
        return "", self.stderr

    def poll(self):
        return self.returncode

    def wait(self, timeout=None):
        return self.returncode

    def kill(self):
        pass

    def terminate(self):
        pass


@pytest.mark.asyncio
async def test_gowitness_asset_storage_and_real_mongo(monkeypatch):
    client, db, old_db, old_is_mock = await setup_real_test_db()
    project_id = ObjectId()
    job_id = ObjectId()
    pid, jid = str(project_id), str(job_id)
    try:
        await db.projects.insert_one({"_id": project_id, "name": "Shots"})
        await db.jobs.insert_one({
            "_id": job_id,
            "project_id": pid,
            "status": "running",
            "started_at": datetime.utcnow(),
            "logs": [],
        })

        monkeypatch.setattr(gowitness_module.platform, "system", lambda: "Linux")
        monkeypatch.setattr(GowitnessProvider, "detect_tool", classmethod(lambda cls, name: "/usr/bin/gowitness"))
        monkeypatch.setattr(
            GowitnessProvider, "verify_gowitness_cli",
            classmethod(lambda cls, path, is_windows=False: {"version": "v3", "version_output": "v3", "help_output": ""}),
        )
        monkeypatch.setattr(GowitnessProvider, "detect_chromium", classmethod(lambda cls, is_windows: "/usr/bin/chromium"))
        monkeypatch.setattr(gowitness_module.subprocess, "Popen", lambda cmd, **kwargs: _FakeProc(cmd))

        provider = GowitnessProvider()
        events = []
        async for ev in provider.discover(
            ["https://app.example.test/"],
            project_id=pid,
            job_id=jid,
            rate_limit=100,
            per_url_timeout=10,
            page_hashes={"app.example.test": "page-hash-123"},
        ):
            events.append(ev)

        assets = [e["data"] for e in events if e.get("type") == "asset"]
        assert len(assets) == 1
        asset = assets[0]
        assert asset["type"] == "screenshot"
        assert asset["domain"] == "app.example.test"
        assert asset["value"] == "https://app.example.test/"
        meta = asset["metadata"]
        assert meta["screenshot_path"].startswith(f"screenshots/{pid}/{jid}/")
        assert meta["size"] == len(PNG_BYTES)
        assert meta["page_hash"] == "page-hash-123"
        assert meta["first_seen"] and meta["last_seen"]
        full_path = os.path.join(STORAGE_ROOT, meta["screenshot_path"])
        assert os.path.isfile(full_path)
        assert open(full_path, "rb").read() == PNG_BYTES

        doc = dict(asset)
        doc.update({
            "project_id": pid,
            "scan_id": jid,
            "first_seen": datetime.utcnow(),
            "last_seen": datetime.utcnow(),
        })
        await db.assets.insert_one(doc)
        await record_run_asset(
            db, pid, jid, "screenshot", asset["value"],
            domain=asset["domain"], status="live", metadata=meta,
        )
        stored = await db.run_assets.find_one({"project_id": pid, "job_id": jid, "type": "screenshot"})
        assert stored["metadata"]["screenshot_path"] == meta["screenshot_path"]
        assert stored["metadata"]["size"] == len(PNG_BYTES)

        run_doc = await record_run_history(db, jid, pid)
        assert run_doc["counts"]["screenshots"] == 1
    finally:
        shutil.rmtree(os.path.join(SCREENSHOT_ROOT, pid), ignore_errors=True)
        shutil.rmtree(os.path.join(RUNS_BASE_DIR, pid), ignore_errors=True)
        await teardown_real_test_db(client, db, old_db, old_is_mock)


@pytest.mark.asyncio
async def test_gowitness_nonzero_exit_and_chromium_error(monkeypatch):
    provider = GowitnessProvider()
    monkeypatch.setattr(provider, "detect_tool", lambda name: "/usr/bin/gowitness")
    monkeypatch.setattr(provider, "verify_gowitness_cli", lambda path, is_windows=False: {"version": "v3"})
    monkeypatch.setattr(provider, "detect_chromium", lambda is_windows: "/usr/bin/chromium")

    long_err = "X" * 700
    monkeypatch.setattr(
        gowitness_module.subprocess, "Popen",
        lambda cmd, **kwargs: _FakeProc(cmd, rc=2, stderr=long_err, write_png=False),
    )
    events = []
    async for ev in provider.discover(
        ["https://app.example.test"], project_id="p", job_id="j", rate_limit=100, per_url_timeout=5
    ):
        events.append(ev)
    errors = [e for e in events if e.get("type") == "stage_error"]
    assert errors
    assert errors[0]["returncode"] == 2
    assert long_err[:500] in errors[0]["reason"]
    assert long_err not in errors[0]["reason"]

    monkeypatch.setattr(
        gowitness_module.subprocess, "Popen",
        lambda cmd, **kwargs: _FakeProc(
            cmd, rc=1, stderr="could not find chrome/chromium executable", write_png=False
        ),
    )
    events = []
    async for ev in provider.discover(
        ["https://app.example.test"], project_id="p", job_id="j", rate_limit=100, per_url_timeout=5
    ):
        events.append(ev)
    errors = [e for e in events if e.get("type") == "stage_error"]
    assert errors
    assert "sudo apt install -y chromium" in errors[0]["reason"]


@pytest.mark.asyncio
async def test_screenshot_endpoint_path_checks_and_listing_real_mongo(monkeypatch):
    client, db, old_db, old_is_mock = await setup_real_test_db()
    project_id = ObjectId()
    job_id = ObjectId()
    pid, jid = str(project_id), str(job_id)
    try:
        await db.projects.insert_one({"_id": project_id, "name": "Shots API"})
        await db.jobs.insert_one({
            "_id": job_id, "project_id": pid, "status": "completed",
            "started_at": datetime.utcnow(), "logs": [],
        })
        run_dir = get_run_dir(pid, jid)
        with open(os.path.join(run_dir, "safe.png"), "wb") as f:
            f.write(PNG_BYTES)
        # File outside the run directory, not reachable through the endpoint.
        outside = os.path.join(SCREENSHOT_ROOT, pid, "outside.png")
        with open(outside, "wb") as f:
            f.write(PNG_BYTES + b"OUTSIDE")
        with open(os.path.join(run_dir, "not-image.png.txt"), "wb") as f:
            f.write(b"nope")

        meta = {
            "url": "https://app.example.test/",
            "host": "app.example.test",
            "filename": "safe.png",
            "screenshot_path": f"screenshots/{pid}/{jid}/safe.png",
            "size": len(PNG_BYTES),
            "page_hash": "h1",
            "first_seen": datetime.utcnow(),
            "last_seen": datetime.utcnow(),
            "run_id": jid,
        }
        await record_run_asset(
            db, pid, jid, "screenshot", "https://app.example.test/",
            domain="app.example.test", status="live", metadata=meta,
        )

        async with api_client() as ac:
            valid = await ac.get(f"/api/v1/assets/project/{pid}/screenshots/{jid}/safe.png")
            assert valid.status_code == 200
            assert valid.headers["content-type"].startswith("image/png")
            assert valid.content == PNG_BYTES

            listing = await ac.get(f"/api/v1/assets/project/{pid}/screenshots")
            assert listing.status_code == 200
            body = listing.json()
            assert body["selected_job_id"] == jid
            assert len(body["items"]) == 1
            assert body["items"][0]["filename"] == "safe.png"
            assert body["items"][0]["image_url"].endswith(f"/screenshots/{jid}/safe.png")
            assert body["runs"][0]["job_id"] == jid

            for bad in (
                f"/api/v1/assets/project/{pid}/screenshots/{jid}/../outside.png",
                f"/api/v1/assets/project/{pid}/screenshots/{jid}/%2e%2e%2foutside.png",
                f"/api/v1/assets/project/{pid}/screenshots/{jid}/not-image.png.txt",
                f"/api/v1/assets/project/{pid}/screenshots/{jid}/missing.png",
                f"/api/v1/assets/project/{pid}/screenshots/{ObjectId()}/safe.png",
            ):
                res = await ac.get(bad)
                assert res.status_code == 404, (bad, res.status_code)
                assert res.content != PNG_BYTES + b"OUTSIDE"
    finally:
        shutil.rmtree(os.path.join(SCREENSHOT_ROOT, pid), ignore_errors=True)
        await teardown_real_test_db(client, db, old_db, old_is_mock)


@pytest.mark.asyncio
async def test_screenshot_changed_diff_real_mongo():
    client, db, old_db, old_is_mock = await setup_real_test_db()
    try:
        project_id = str(ObjectId())
        prev_job = str(ObjectId())
        current_job = str(ObjectId())
        now = datetime.utcnow()
        await db.projects.insert_one({"_id": ObjectId(project_id), "name": "Shot Diff"})
        await db.jobs.insert_many([
            {
                "_id": ObjectId(prev_job), "project_id": project_id, "status": "completed",
                "scan_mode": "full", "job_kind": "full",
                "started_at": now - timedelta(hours=2), "finished_at": now - timedelta(hours=1, minutes=50),
                "executed_phases": ["subdomain_discovery", "screenshots"], "liveness_version": 2,
            },
            {
                "_id": ObjectId(current_job), "project_id": project_id, "status": "completed",
                "scan_mode": "full", "job_kind": "full",
                "started_at": now - timedelta(minutes=5), "finished_at": now,
                "executed_phases": ["subdomain_discovery", "screenshots"], "liveness_version": 2,
            },
        ])
        for job, page_hash in ((prev_job, "old-hash"), (current_job, "new-hash")):
            await record_run_asset(
                db, project_id, job, "screenshot", "https://app.example.test/",
                domain="app.example.test", status="live",
                metadata={
                    "url": "https://app.example.test/",
                    "host": "app.example.test",
                    "page_hash": page_hash,
                    "screenshot_path": f"screenshots/{project_id}/{job}/safe.png",
                    "filename": "safe.png",
                    "size": len(PNG_BYTES),
                    "run_id": job,
                },
            )

        diff = await compute_and_save_diff(project_id, current_job, db)
        assert diff["summary"]["changed_screenshots_count"] == 1
        changed = diff["diff"]["changed_screenshots"][0]
        assert changed["url"] == "https://app.example.test/"
        assert changed["old_hash"] == "old-hash"
        assert changed["new_hash"] == "new-hash"
    finally:
        await teardown_real_test_db(client, db, old_db, old_is_mock)


@pytest.mark.asyncio
async def test_targeted_run_supports_screenshots_real_mongo(monkeypatch):
    from app.providers.gowitness_provider import GowitnessProvider as GW

    async def fake_discover(self, targets, **kwargs):
        assert kwargs.get("project_id")
        assert kwargs.get("job_id")
        yield {
            "type": "asset",
            "data": {
                "domain": "app.example.test",
                "type": "screenshot",
                "value": "https://app.example.test/",
                "status": "live",
                "metadata": {
                    "url": "https://app.example.test/",
                    "host": "app.example.test",
                    "filename": "safe.png",
                    "screenshot_path": "screenshots/p/j/safe.png",
                    "size": len(PNG_BYTES),
                    "page_hash": "h1",
                },
                "discovered_by": "gowitness",
                "sources": ["gowitness"],
            },
        }
        yield {"type": "scan_summary", "provider": "gowitness", "status": "completed", "count": 1}

    monkeypatch.setattr(GW, "discover", fake_discover)

    client, db, old_db, old_is_mock = await setup_real_test_db()
    project_id = ObjectId()
    try:
        pid = str(project_id)
        await db.projects.insert_one({
            "_id": project_id,
            "name": "Targeted Shots",
            "scope": {"in_scope": ["*.example.test"], "out_of_scope": []},
        })
        async with api_client() as ac:
            res = await ac.post(f"/api/v1/jobs/project/{pid}/targeted", json={
                "tool": "screenshots",
                "hosts": ["https://app.example.test"],
                "time_cap_seconds": 30,
            })
            assert res.status_code == 200, res.text
            job = res.json()
            job_doc = (await ac.get(f"/api/v1/jobs/{job['id']}")).json()
            assert job_doc["status"] == "completed"
            assert "screenshots" in (job_doc.get("executed_phases") or [])

        asset = await db.assets.find_one({"project_id": pid, "type": "screenshot"})
        assert asset is not None
        run_doc = await db.scan_runs.find_one({"job_id": job["id"]})
        assert run_doc["run_kind"] == "targeted"
        assert run_doc["counts"]["screenshots"] == 1
    finally:
        shutil.rmtree(os.path.join(RUNS_BASE_DIR, pid), ignore_errors=True)
        await teardown_real_test_db(client, db, old_db, old_is_mock)


@pytest.mark.asyncio
async def test_targeted_screenshots_prioritizes_and_skips_static_assets(monkeypatch):
    from app.providers.gowitness_provider import GowitnessProvider as GW

    received = []

    async def fake_discover(self, targets, **kwargs):
        received.extend(targets)
        yield {"type": "scan_summary", "provider": "gowitness", "status": "completed", "count": 0}

    monkeypatch.setattr(GW, "discover", fake_discover)

    client, db, old_db, old_is_mock = await setup_real_test_db()
    project_id = ObjectId()
    try:
        pid = str(project_id)
        await db.projects.insert_one({
            "_id": project_id,
            "name": "Targeted Shot Filters",
            "scope": {"in_scope": ["*.example.test"], "out_of_scope": []},
        })
        async with api_client() as ac:
            res = await ac.post(f"/api/v1/jobs/project/{pid}/targeted", json={
                "tool": "screenshots",
                "hosts": [
                    "https://app.example.test/app.js",
                    "https://app.example.test/robots.txt",
                    "https://app.example.test/",
                    "https://app.example.test/search?q=1",
                ],
                "time_cap_seconds": 30,
            })
            assert res.status_code == 200, res.text
            job = res.json()
            job_doc = (await ac.get(f"/api/v1/jobs/{job['id']}")).json()
            assert job_doc["status"] == "completed"

        assert received == [
            "https://app.example.test/search?q=1",
            "https://app.example.test",
        ]
    finally:
        shutil.rmtree(os.path.join(RUNS_BASE_DIR, pid), ignore_errors=True)
        await teardown_real_test_db(client, db, old_db, old_is_mock)


@pytest.mark.asyncio
async def test_targeted_screenshots_include_related_cloud_services(monkeypatch):
    from app.providers.gowitness_provider import GowitnessProvider as GW

    received = []

    async def fake_discover(self, targets, **kwargs):
        received.extend(targets)
        yield {"type": "scan_summary", "provider": "gowitness", "status": "completed", "count": 0}

    monkeypatch.setattr(GW, "discover", fake_discover)

    client, db, old_db, old_is_mock = await setup_real_test_db()
    project_id = ObjectId()
    try:
        pid = str(project_id)
        await db.projects.insert_one({
            "_id": project_id,
            "name": "Cloud Screenshot Targets",
            "scope": {"in_scope": ["*"], "out_of_scope": []},
        })
        await db.assets.insert_one({
            "project_id": pid,
            "type": "cloud_service",
            "domain": "bucket.s3.amazonaws.com",
            "value": "https://bucket.s3.amazonaws.com/public/index",
            "status": "live",
            "metadata": {
                "url": "https://bucket.s3.amazonaws.com/public/index",
                "host": "bucket.s3.amazonaws.com",
                "provider": "aws",
                "service": "s3",
                "parent_host": "app.example.test",
                "parent_hosts": ["app.example.test"],
            },
        })
        async with api_client() as ac:
            res = await ac.post(f"/api/v1/jobs/project/{pid}/targeted", json={
                "tool": "screenshots",
                "hosts": ["https://app.example.test/"],
                "time_cap_seconds": 30,
            })
            assert res.status_code == 200, res.text
            job = res.json()
            job_doc = (await ac.get(f"/api/v1/jobs/{job['id']}")).json()
            assert job_doc["status"] == "completed"

        assert "https://app.example.test" in received
        assert "https://bucket.s3.amazonaws.com/public/index" in received
    finally:
        shutil.rmtree(os.path.join(RUNS_BASE_DIR, pid), ignore_errors=True)
        await teardown_real_test_db(client, db, old_db, old_is_mock)


def test_parse_have_screenshot_result_lines():
    provider = GowitnessProvider()
    assert provider.parse_have_screenshot(
        'INFO result target=https://app.example.test status-code=200 have-screenshot=true',
        "https://app.example.test",
    ) is True
    assert provider.parse_have_screenshot(
        'ERRO result target=https://bad.example.test have-screenshot=false err="timeout"',
        "https://bad.example.test",
    ) is False
    assert provider.parse_have_screenshot("no result markers", "https://x.test") is None


@pytest.mark.asyncio
async def test_gowitness_preflight_skips_without_chromium(monkeypatch):
    provider = GowitnessProvider()
    monkeypatch.setattr(provider, "detect_tool", lambda name: "/usr/bin/gowitness")
    monkeypatch.setattr(provider, "verify_gowitness_cli", lambda path, is_windows=False: {"version": "v3"})
    monkeypatch.setattr(provider, "detect_chromium", lambda is_windows: None)

    events = []
    async for ev in provider.discover(
        ["https://app.example.test"], project_id="p", job_id="j", rate_limit=100
    ):
        events.append(ev)

    errors = [e for e in events if e.get("type") == "stage_error"]
    assert errors
    assert "sudo apt install -y chromium" in errors[0]["reason"]
    summ = [e for e in events if e.get("type") == "scan_summary"][0]
    assert summ["status"] == "SKIPPED"


class _PerUrlProc:
    def __init__(self, cmd):
        self.cmd = cmd
        self.url = cmd[cmd.index("-u") + 1]
        self.returncode = 0
        self.pid = 5151

    def communicate(self, timeout=None):
        target_dir = self.cmd[self.cmd.index("--screenshot-path") + 1]
        success = "good" in self.url
        if success:
            os.makedirs(target_dir, exist_ok=True)
            with open(os.path.join(target_dir, "shot.png"), "wb") as f:
                f.write(PNG_BYTES)
            return "", f"INFO result target={self.url} have-screenshot=true"
        return "", f"ERRO result target={self.url} have-screenshot=false err=sandbox"

    def poll(self):
        return self.returncode

    def wait(self, timeout=None):
        return self.returncode

    def kill(self):
        pass

    def terminate(self):
        pass


@pytest.mark.asyncio
async def test_gowitness_partial_failure_warning_and_counts(monkeypatch):
    monkeypatch.setattr(gowitness_module.platform, "system", lambda: "Linux")
    monkeypatch.setattr(GowitnessProvider, "detect_tool", classmethod(lambda cls, name: "/usr/bin/gowitness"))
    monkeypatch.setattr(
        GowitnessProvider, "verify_gowitness_cli",
        classmethod(lambda cls, path, is_windows=False: {
            "version": "v3", "version_output": "v3",
            "help_output": "--log-scan-errors --no-log-color --timeout",
        }),
    )
    monkeypatch.setattr(GowitnessProvider, "detect_chromium", classmethod(lambda cls, is_windows: "/usr/bin/chromium"))
    monkeypatch.setattr(gowitness_module.subprocess, "Popen", lambda cmd, **kwargs: _PerUrlProc(cmd))

    provider = GowitnessProvider()
    events = []
    async for ev in provider.discover(
        ["https://good.example.test", "https://bad.example.test"],
        project_id="p", job_id="j", rate_limit=100, per_url_timeout=7, concurrency=2,
    ):
        events.append(ev)

    warnings = [e for e in events if e.get("type") == "warning_event"]
    assert len(warnings) == 1
    assert warnings[0]["warning"] == "gowitness_partial_failures"
    assert warnings[0]["failed_urls"] == ["https://bad.example.test"]

    summ = [e for e in events if e.get("type") == "scan_summary"][0]
    assert summ["successful_screenshots"] == 1
    assert summ["failed_screenshots"] == 1
    assert summ["screenshots"] == 1

    command_logs = [str(e.get("message") or "") for e in events if e.get("type") == "log"]
    assert any("-T 7" in m for m in command_logs)
    assert any("--log-scan-errors" in m for m in command_logs)


@pytest.mark.asyncio
async def test_gowitness_true_hint_without_png_is_failure(monkeypatch):
    provider = GowitnessProvider()
    monkeypatch.setattr(provider, "detect_tool", lambda name: "/usr/bin/gowitness")
    monkeypatch.setattr(provider, "verify_gowitness_cli", lambda path, is_windows=False: {
        "version": "v3", "help_output": "--log-scan-errors --no-log-color",
    })
    monkeypatch.setattr(provider, "detect_chromium", lambda is_windows: "/usr/bin/chromium")

    class NoFileProc(_PerUrlProc):
        def communicate(self, timeout=None):
            return "", f"INFO result target={self.url} have-screenshot=true"

    monkeypatch.setattr(gowitness_module.subprocess, "Popen", lambda cmd, **kwargs: NoFileProc(cmd))
    events = []
    async for ev in provider.discover(
        ["https://app.example.test"], project_id="p", job_id="j", rate_limit=100
    ):
        events.append(ev)

    errors = [e for e in events if e.get("type") == "stage_error"]
    assert errors
    assert "no png file produced" in errors[0]["reason"].lower()
    summ = [e for e in events if e.get("type") == "scan_summary"][0]
    assert summ["failed_screenshots"] == 1
    assert summ["successful_screenshots"] == 0


@pytest.mark.asyncio
async def test_gowitness_prefers_gorod_driver_when_supported(monkeypatch):
    monkeypatch.setattr(gowitness_module.platform, "system", lambda: "Linux")
    monkeypatch.setattr(GowitnessProvider, "detect_tool", classmethod(lambda cls, name: "/usr/bin/gowitness"))
    monkeypatch.setattr(
        GowitnessProvider, "verify_gowitness_cli",
        classmethod(lambda cls, path, is_windows=False: {
            "version": "v3",
            "version_output": "v3",
            "help_output": (
                "--driver string The scan driver to use. Can be one of [gorod, chromedp] "
                "-T, --timeout int --log-scan-errors --no-log-color"
            ),
        }),
    )
    monkeypatch.setattr(GowitnessProvider, "detect_chromium", classmethod(lambda cls, is_windows: "/usr/bin/chromium"))
    captured = []

    def fake_popen(cmd, **kwargs):
        captured.append(list(cmd))
        return _FakeProc(cmd)

    monkeypatch.setattr(gowitness_module.subprocess, "Popen", fake_popen)

    pid, jid = f"p_{uuid.uuid4().hex[:6]}", f"j_{uuid.uuid4().hex[:6]}"
    provider = GowitnessProvider()
    events = []
    try:
        async for ev in provider.discover(
            ["https://app.example.test"],
            project_id=pid, job_id=jid, rate_limit=100, per_url_timeout=30,
        ):
            events.append(ev)
    finally:
        shutil.rmtree(os.path.join(SCREENSHOT_ROOT, pid), ignore_errors=True)

    assert captured
    assert "--driver" in captured[0]
    assert captured[0][captured[0].index("--driver") + 1] == "gorod"
    assert any("GoWitness driver: gorod" in str(e.get("message") or "") for e in events)
    assert any(e.get("type") == "asset" for e in events)


def test_select_screenshot_targets_keeps_roots_first_and_dedupes():
    live = ["https://a.test", "https://a.test/", "https://b.test"]
    candidates = [
        "https://a.test/",
        "https://a.test/search?q=1",
        "https://a.test/about",
    ]

    targets = select_screenshot_targets(live, candidates, max_urls=10, max_per_host_extras=5)

    assert targets[:2] == ["https://a.test", "https://b.test"]
    assert "https://a.test/search?q=1" in targets
    assert targets.count("https://a.test") == 1


def test_select_screenshot_targets_ranks_priority_and_skips_assets():
    live = ["https://a.test"]
    candidates = [
        "https://a.test/page.html",
        "https://a.test/zzz",
        "https://a.test/search?id=1",
        "https://a.test/app.js",
        "https://a.test/logo.png",
    ]

    targets = select_screenshot_targets(live, candidates, max_urls=10, max_per_host_extras=3)

    assert targets == [
        "https://a.test",
        "https://a.test/search?id=1",
        "https://a.test/zzz",
        "https://a.test/page.html",
    ]


def test_select_screenshot_targets_caps_extras_per_host_and_globally():
    live = ["https://a.test", "https://b.test"]
    a_candidates = [f"https://a.test/page-{i}" for i in range(10)]
    b_candidates = [f"https://b.test/page-{i}" for i in range(10)]

    per_host = select_screenshot_targets(
        live, a_candidates + b_candidates, max_urls=50, max_per_host_extras=2
    )
    assert per_host.count("https://a.test") + sum(
        1 for u in per_host if u.startswith("https://a.test/")
    ) == 3
    assert per_host.count("https://b.test") + sum(
        1 for u in per_host if u.startswith("https://b.test/")
    ) == 3

    global_cap = select_screenshot_targets(
        live, a_candidates + b_candidates, max_urls=3, max_per_host_extras=5
    )
    assert global_cap == ["https://a.test", "https://b.test", "https://a.test/page-0"]


def test_select_screenshot_targets_extras_do_not_displace_roots():
    live = ["https://a.test", "https://a.test/admin"]
    candidates = [f"https://a.test/page-{i}" for i in range(5)]

    targets = select_screenshot_targets(
        live, candidates, max_urls=10, max_per_host_extras=0
    )

    assert targets == live


@pytest.mark.asyncio
async def test_gowitness_host_hash_only_applies_to_root_urls(monkeypatch):
    monkeypatch.setattr(gowitness_module.platform, "system", lambda: "Linux")
    monkeypatch.setattr(GowitnessProvider, "detect_tool", classmethod(lambda cls, name: "/usr/bin/gowitness"))
    monkeypatch.setattr(
        GowitnessProvider, "verify_gowitness_cli",
        classmethod(lambda cls, path, is_windows=False: {"version": "v3", "version_output": "v3", "help_output": ""}),
    )
    monkeypatch.setattr(GowitnessProvider, "detect_chromium", classmethod(lambda cls, is_windows: "/usr/bin/chromium"))
    monkeypatch.setattr(gowitness_module.subprocess, "Popen", lambda cmd, **kwargs: _FakeProc(cmd))

    pid = f"p_{uuid.uuid4().hex[:6]}"
    jid = f"j_{uuid.uuid4().hex[:6]}"
    provider = GowitnessProvider()
    events = []
    try:
        async for ev in provider.discover(
            ["https://app.example.test/admin"],
            project_id=pid,
            job_id=jid,
            rate_limit=100,
            per_url_timeout=10,
            page_hashes={"app.example.test": "host-page-hash"},
        ):
            events.append(ev)
    finally:
        shutil.rmtree(os.path.join(SCREENSHOT_ROOT, pid), ignore_errors=True)

    meta = [e["data"]["metadata"] for e in events if e.get("type") == "asset"][0]
    assert meta["page_hash"] != "host-page-hash"
    assert meta["page_hash"] == meta["screenshot_hash"]
