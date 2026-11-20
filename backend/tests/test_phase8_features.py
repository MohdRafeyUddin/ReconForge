"""Phase 8 — regression tests for additive JS/secrets/cloud/OAST/export features."""

import json
import os

import pytest

from app.core.phase8_config import get_phase8_config, load_phase8_defaults
from app.core.redaction import (
    mask_secret_value,
    redact_cmd_args,
    scrub_secret_metadata,
)
from app.core.tools import RECON_TOOLS
from app.providers.cloud_enum_provider import CloudEnumProvider
from app.providers.js_analysis_provider import JsAnalysisProvider
from app.providers.secrets_provider import SecretsProvider
from app.routers.reports import collect_export_urls
from app.services.diff_engine import compute_modified_js_files
from app.services.oast import OASTSession


PHASE8_TOOLS = [
    "jsluice", "xnlinkfinder", "sourcemapper", "trufflehog",
    "gitleaks", "cloud_enum", "s3scanner", "interactsh", "wpscan",
]


def test_phase8_tool_registry_entries():
    for tool in PHASE8_TOOLS:
        assert tool in RECON_TOOLS, f"{tool} missing from RECON_TOOLS"
        assert RECON_TOOLS[tool]["install_hint"]
        assert RECON_TOOLS[tool]["required"] is False


def test_phase8_defaults_and_project_merge():
    defaults = load_phase8_defaults()
    assert defaults["js_analysis"]["enabled"] is True
    assert defaults["oast"]["enabled"] is False
    cfg = get_phase8_config({
        "oast": {"enabled": True, "server": "oast.example.test"},
        "cloud_enum": {"enabled": True},
    })
    assert cfg["oast"]["enabled"] is True
    assert cfg["oast"]["server"] == "oast.example.test"
    assert cfg["oast"]["token"] == ""
    assert cfg["cloud_enum"]["enabled"] is True
    assert cfg["secrets_scan"]["enabled"] is True


def test_secret_masking_and_scrubbing():
    raw = "AKIAABCDEFGHIJKLMNOP"
    masked = mask_secret_value(raw)
    assert masked.startswith("AKIA")
    assert raw not in masked

    scrubbed = scrub_secret_metadata({
        "detector": "AWS",
        "raw": raw,
        "prefix": raw,
        "location": "app.js:10",
        "nested": {"secret": raw, "prefix": raw},
    })
    assert "raw" not in scrubbed
    assert raw not in json.dumps(scrubbed)
    assert scrubbed["prefix"].startswith("AKIA")
    assert scrubbed["nested"]["prefix"].startswith("AKIA")


def test_redact_interactsh_token_flag():
    redacted = redact_cmd_args([
        "interactsh-client", "-json", "-interactsh-token", "super-secret-token",
        "-server", "oast.example.test",
    ])
    assert "super-secret-token" not in " ".join(redacted)
    assert "[REDACTED]" in " ".join(redacted)


def test_js_sourcemap_and_jsluice_parsing():
    body = "var x=1;\n//# sourceMappingURL=static/app.js.map\n//# sourceMappingURL=/maps/vendor.map\n"
    maps = JsAnalysisProvider.extract_sourcemap_urls("https://host.test/js/app.js", body)
    assert maps == [
        "https://host.test/js/static/app.js.map",
        "https://host.test/maps/vendor.map",
    ]

    lines = [
        json.dumps({"url": "/api/v1/users", "filename": "js_0.js"}),
        json.dumps({"url": "https://cdn.host.test/lib.js", "filename": "js_0.js"}),
        "not json",
    ]
    parsed = JsAnalysisProvider.parse_jsluice_output(
        lines, {"js_0.js": "https://host.test/js/app.js"}, fallback_js_url="https://host.test/js/app.js"
    )
    assert ("https://host.test/api/v1/users", "https://host.test/js/app.js") in parsed
    assert ("https://cdn.host.test/lib.js", "https://host.test/js/app.js") in parsed


def test_xnlinkfinder_ansi_parsing():
    lines = ["\x1b[32mhttps://host.test/api?x=1\x1b[0m", "noise", "https://host.test/api?x=1"]
    urls = JsAnalysisProvider.parse_xnlinkfinder_output(lines, "https://host.test/app.js")
    assert urls == ["https://host.test/api?x=1"]


def test_select_scannable_files_fails_closed(monkeypatch, tmp_path):
    import app.providers.secrets_provider as sp
    monkeypatch.setattr(sp, "BASE_STORAGE_DIR", str(tmp_path))
    project_dir = tmp_path / "abc"
    project_dir.mkdir()
    body_file = project_dir / "response.txt"
    body_file.write_text("test", encoding="utf-8")

    assets = [
        {
            "domain": "app.example.test",
            "metadata": {"url": "https://app.example.test/", "response_body_path": "abc/response.txt", "source": "httpx"},
        },
        {
            "domain": "evil.test",
            "metadata": {"url": "https://evil.test/", "response_body_path": "abc/response.txt"},
        },
    ]
    scope = {"in_scope": ["*.example.test"], "out_of_scope": []}
    selected = SecretsProvider.select_scannable_files(assets, scope)
    assert len(selected) == 1
    assert selected[0]["host"] == "app.example.test"
    assert selected[0]["path"].endswith("response.txt")


def test_trufflehog_parsing_never_returns_raw_secret(tmp_path):
    body = tmp_path / "app.js"
    body.write_text("const k='x';", encoding="utf-8")
    identity = {"path": str(body), "url": "https://app.example.test/app.js", "host": "app.example.test"}
    raw = "AKIAABCDEFGHIJKLMNOP"
    line = json.dumps({
        "DetectorName": "AWS",
        "Verified": False,
        "Raw": raw,
        "SourceMetadata": {"Data": {"Filesystem": {"file": str(body), "line": 3}}},
    })
    findings = SecretsProvider.parse_trufflehog_output([line], {str(body): identity})
    assert len(findings) == 1
    finding = findings[0]
    assert finding["detector"] == "AWS"
    assert finding["line"] == 3
    assert raw not in json.dumps(finding)
    assert finding["prefix"].startswith("AKIA")


def test_gitleaks_parsing_masks_secret(tmp_path):
    body = tmp_path / "body.txt"
    body.write_text("x", encoding="utf-8")
    identity = {"path": str(body), "url": "https://app.example.test/", "host": "app.example.test"}
    raw = "ghp_abcdefghijklmnopqrstuvwxyz0123456789"
    report = [{
        "RuleID": "github-pat",
        "Secret": raw,
        "File": str(body),
        "StartLine": 7,
    }]
    findings = SecretsProvider.parse_gitleaks_report(report, {str(body): identity})
    assert len(findings) == 1
    assert findings[0]["detector"] == "github-pat"
    assert raw not in json.dumps(findings)
    assert findings[0]["prefix"].startswith("ghp_")


def test_cloud_keyword_derivation_scope_and_parsing():
    scope = {"in_scope": ["*.example.test"], "out_of_scope": ["dev.example.test"]}
    keywords = CloudEnumProvider.derive_keywords(["www.example.test", "other.test"], scope)
    assert "example.test" in keywords
    assert "other.test" not in keywords
    assert CloudEnumProvider.root_in_scope("example.test", scope) is True
    assert CloudEnumProvider.root_in_scope("dev.example.test", scope) is False

    output = [
        "[+] Found: https://example-test-assets.s3.amazonaws.com (public)",
        "[+] Found: https://unrelated.s3.amazonaws.com (public)",
    ]
    parsed = CloudEnumProvider.parse_cloud_enum_output(output, "example-test")
    assert len(parsed) == 1
    assert parsed[0]["bucket_name"] == "example-test-assets"
    assert parsed[0]["public"] is True


def test_oast_correlation_requires_candidate_and_scope():
    interaction = {
        "protocol": "http",
        "remote-address": "203.0.113.10",
        "raw-request": "GET / HTTP/1.1\r\nHost: app.example.test\r\n\r\n",
    }
    scope = {"in_scope": ["*.example.test"], "out_of_scope": []}
    event = OASTSession.interaction_to_finding(interaction, scope, {"app.example.test"})
    assert event is not None
    assert event["type"] == "finding_event"
    assert event["data"]["host"] == "app.example.test"
    assert event["data"]["source"] == "interactsh"

    assert OASTSession.interaction_to_finding(interaction, scope, {"other.example.test"}) is None
    out_scope = {"in_scope": ["other.test"], "out_of_scope": []}
    assert OASTSession.interaction_to_finding(interaction, out_scope, {"app.example.test"}) is None


def test_modified_js_diff_helper():
    current = {
        "https://host.test/app.js": {"host": "host.test", "hash": "newhash"},
        "https://host.test/new.js": {"host": "host.test", "hash": "abc"},
    }
    previous = {
        "https://host.test/app.js": {"host": "host.test", "hash": "oldhash"},
        "https://host.test/gone.js": {"host": "host.test", "hash": "abc"},
    }
    modified = compute_modified_js_files(current, previous)
    assert len(modified) == 1
    assert modified[0]["url"] == "https://host.test/app.js"
    assert modified[0]["old_hash"] == "oldhash"
    assert modified[0]["new_hash"] == "newhash"


def test_export_urls_scope_and_redaction():
    assets = [
        {"type": "uro_url", "value": "https://app.example.test/api?token=secretvalue&x=1", "metadata": {}},
        {"type": "historical_url", "value": "https://evil.test/a", "metadata": {}},
        {"type": "secret", "value": "AWS:https://app.example.test/:1", "metadata": {}},
        {"type": "cloud_bucket", "value": "https://example-test.s3.amazonaws.com", "metadata": {"url": "https://example-test.s3.amazonaws.com"}},
    ]
    scope = {"in_scope": ["*.example.test"], "out_of_scope": []}
    urls = collect_export_urls(assets, scope)
    assert any("app.example.test/api" in u for u in urls)
    assert all("evil.test" not in u for u in urls)
    assert all("secret" not in u.split("token=")[1] if "token=" in u else True for u in urls)
    assert all(not u.startswith("AWS:") for u in urls)
