import pytest
from app.core.scope import is_in_scope, is_ip_in_scope, filter_scope
from app.core.redaction import redact_cmd_args, redact_text
from app.core.tools import RECON_TOOLS, get_all_tools_status, get_tool_status, is_tool_available


def test_scope_engine_wildcards():
    scope = {
        "in_scope": ["*.example.com", "example.com"],
        "out_of_scope": ["out.example.com", "*.internal.example.com"]
    }
    
    assert is_in_scope("example.com", scope) is True
    assert is_in_scope("sub.example.com", scope) is True
    assert is_in_scope("deep.sub.example.com", scope) is True
    assert is_in_scope("https://sub.example.com:8443/api/v1", scope) is True
    
    # Out of scope must win
    assert is_in_scope("out.example.com", scope) is False
    assert is_in_scope("secret.internal.example.com", scope) is False
    assert is_in_scope("https://out.example.com/login", scope) is False
    
    # Outside in-scope
    assert is_in_scope("notexample.com", scope) is False
    assert is_in_scope("google.com", scope) is False


def test_scope_engine_cidrs_and_ips():
    scope = {
        "in_scope": ["192.168.1.0/24", "10.10.10.5"],
        "out_of_scope": ["192.168.1.50"]
    }
    
    assert is_in_scope("192.168.1.10", scope) is True
    assert is_in_scope("10.10.10.5", scope) is True
    assert is_in_scope("http://192.168.1.20:8080/test", scope) is True
    
    # Out of scope must win
    assert is_in_scope("192.168.1.50", scope) is False
    assert is_in_scope("10.10.10.6", scope) is False
    assert is_in_scope("8.8.8.8", scope) is False


def test_resolved_ip_scope_check():
    # Only domain in-scope, but private CIDRs out-of-scope
    scope = {
        "in_scope": ["*.target.com"],
        "out_of_scope": ["10.0.0.0/8", "169.254.169.254/32"]
    }
    
    # Public IP for domain -> in scope
    assert is_ip_in_scope("93.184.216.34", scope) is True
    # Private IP or metadata IP -> dropped
    assert is_ip_in_scope("10.0.0.1", scope) is False
    assert is_ip_in_scope("169.254.169.254", scope) is False


def test_scope_unconfigured():
    # If scope is empty/None, all targets are allowed (with UI warning)
    assert is_in_scope("anything.com", None) is True
    assert is_in_scope("anything.com", {}) is True
    assert is_in_scope("anything.com", {"in_scope": [], "out_of_scope": []}) is True


def test_filter_scope_list():
    scope = {
        "in_scope": ["*.example.com"],
        "out_of_scope": ["blocked.example.com"]
    }
    targets = [
        "a.example.com",
        "blocked.example.com",
        "b.example.com",
        "evil.com",
        "a.example.com"  # Duplicate
    ]
    kept, dropped = filter_scope(targets, scope)
    assert kept == ["a.example.com", "b.example.com"]
    assert "blocked.example.com" in dropped
    assert "evil.com" in dropped


def test_command_redaction():
    cmd = [
        "httpx",
        "-u", "https://example.com",
        "-H", "Authorization: Bearer super_secret_token_12345",
        "-H", "Cookie: session_id=abcdef123456; theme=dark",
        "-H", "X-Bug-Bounty: hunter123",
        "-token", "api_key_secret_999"
    ]
    redacted = redact_cmd_args(cmd)
    
    # Check that secrets are masked
    cmd_str = " ".join(redacted)
    assert "super_secret_token" not in cmd_str
    assert "abcdef123456" not in cmd_str
    assert "api_key_secret_999" not in cmd_str
    assert "[REDACTED]" in cmd_str
    # Safe custom bug bounty header remains visible
    assert "X-Bug-Bounty: hunter123" in cmd_str


def test_tool_registry():
    assert "subfinder" in RECON_TOOLS
    assert "dnsx" in RECON_TOOLS
    assert "httpx" in RECON_TOOLS
    assert "nuclei" in RECON_TOOLS
    assert "uro" in RECON_TOOLS
    assert "gf" in RECON_TOOLS
    
    all_status = get_all_tools_status()
    assert len(all_status) >= 19
    for tool in all_status:
        assert "name" in tool
        assert "installed" in tool
        assert "wsl_binary" in tool
        assert "install_hint" in tool


def test_system_tools_api_endpoint():
    from fastapi.testclient import TestClient
    from app.main import app
    from app.auth import get_current_user

    app.dependency_overrides[get_current_user] = lambda: {"username": "tester", "id": "123"}
    client = TestClient(app)
    
    response = client.get("/api/v1/system/tools")
    assert response.status_code == 200
    data = response.json()
    assert "tools" in data
    assert "total" in data
    assert "installed" in data
    assert "missing" in data
    assert data["total"] >= 19
    assert len(data["tools"]) == data["total"]
    app.dependency_overrides.clear()


def test_wildcard_does_not_match_root_without_separate_entry():
    """Item 7: '*.example.com' does NOT match 'example.com' unless 'example.com' is listed separately."""
    wildcard_only_scope = {
        "in_scope": ["*.example.com"],
        "out_of_scope": []
    }
    # Root domain must NOT match wildcard alone
    assert is_in_scope("example.com", wildcard_only_scope) is False
    assert is_in_scope("https://example.com", wildcard_only_scope) is False
    assert is_in_scope("http://example.com:8080/path", wildcard_only_scope) is False

    # Subdomains DO match
    assert is_in_scope("sub.example.com", wildcard_only_scope) is True
    assert is_in_scope("https://api.example.com/v1", wildcard_only_scope) is True
    assert is_in_scope("foo.bar.example.com", wildcard_only_scope) is True

    # When example.com is listed separately, it matches
    both_scope = {
        "in_scope": ["*.example.com", "example.com"],
        "out_of_scope": []
    }
    assert is_in_scope("example.com", both_scope) is True
    assert is_in_scope("https://example.com/test", both_scope) is True
    assert is_in_scope("sub.example.com", both_scope) is True


def test_katana_crawl_scope_and_regex():
    """Item 1: Katana crawl-scope regex generation and scope restriction flags."""
    import re
    from app.core.scope import build_scope_regex

    # 1. Regex test for subdomains
    cs_regex = build_scope_regex(["*.example.com"])
    assert cs_regex is not None
    compiled = re.compile(cs_regex)

    assert compiled.match("https://sub.example.com") is not None
    assert compiled.match("http://api.sub.example.com:8080/test?p=1") is not None
    # Must NOT match root domain alone or other domains
    assert compiled.match("https://example.com") is None
    assert compiled.match("https://notexample.com") is None
    assert compiled.match("https://bad-example.com/test") is None

    # 2. Combined regex with root domain
    both_regex = build_scope_regex(["*.example.com", "example.com"])
    compiled_both = re.compile(both_regex)
    assert compiled_both.match("https://example.com/page") is not None
    assert compiled_both.match("https://sub.example.com/page") is not None

    # 3. Out of scope regex
    cos_regex = build_scope_regex(["*.internal.example.com", "logout.example.com"])
    compiled_cos = re.compile(cos_regex)
    assert compiled_cos.match("https://secret.internal.example.com") is not None
    assert compiled_cos.match("https://logout.example.com") is not None


@pytest.mark.asyncio
async def test_httpx_redirect_scope_drop():
    """Item 2: HTTPX re-checks final/redirect-target host with is_in_scope and drops out-of-scope results."""
    from app.providers.httpx_provider import HttpxProvider

    scope = {
        "in_scope": ["*.example.com", "example.com"],
        "out_of_scope": ["blocked.example.com"]
    }

    # Case A: Redirects to external third-party domain -> dropped
    out_of_scope_payload = {
        "input": "login.example.com",
        "host": "evil-oauth.attacker.com",
        "url": "https://evil-oauth.attacker.com/oauth/authorize",
        "redirect_location": "https://evil-oauth.attacker.com/oauth/authorize",
        "status_code": 200,
    }
    assert is_in_scope(out_of_scope_payload["url"], scope) is False
    assert is_in_scope(out_of_scope_payload["host"], scope) is False

    # Case B: Redirects to blocked internal subdomain -> dropped
    blocked_payload = {
        "input": "portal.example.com",
        "host": "blocked.example.com",
        "url": "https://blocked.example.com/dashboard",
        "status_code": 200,
    }
    assert is_in_scope(blocked_payload["url"], scope) is False

    # Case C: Redirects within in-scope domain -> kept
    in_scope_payload = {
        "input": "example.com",
        "host": "www.example.com",
        "url": "https://www.example.com/",
        "status_code": 200,
    }
    assert is_in_scope(in_scope_payload["url"], scope) is True


def test_js_urls_filtered_through_scope_before_linkfinder():
    """Item 3: Filter all JS URLs (from Katana and SubJS) through is_in_scope BEFORE LinkFinder runs."""
    scope = {
        "in_scope": ["*.example.com"],
        "out_of_scope": ["out.example.com"]
    }

    # Combined candidate list from Katana and SubJS
    raw_js_files = [
        "https://sub.example.com/static/js/app.js",
        "https://cdn.thirdparty.com/libs/jquery.min.js",
        "https://out.example.com/admin.js",
        "https://api.example.com/bundle.js",
        "https://sub.example.com/static/js/app.js",  # duplicate
    ]

    kept, dropped = filter_scope(raw_js_files, scope)
    assert kept == [
        "https://sub.example.com/static/js/app.js",
        "https://api.example.com/bundle.js"
    ]
    assert "https://cdn.thirdparty.com/libs/jquery.min.js" in dropped
    assert "https://out.example.com/admin.js" in dropped


def test_rate_limit_defaults_and_global_rps_fallback():
    """Item 5: Default rate limits and fallback to global_rps for any tool without explicit override."""
    rate_limits_cfg = {
        "global_rps": 10,
        "per_tool": {
            "httpx": 20,
            "katana": 10,
            "nuclei": 10,
            "naabu": 300,
        }
    }
    global_rps = int(rate_limits_cfg.get("global_rps") or 10)
    per_tool_rps = rate_limits_cfg.get("per_tool") or {}

    def get_tool_rl(tool_name: str) -> int:
        return int(per_tool_rps.get(tool_name) or global_rps)

    assert get_tool_rl("httpx") == 20
    assert get_tool_rl("katana") == 10
    assert get_tool_rl("nuclei") == 10
    assert get_tool_rl("naabu") == 300
    # Tools with no explicit override receive global_rps (10)
    assert get_tool_rl("dalfox") == 10
    assert get_tool_rl("openredirex") == 10
    assert get_tool_rl("ffuf") == 10
