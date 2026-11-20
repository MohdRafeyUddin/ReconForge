"""Performance-focused tests for bounded nmap service detection."""

from app.providers.naabu_provider import NaabuProvider


def test_nmap_defaults_are_bounded():
    opts = NaabuProvider.normalize_nmap_options({})
    assert opts["enabled"] is True
    assert opts["scan_modes"] == ["deep"]
    assert opts["max_hosts"] == 25
    assert opts["concurrency"] == 5
    assert opts["timeout_seconds"] == 15
    assert opts["version_light"] is True


def test_nmap_options_are_clamped():
    opts = NaabuProvider.normalize_nmap_options({
        "max_hosts": 9999,
        "concurrency": 999,
        "timeout_seconds": 1,
        "scan_modes": "always",
    })
    assert opts["max_hosts"] == 500
    assert opts["concurrency"] == 20
    assert opts["timeout_seconds"] == 5
    assert opts["scan_modes"] == ["always"]


def test_fast_mode_skips_and_deep_mode_selects():
    ports = {"a.example.test": [80, 443]}
    selected, skipped, reason = NaabuProvider.select_nmap_targets(ports, "fast")
    assert selected == []
    assert skipped == 0
    assert "fast mode" in reason

    selected, skipped, reason = NaabuProvider.select_nmap_targets(ports, "deep")
    assert reason == ""
    assert skipped == 0
    assert selected == [("a.example.test", [80, 443])]


def test_disabled_nmap_skips():
    ports = {"a.example.test": [80]}
    selected, skipped, reason = NaabuProvider.select_nmap_targets(
        ports, "deep", {"enabled": False}
    )
    assert selected == []
    assert skipped == 0
    assert reason == "disabled"


def test_host_cap_and_interesting_port_priority():
    ports = {f"host{i}.example.test": [80, 443] for i in range(60)}
    ports["database.example.test"] = [3306, 5432]
    selected, skipped, reason = NaabuProvider.select_nmap_targets(ports, "deep")
    assert reason == ""
    assert len(selected) == 25
    assert skipped == 36
    # Host with non-standard database ports is prioritized first.
    assert selected[0][0] == "database.example.test"
    assert selected[0][1] == [3306, 5432]


def test_parse_nmap_service_lines():
    output = (
        "Nmap scan report for app.example.test\n"
        "PORT     STATE SERVICE  VERSION\n"
        "80/tcp   open  http     nginx 1.24.0\n"
        "3306/tcp open  mysql    MySQL 8.0.35\n"
        "22/tcp   closed ssh\n"
    )
    services = NaabuProvider.parse_nmap_services(output)
    assert services == [
        {"port": 80, "protocol": "tcp", "service": "http", "version": "nginx 1.24.0"},
        {"port": 3306, "protocol": "tcp", "service": "mysql", "version": "MySQL 8.0.35"},
    ]
