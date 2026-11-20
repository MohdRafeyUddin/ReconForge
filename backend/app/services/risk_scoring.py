import json
import os
import logging
from datetime import datetime
from collections import defaultdict
from urllib.parse import urlparse
from bson import ObjectId
from pymongo import UpdateOne
from app.database import get_database

logger = logging.getLogger("reconforge.services.risk_scoring")

def extract_host(url_or_domain: str) -> str:
    if not url_or_domain:
        return ""
    url_or_domain = url_or_domain.strip()
    if "://" in url_or_domain:
        try:
            parsed = urlparse(url_or_domain)
            return parsed.hostname or parsed.netloc or url_or_domain
        except Exception:
            return url_or_domain
    return url_or_domain

def load_weights() -> dict:
    try:
        config_path = os.path.join(os.path.dirname(__file__), "..", "config", "risk_weights.json")
        if os.path.exists(config_path):
            with open(config_path, "r", encoding="utf-8") as f:
                return json.load(f)
    except Exception as e:
        logger.error(f"Failed to load risk_weights.json: {e}")
    
    # Fallback weights
    return {
        "nuclei_severity": {
            "critical": 40,
            "high": 25,
            "medium": 10,
            "low": 5
        },
        "severity_floors": {
            "critical": 90,
            "high": 70,
            "medium": 40,
            "low": 10
        },
        "category_caps": {
            "nuclei": 50,
            "xss": 30,
            "open_redirect": 20,
            "subdomain_takeover": 40,
            "exposed_admin_panel": 25,
            "sensitive_file_leak": 25,
            "database_port": 20,
            "technology": 15,
            "tls": 10
        },
        "diminishing_returns": {
            "repeat_decay": 0.5,
            "min_repeat_weight": 1
        },
        "exposed_admin_panel": 20,
        "sensitive_file_leak": 20,
        "open_database_port": 15,
        "outdated_technology": 10,
        "no_https": 5,
        "subdomain_takeover": 30,
        "confirmed_open_redirect": 10,
        "confirmed_xss": 20
    }

def load_hunt_weights() -> dict:
    try:
        config_path = os.path.join(os.path.dirname(__file__), "..", "config", "hunt_weights.json")
        if os.path.exists(config_path):
            with open(config_path, "r", encoding="utf-8") as f:
                return json.load(f)
    except Exception as e:
        logger.error(f"Failed to load hunt_weights.json: {e}")
    
    return {
        "factors": {
            "is_new_or_changed": 15,
            "status_401_or_403": 15,
            "auth_or_admin_path": 20,
            "sensitive_naming": 15,
            "has_parameters": 15,
            "has_api_or_graphql": 15,
            "interesting_content_paths": 10,
            "no_waf_or_cdn": 10,
            "high_value_technology": 20,
            "has_js_endpoints": 10,
            "has_exposed_secrets": 25,
            "has_open_bucket": 20,
            "many_historical_urls": 10
        },
        "caps": {
            "is_new_or_changed": 15,
            "status_401_or_403": 15,
            "auth_or_admin_path": 25,
            "sensitive_naming": 15,
            "has_parameters": 20,
            "has_api_or_graphql": 20,
            "interesting_content_paths": 15,
            "no_waf_or_cdn": 10,
            "high_value_technology": 25,
            "has_js_endpoints": 10,
            "has_exposed_secrets": 25,
            "has_open_bucket": 25,
            "many_historical_urls": 10
        },
        "sensitive_keywords": ["dev", "stg", "stage", "staging", "uat", "test", "testing", "internal", "corp", "admin", "portal", "vpn", "gateway", "qa", "sandbox", "demo", "preprod", "nonprod"],
        "high_value_tech": ["jenkins", "grafana", "kibana", "tomcat", "phpmyadmin", "wordpress", "drupal", "joomla", "spring", "actuator", "sonarqube", "gitlab", "jira", "confluence", "cpanel", "webmin", "keycloak", "rabbitmq", "swagger", "openapi"]
    }


def compute_host_risk_and_hunt(
    h: dict,
    asset_findings: list,
    all_project_assets: list,
    new_or_changed_set: set,
    weights: dict,
    hunt_weights: dict,
) -> tuple:
    """
    Computes (risk_data, hunt_priority, hunt_reasons) for a single host document.
    Enforces Part B (floors, category caps, diminishing returns) and Part C (hunt priority).
    """
    category_caps = weights.get("category_caps", {})
    severity_floors = weights.get("severity_floors", {"critical": 90, "high": 70, "medium": 40, "low": 10})
    nuclei_weights = weights.get("nuclei_severity", {"critical": 40, "high": 25, "medium": 10, "low": 5})
    confirmed_xss_w = weights.get("confirmed_xss", 20)
    confirmed_open_redirect_w = weights.get("confirmed_open_redirect", 10)
    subdomain_takeover_w = weights.get("subdomain_takeover", 30)
    open_database_port_w = weights.get("open_database_port", 15)
    no_https_w = weights.get("no_https", 5)
    outdated_technology_w = weights.get("outdated_technology", 10)
    exposed_admin_panel_w = weights.get("exposed_admin_panel", 20)
    sensitive_file_leak_w = weights.get("sensitive_file_leak", 20)

    db_ports = {3306, 5432, 1433, 27017, 6379, 9200, 11211}
    severity_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}

    total_score = 0
    reasons = []
    exposure_factors = []
    host_domain = h.get("domain", "").lower()

    # 1. Nuclei Severity with category cap & diminishing returns per template
    nuclei_findings = [f for f in asset_findings if f.get("metadata", {}).get("source") == "nuclei"]
    severities = [f.get("metadata", {}).get("severity", "").lower() for f in nuclei_findings if f.get("metadata", {}).get("severity")]

    template_counts = defaultdict(int)
    nuclei_score = 0
    for f in nuclei_findings:
        sev = f.get("metadata", {}).get("severity", "").lower()
        t_id = f.get("metadata", {}).get("template_id") or f.get("metadata", {}).get("template") or "generic"
        count = template_counts[t_id]
        template_counts[t_id] += 1
        decay = 0.5 ** count
        base_w = nuclei_weights.get(sev, 0)
        if base_w > 0:
            nuclei_score += max(1, int(round(base_w * decay)))

    nuclei_cap = category_caps.get("nuclei", 50)
    capped_nuclei_score = min(nuclei_score, nuclei_cap)
    if capped_nuclei_score > 0:
        total_score += capped_nuclei_score
        reasons.append(f"Nuclei vulnerability findings (+{capped_nuclei_score})")

    # Determine floor for highest finding severity
    highest_severity = None
    for sev in severities:
        rank = severity_rank.get(sev, 0)
        if rank > severity_rank.get(highest_severity, -1):
            highest_severity = sev

    finding_floor = 0
    if highest_severity == "critical":
        finding_floor = severity_floors.get("critical", 90)
    elif highest_severity == "high":
        finding_floor = severity_floors.get("high", 70)
    elif highest_severity == "medium":
        finding_floor = severity_floors.get("medium", 40)
    elif highest_severity == "low":
        finding_floor = severity_floors.get("low", 10)

    # 2. Confirmed XSS (Dalfox) with category cap
    dalfox_findings = [f for f in asset_findings if f.get("metadata", {}).get("source") == "dalfox"]
    if dalfox_findings:
        xss_cap = category_caps.get("xss", 30)
        xss_score = min(len(dalfox_findings) * confirmed_xss_w, xss_cap)
        total_score += xss_score
        finding_floor = max(finding_floor, severity_floors.get("high", 70))
        reasons.append(f"Confirmed parameter XSS vulnerability via Dalfox (+{xss_score})")

    # 3. Confirmed Open Redirect (OpenRedirex) with category cap
    openredirex_findings = [f for f in asset_findings if f.get("metadata", {}).get("source") == "openredirex"]
    if openredirex_findings:
        or_cap = category_caps.get("open_redirect", 20)
        or_score = min(len(openredirex_findings) * confirmed_open_redirect_w, or_cap)
        total_score += or_score
        finding_floor = max(finding_floor, severity_floors.get("medium", 40))
        reasons.append(f"Confirmed Open Redirect vulnerability via OpenRedirex (+{or_score})")

    # 4. Subdomain Takeover
    is_takeover = (h.get("status") == "vulnerable" or 
                   h.get("metadata", {}).get("subzy", {}).get("takeover_status") == "Vulnerable")
    if is_takeover:
        takeover_cap = category_caps.get("subdomain_takeover", 40)
        takeover_score = min(subdomain_takeover_w, takeover_cap)
        total_score += takeover_score
        finding_floor = max(finding_floor, severity_floors.get("high", 70))
        reasons.append(f"Subdomain takeover vulnerability detected (+{takeover_score})")

    # 5. Open Database Port
    asset_ports = h.get("open_ports", [])
    matching_db_ports = [p for p in asset_ports if p in db_ports]
    if matching_db_ports:
        db_cap = category_caps.get("database_port", 20)
        db_score = min(open_database_port_w, db_cap)
        total_score += db_score
        reasons.append(f"Exposed database service port {matching_db_ports[0]} (+{db_score})")

    # 6. No HTTPS
    url = h.get("metadata", {}).get("url", "")
    is_live_http = h.get("status") == "live" or url.startswith("http")
    if is_live_http and not url.startswith("https://"):
        tls_cap = category_caps.get("tls", 10)
        tls_score = min(no_https_w, tls_cap)
        total_score += tls_score
        reasons.append(f"Unencrypted HTTP service (No HTTPS) (+{tls_score})")

    # 7. Outdated Technology
    technologies = h.get("metadata", {}).get("technologies") or h.get("metadata", {}).get("tech") or []
    outdated_indicators = ["jquery-migrate", "php-5", "python-2", "iis-7", "apache-2.2", "nginx-1.12", "windows-server-2008"]
    has_outdated_tech = any(any(ind in t.lower() for ind in outdated_indicators) for t in technologies)
    nuclei_eol = any("eol" in f.get("metadata", {}).get("evidence", "").lower() or 
                    "outdated" in f.get("metadata", {}).get("evidence", "").lower() or
                    "deprecated" in f.get("metadata", {}).get("evidence", "").lower()
                    for f in nuclei_findings)
    if has_outdated_tech or nuclei_eol:
        tech_cap = category_caps.get("technology", 15)
        tech_score = min(outdated_technology_w, tech_cap)
        total_score += tech_score
        reasons.append(f"Outdated or deprecated software/library EOL detected (+{tech_score})")

    # 8. Exposed Admin Panel
    title = h.get("metadata", {}).get("title", "").lower()
    url_lower = url.lower()
    has_admin_title_url = any(x in title or x in url_lower for x in ["admin", "login", "panel", "dashboard", "console", "interface"])
    has_admin_nuclei = any("admin" in f.get("metadata", {}).get("evidence", "").lower() or
                          "login" in f.get("metadata", {}).get("evidence", "").lower() or
                          "panel" in f.get("metadata", {}).get("evidence", "").lower()
                          for f in nuclei_findings)
    if has_admin_title_url or has_admin_nuclei:
        admin_cap = category_caps.get("exposed_admin_panel", 25)
        admin_score = min(exposed_admin_panel_w, admin_cap)
        total_score += admin_score
        reasons.append(f"Exposed administrator portal or login endpoint (+{admin_score})")

    # 9. Sensitive File Leak
    has_leak_nuclei = any(any(kw in f.get("metadata", {}).get("evidence", "").lower() for kw in ["config", "backup", "git", "env", "key", "token", "credential", "secret", ".env", ".git", "passwd", "shadow"])
                          for f in nuclei_findings)
    if has_leak_nuclei:
        leak_cap = category_caps.get("sensitive_file_leak", 25)
        leak_score = min(sensitive_file_leak_w, leak_cap)
        total_score += leak_score
        reasons.append(f"Exposed sensitive file leak detected (+{leak_score})")

    # Part B: final = max(capped_sum, floor_for_highest_finding)
    capped_sum = min(total_score, 100)
    final_score = max(capped_sum, finding_floor)
    final_score = min(100, max(0, final_score))

    # Risk Level mapping (backward compatible)
    if final_score >= 90:
        level = "Critical"
        recommended_priority = "Immediate remediation required"
    elif final_score >= 70:
        level = "High"
        recommended_priority = "High priority remediation"
    elif final_score >= 40:
        level = "Medium"
        recommended_priority = "Medium priority remediation"
    elif final_score >= 1:
        level = "Low"
        recommended_priority = "Low priority remediation"
    else:
        level = "Informational"
        recommended_priority = "No immediate action required"

    # Exposure factors
    is_live = h.get("status") == "live"
    has_ports = len(h.get("open_ports", [])) > 0
    internet_exposed = is_live or has_ports or (h.get("status") == "resolved")

    if internet_exposed:
        exposure_factors.append("Internet Exposed")
    if is_live_http:
        exposure_factors.append("HTTP/HTTPS Service")
    if has_ports:
        exposure_factors.append(f"Open Ports: {', '.join(map(str, asset_ports))}")

    # Asset importance
    importance_score = 0
    exposure_score = 20 if internet_exposed else 0

    if host_domain.startswith("admin."):
        importance_score = 25
        exposure_factors.append("Administrative Interface")
    elif host_domain.startswith("vpn."):
        importance_score = 25
        exposure_factors.append("VPN Access Portal")
    elif host_domain.startswith("jenkins."):
        importance_score = 25
        exposure_factors.append("CI/CD Pipeline Server")
    elif host_domain.startswith("api."):
        importance_score = 20
        exposure_factors.append("API exposure")
    elif host_domain.startswith("internal."):
        importance_score = 20
        exposure_factors.append("Internal System")
    elif host_domain.startswith("grafana."):
        importance_score = 15
        exposure_factors.append("Monitoring Console")
    elif host_domain.startswith("prometheus."):
        importance_score = 15
        exposure_factors.append("Monitoring System")
    elif host_domain.startswith("dev."):
        importance_score = 10
        exposure_factors.append("Development System")
    elif host_domain.startswith("staging."):
        importance_score = 10
        exposure_factors.append("Staging System")

    risk_data = {
        "score": final_score,
        "level": level,
        "reasons": reasons,
        "exposure_factors": exposure_factors,
        "recommended_priority": recommended_priority,
        "importance_score": importance_score,
        "exposure_score": exposure_score,
        "updated_at": datetime.utcnow()
    }

    # =========================================================================
    # PART C: Hunt-Priority Score (0-100) - Separate from risk, never merged
    # =========================================================================
    hunt_factors = hunt_weights.get("factors", {})
    hunt_caps = hunt_weights.get("caps", {})
    sensitive_keywords = hunt_weights.get("sensitive_keywords", [])
    high_value_tech = hunt_weights.get("high_value_tech", [])

    hunt_total = 0
    hunt_reasons = []

    # 1. New or changed since last run
    if host_domain in new_or_changed_set:
        w = min(hunt_factors.get("is_new_or_changed", 15), hunt_caps.get("is_new_or_changed", 15))
        hunt_total += w
        hunt_reasons.append(f"Newly discovered or modified host since last run (+{w})")

    # 2. 401 or 403 status code
    sc = h.get("status_code") or (h.get("metadata") or {}).get("status_code")
    if sc in (401, 403) or h.get("is_interesting"):
        w = min(hunt_factors.get("status_401_or_403", 15), hunt_caps.get("status_401_or_403", 15))
        hunt_total += w
        hunt_reasons.append(f"Restricted access boundary HTTP {sc or 403} (+{w})")

    # 3. Auth/admin/login/dashboard paths found
    host_cps = [
        cp for cp in all_project_assets
        if cp.get("type") == "content_path" and (cp.get("domain", "").lower() == host_domain or (cp.get("metadata") or {}).get("host", "").lower() == host_domain)
    ]
    has_auth_path = any(kw in title or kw in url_lower for kw in ("admin", "login", "portal", "dashboard", "console", "auth", "oauth", "sso")) or \
                    any(any(kw in (cp.get("value") or "").lower() for kw in ("admin", "login", "portal", "dashboard", "auth")) for cp in host_cps)
    if has_auth_path:
        w = min(hunt_factors.get("auth_or_admin_path", 20), hunt_caps.get("auth_or_admin_path", 25))
        hunt_total += w
        hunt_reasons.append(f"Authentication portal or administrative interface (+{w})")

    # 4. Sensitive naming (dev, stg, uat, test, internal, staging)
    matched_sens = [kw for kw in sensitive_keywords if kw in host_domain.split(".")]
    if not matched_sens:
        matched_sens = [kw for kw in sensitive_keywords if f"{kw}-" in host_domain or f"-{kw}" in host_domain]
    if matched_sens:
        w = min(hunt_factors.get("sensitive_naming", 15), hunt_caps.get("sensitive_naming", 15))
        hunt_total += w
        hunt_reasons.append(f"Non-production naming indicator '{matched_sens[0]}' (+{w})")

    # 5. Parameters present (param assets and GF classes)
    host_params = [p for p in all_project_assets if p.get("type") == "param" and p.get("domain", "").lower() == host_domain]
    has_gf_for_host = any(g for g in all_project_assets if g.get("type") == "gf_url" and g.get("domain", "").lower() == host_domain)
    if host_params or has_gf_for_host:
        w = min(hunt_factors.get("has_parameters", 15), hunt_caps.get("has_parameters", 20))
        hunt_total += w
        hunt_reasons.append(f"Fuzzable input parameters identified ({len(host_params)} params) (+{w})")

    # 6. API / Swagger / GraphQL surface
    host_apis = [ap for ap in all_project_assets if ap.get("type") in ("api_spec", "graphql_endpoint") and ap.get("domain", "").lower() == host_domain]
    if host_apis or "api." in host_domain or "/api" in url_lower:
        w = min(hunt_factors.get("has_api_or_graphql", 15), hunt_caps.get("has_api_or_graphql", 20))
        hunt_total += w
        hunt_reasons.append(f"API specification or GraphQL attack surface (+{w})")

    # 7. Discovered content paths with status 200/401/403
    interesting_cps = [
        cp for cp in host_cps
        if (cp.get("status_code") or (cp.get("metadata") or {}).get("status_code")) in (200, 401, 403)
    ]
    if interesting_cps:
        w = min(hunt_factors.get("interesting_content_paths", 10), hunt_caps.get("interesting_content_paths", 15))
        hunt_total += w
        hunt_reasons.append(f"Reachable content paths discovered ({len(interesting_cps)} paths) (+{w})")

    # 8. No WAF / CDN
    cdn_waf = h.get("cdn_waf") or {}
    is_waf_cdn = cdn_waf.get("is_waf") or cdn_waf.get("is_cdn")
    if is_live_http and not is_waf_cdn:
        w = min(hunt_factors.get("no_waf_or_cdn", 10), hunt_caps.get("no_waf_or_cdn", 10))
        hunt_total += w
        hunt_reasons.append(f"Direct origin service without WAF/CDN edge (+{w})")

    # 9. High-value technology (Jenkins, Grafana, Kibana, Tomcat, WordPress, etc.)
    matched_tech = [t for t in technologies if any(hvt in str(t).lower() for hvt in high_value_tech)]
    if matched_tech:
        w = min(hunt_factors.get("high_value_technology", 20), hunt_caps.get("high_value_technology", 25))
        hunt_total += w
        hunt_reasons.append(f"High-value target technology ({matched_tech[0]}) (+{w})")

    # 10. Exposed JS endpoints
    host_js = [js for js in all_project_assets if js.get("type") == "js_file" and js.get("domain", "").lower() == host_domain]
    if host_js:
        w = min(hunt_factors.get("has_js_endpoints", 10), hunt_caps.get("has_js_endpoints", 10))
        hunt_total += w
        hunt_reasons.append(f"Exposed JavaScript endpoints for review ({len(host_js)} scripts) (+{w})")

    # 11. Exposed secrets (masked findings only)
    host_secrets = [
        s for s in all_project_assets
        if s.get("type") in ("secret_finding", "secret")
        and (
            s.get("domain", "").lower() == host_domain
            or (s.get("metadata") or {}).get("host", "").lower() == host_domain
        )
    ]
    if host_secrets:
        w = min(hunt_factors.get("has_exposed_secrets", 25), hunt_caps.get("has_exposed_secrets", 25))
        hunt_total += w
        hunt_reasons.append(f"Exposed secret candidates on host ({len(host_secrets)}) (+{w})")

    # 12. Public/open cloud buckets tied to this host
    host_buckets = [
        b for b in all_project_assets
        if b.get("type") in ("bucket", "cloud_bucket")
        and (
            b.get("domain", "").lower() == host_domain
            or (b.get("metadata") or {}).get("host", "").lower() == host_domain
        )
    ]
    if host_buckets:
        public_bucket = any(bool((b.get("metadata") or {}).get("public")) for b in host_buckets)
        w = min(
            hunt_factors.get("has_open_bucket", 20) + (5 if public_bucket else 0),
            hunt_caps.get("has_open_bucket", 25),
        )
        hunt_total += w
        hunt_reasons.append(
            f"Cloud bucket candidate tied to host ({len(host_buckets)}"
            f"{', public listing' if public_bucket else ''}) (+{w})"
        )

    # 13. Many historical URLs (>= 10)
    host_hist = [u for u in all_project_assets if u.get("type") in ("historical_url", "uro_url", "gf_url") and u.get("domain", "").lower() == host_domain]
    if len(host_hist) >= 10:
        w = min(hunt_factors.get("many_historical_urls", 10), hunt_caps.get("many_historical_urls", 10))
        hunt_total += w
        hunt_reasons.append(f"Broad historical footprint ({len(host_hist)} archive URLs) (+{w})")

    hunt_priority = min(100, max(0, hunt_total))

    return risk_data, hunt_priority, hunt_reasons


async def calculate_risk_score(asset_id: str) -> dict:
    """
    Computes risk score and hunt priority for a single asset.
    """
    db = get_database()
    try:
        query_id = ObjectId(asset_id) if isinstance(asset_id, str) and len(asset_id) == 24 else asset_id
    except Exception:
        query_id = asset_id

    asset = await db.assets.find_one({"_id": query_id})
    if not asset:
        raise ValueError(f"Asset not found: {asset_id}")

    project_id = asset.get("project_id")
    host_domain = asset.get("domain", "").lower()

    findings_cursor = db.assets.find({"project_id": project_id, "type": "finding"})
    all_project_findings = await findings_cursor.to_list(length=10000)
    asset_findings = [f for f in all_project_findings if extract_host(f.get("domain", "")).lower() == host_domain]

    all_assets_cursor = db.assets.find({"project_id": project_id})
    all_project_assets = await all_assets_cursor.to_list(length=20000)

    weights = load_weights()
    hunt_weights = load_hunt_weights()

    risk_data, hunt_priority, hunt_reasons = compute_host_risk_and_hunt(
        asset, asset_findings, all_project_assets, set(), weights, hunt_weights
    )

    return {
        "asset": asset.get("domain"),
        "score": risk_data["score"],
        "level": risk_data["level"],
        "reasons": risk_data["reasons"],
        "exposure_factors": risk_data["exposure_factors"],
        "recommended_priority": risk_data["recommended_priority"],
        "importance_score": risk_data["importance_score"],
        "exposure_score": risk_data["exposure_score"],
        "updated_at": risk_data["updated_at"],
        "hunt_priority": hunt_priority,
        "hunt_reasons": hunt_reasons,
    }


async def recalculate_all_scores(project_id: str) -> list:
    """
    Iterates every asset in the project, calculates risk score and hunt priority,
    and bulk-writes results back to each asset document.
    Returns list of scored assets dicts.
    """
    db = get_database()
    if db is None:
        return []

    # 1. Fetch all assets for this project
    assets_cursor = db.assets.find({"project_id": str(project_id)})
    all_project_assets = await assets_cursor.to_list(length=100000)

    from app.services.asset_counts import HOST_ASSET_TYPES, is_passive_candidate

    hosts = [
        a for a in all_project_assets
        if str(a.get("type") or "").strip().lower() in HOST_ASSET_TYPES
        and not is_passive_candidate(a)
    ]
    findings = [a for a in all_project_assets if a.get("type") == "finding"]

    # 2. Extract new or changed hosts from latest scan diff
    new_or_changed_set = set()
    try:
        latest_diff = await db.scan_diffs.find_one({"project_id": str(project_id)}, sort=[("created_at", -1)])
        if latest_diff:
            for s in latest_diff.get("new_subdomains", []):
                new_or_changed_set.add(str(s).lower())
            for h in latest_diff.get("new_live_hosts", []):
                new_or_changed_set.add(str(h).lower())
            for ch in latest_diff.get("changed_hosts", []):
                new_or_changed_set.add(str(ch.get("domain", "")).lower())
            for mj in latest_diff.get("modified_js_files", []):
                host = str((mj or {}).get("host") or "").lower()
                if host:
                    new_or_changed_set.add(host)
    except Exception as e:
        logger.debug(f"Could not load scan diff for hunt scoring: {e}")

    # Group findings by host
    findings_by_host = defaultdict(list)
    for f in findings:
        f_host = extract_host(f.get("domain", "")).lower()
        findings_by_host[f_host].append(f)

    weights = load_weights()
    hunt_weights = load_hunt_weights()

    results = []
    bulk_updates = []
    now = datetime.utcnow()

    for h in hosts:
        host_domain = h.get("domain", "").lower()
        asset_findings = findings_by_host.get(host_domain, [])

        risk_data, hunt_priority, hunt_reasons = compute_host_risk_and_hunt(
            h, asset_findings, all_project_assets, new_or_changed_set, weights, hunt_weights
        )

        history = h.get("risk_history", [])
        history.append({"score": risk_data["score"], "date": now})
        history = history[-20:]

        results.append({
            "asset": h.get("domain"),
            "score": risk_data["score"],
            "level": risk_data["level"],
            "reasons": risk_data["reasons"],
            "exposure_factors": risk_data["exposure_factors"],
            "recommended_priority": risk_data["recommended_priority"],
            "importance_score": risk_data["importance_score"],
            "exposure_score": risk_data["exposure_score"],
            "updated_at": now,
            "hunt_priority": hunt_priority,
            "hunt_reasons": hunt_reasons,
        })

        update_doc = {
            "$set": {
                "risk": risk_data,
                "risk_history": history,
                "hunt_priority": hunt_priority,
                "hunt_reasons": hunt_reasons,
            }
        }
        bulk_updates.append((h["_id"], update_doc))

    # Write updates
    if bulk_updates:
        from app.database import db_helper
        is_mock = getattr(db_helper, "is_mock", False)
        if is_mock or not hasattr(db.assets, "bulk_write"):
            for aid, update in bulk_updates:
                await db.assets.update_one({"_id": aid}, update)
        else:
            requests = [UpdateOne({"_id": aid}, update) for aid, update in bulk_updates]
            await db.assets.bulk_write(requests)

    return results
