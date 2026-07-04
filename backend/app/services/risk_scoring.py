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
        "exposed_admin_panel": 20,
        "sensitive_file_leak": 20,
        "open_database_port": 15,
        "outdated_technology": 10,
        "no_https": 5,
        "subdomain_takeover": 30,
        "confirmed_open_redirect": 10,
        "confirmed_xss": 20
    }

async def calculate_risk_score(asset_id: str) -> dict:
    """
    Loads risk_weights.json, queries MongoDB for all findings tied to this asset,
    computes the 0-100 risk score and returns a dictionary.
    """
    db = get_database()
    
    # Fetch asset
    try:
        query_id = ObjectId(asset_id) if isinstance(asset_id, str) and len(asset_id) == 24 else asset_id
    except Exception:
        query_id = asset_id
        
    asset = await db.assets.find_one({"_id": query_id})
    if not asset:
        raise ValueError(f"Asset not found: {asset_id}")
        
    project_id = asset.get("project_id")
    host_domain = asset.get("domain", "").lower()
    
    # Fetch findings for this domain/host
    # Findings are stored with project_id and domain mapping to host/vulnerable URL
    findings_cursor = db.assets.find({
        "project_id": project_id,
        "type": "finding"
    })
    
    all_project_findings = await findings_cursor.to_list(length=10000)
    asset_findings = []
    for f in all_project_findings:
        f_host = extract_host(f.get("domain", "")).lower()
        if f_host == host_domain:
            asset_findings.append(f)
            
    # Compute score
    weights = load_weights()
    total_score = 0
    reasons = []
    exposure_factors = []
    
    # 1. Nuclei Severity
    nuclei_weights = weights.get("nuclei_severity", {})
    nuclei_findings = [f for f in asset_findings if f.get("metadata", {}).get("source") == "nuclei"]
    severities = [f.get("metadata", {}).get("severity", "").lower() for f in nuclei_findings if f.get("metadata", {}).get("severity")]
    
    highest_severity = None
    highest_sev_weight = 0
    severity_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
    for sev in severities:
        rank = severity_rank.get(sev, 0)
        if rank > severity_rank.get(highest_severity, -1):
            highest_severity = sev
            highest_sev_weight = nuclei_weights.get(sev, 0)
            
    if highest_severity:
        total_score += highest_sev_weight
        reasons.append(f"Highest severity nuclei vulnerability: {highest_severity.upper()} (+{highest_sev_weight})")
        
    # 2. Confirmed XSS
    confirmed_xss_w = weights.get("confirmed_xss", 20)
    dalfox_findings = [f for f in asset_findings if f.get("metadata", {}).get("source") == "dalfox"]
    if dalfox_findings:
        total_score += confirmed_xss_w
        reasons.append(f"Confirmed parameter XSS vulnerability via Dalfox (+{confirmed_xss_w})")
        
    # 3. Confirmed Open Redirect
    confirmed_open_redirect_w = weights.get("confirmed_open_redirect", 10)
    openredirex_findings = [f for f in asset_findings if f.get("metadata", {}).get("source") == "openredirex"]
    if openredirex_findings:
        total_score += confirmed_open_redirect_w
        reasons.append(f"Confirmed Open Redirect vulnerability via OpenRedirex (+{confirmed_open_redirect_w})")
        
    # 4. Subdomain Takeover
    subdomain_takeover_w = weights.get("subdomain_takeover", 30)
    is_takeover = (asset.get("status") == "vulnerable" or 
                   asset.get("metadata", {}).get("subzy", {}).get("takeover_status") == "Vulnerable")
    if is_takeover:
        total_score += subdomain_takeover_w
        reasons.append(f"Subdomain takeover vulnerability detected (+{subdomain_takeover_w})")
        
    # 5. Open Database Port
    open_database_port_w = weights.get("open_database_port", 15)
    db_ports = {3306, 5432, 1433, 27017, 6379, 9200, 11211}
    asset_ports = asset.get("open_ports", [])
    matching_db_ports = [p for p in asset_ports if p in db_ports]
    if matching_db_ports:
        total_score += open_database_port_w
        reasons.append(f"Exposed database service port {matching_db_ports[0]} (+{open_database_port_w})")
        
    # 6. No HTTPS
    no_https_w = weights.get("no_https", 5)
    url = asset.get("metadata", {}).get("url", "")
    is_live_http = asset.get("status") == "live" or url.startswith("http")
    if is_live_http and not url.startswith("https://"):
        total_score += no_https_w
        reasons.append(f"Unencrypted HTTP service (No HTTPS) (+{no_https_w})")
        
    # 7. Outdated Technology
    outdated_technology_w = weights.get("outdated_technology", 10)
    technologies = asset.get("metadata", {}).get("technologies", [])
    outdated_indicators = ["jquery-migrate", "php-5", "python-2", "iis-7", "apache-2.2", "nginx-1.12", "windows-server-2008"]
    has_outdated_tech = any(any(ind in t.lower() for ind in outdated_indicators) for t in technologies)
    nuclei_eol = any("eol" in f.get("metadata", {}).get("evidence", "").lower() or 
                    "outdated" in f.get("metadata", {}).get("evidence", "").lower() or
                    "deprecated" in f.get("metadata", {}).get("evidence", "").lower()
                    for f in nuclei_findings)
    if has_outdated_tech or nuclei_eol:
        total_score += outdated_technology_w
        reasons.append(f"Outdated or deprecated software/library EOL detected (+{outdated_technology_w})")
        
    # 8. Exposed Admin Panel
    exposed_admin_panel_w = weights.get("exposed_admin_panel", 20)
    title = asset.get("metadata", {}).get("title", "").lower()
    url_lower = url.lower()
    has_admin_title_url = any(x in title or x in url_lower for x in ["admin", "login", "panel", "dashboard", "console", "interface"])
    has_admin_nuclei = any("admin" in f.get("metadata", {}).get("evidence", "").lower() or
                          "login" in f.get("metadata", {}).get("evidence", "").lower() or
                          "panel" in f.get("metadata", {}).get("evidence", "").lower()
                          for f in nuclei_findings)
    if has_admin_title_url or has_admin_nuclei:
        total_score += exposed_admin_panel_w
        reasons.append(f"Exposed administrator portal or login endpoint (+{exposed_admin_panel_w})")
        
    # 9. Sensitive File Leak
    sensitive_file_leak_w = weights.get("sensitive_file_leak", 20)
    has_leak_nuclei = any(any(kw in f.get("metadata", {}).get("evidence", "").lower() for kw in ["config", "backup", "git", "env", "key", "token", "credential", "secret", ".env", ".git", "passwd", "shadow"])
                          for f in nuclei_findings)
    if has_leak_nuclei:
        total_score += sensitive_file_leak_w
        reasons.append(f"Exposed sensitive file leak detected (+{sensitive_file_leak_w})")
        
    # Cap score at 100
    final_score = min(total_score, 100)
    
    # Risk Level mapping
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
    is_live = asset.get("status") == "live"
    has_ports = len(asset.get("open_ports", [])) > 0
    internet_exposed = is_live or has_ports or (asset.get("status") == "resolved")
    
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
        
    return {
        "asset": asset.get("domain"),
        "score": final_score,
        "level": level,
        "reasons": reasons,
        "exposure_factors": exposure_factors,
        "recommended_priority": recommended_priority,
        "importance_score": importance_score,
        "exposure_score": exposure_score,
        "updated_at": datetime.utcnow()
    }

async def recalculate_all_scores(project_id: str) -> list:
    """
    Iterates every asset in the project, calculates risk score,
    and bulk-writes results back to each asset document.
    Returns list of scored assets dicts.
    """
    db = get_database()
    
    # 1. Fetch all assets for this project
    assets_cursor = db.assets.find({"project_id": project_id})
    all_project_assets = await assets_cursor.to_list(length=100000)
    
    # Separate findings from hosts
    hosts = [a for a in all_project_assets if a.get("type") in ("subdomain", "domain", "ip", "service")]
    findings = [a for a in all_project_assets if a.get("type") == "finding"]
    
    # Group findings in memory by canonical host name
    findings_by_host = defaultdict(list)
    for f in findings:
        f_host = extract_host(f.get("domain", "")).lower()
        findings_by_host[f_host].append(f)
        
    weights = load_weights()
    nuclei_weights = weights.get("nuclei_severity", {})
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
    
    results = []
    bulk_updates = []
    
    now = datetime.utcnow()
    
    # Calculate for each host
    for h in hosts:
        total_score = 0
        reasons = []
        exposure_factors = []
        
        host_domain = h.get("domain", "").lower()
        asset_findings = findings_by_host.get(host_domain, [])
        
        # 1. Nuclei Severity
        nuclei_findings = [f for f in asset_findings if f.get("metadata", {}).get("source") == "nuclei"]
        severities = [f.get("metadata", {}).get("severity", "").lower() for f in nuclei_findings if f.get("metadata", {}).get("severity")]
        
        highest_severity = None
        highest_sev_weight = 0
        for sev in severities:
            rank = severity_rank.get(sev, 0)
            if rank > severity_rank.get(highest_severity, -1):
                highest_severity = sev
                highest_sev_weight = nuclei_weights.get(sev, 0)
                
        if highest_severity:
            total_score += highest_sev_weight
            reasons.append(f"Highest severity nuclei vulnerability: {highest_severity.upper()} (+{highest_sev_weight})")
            
        # 2. Confirmed XSS
        dalfox_findings = [f for f in asset_findings if f.get("metadata", {}).get("source") == "dalfox"]
        if dalfox_findings:
            total_score += confirmed_xss_w
            reasons.append(f"Confirmed parameter XSS vulnerability via Dalfox (+{confirmed_xss_w})")
            
        # 3. Confirmed Open Redirect
        openredirex_findings = [f for f in asset_findings if f.get("metadata", {}).get("source") == "openredirex"]
        if openredirex_findings:
            total_score += confirmed_open_redirect_w
            reasons.append(f"Confirmed Open Redirect vulnerability via OpenRedirex (+{confirmed_open_redirect_w})")
            
        # 4. Subdomain Takeover
        is_takeover = (h.get("status") == "vulnerable" or 
                       h.get("metadata", {}).get("subzy", {}).get("takeover_status") == "Vulnerable")
        if is_takeover:
            total_score += subdomain_takeover_w
            reasons.append(f"Subdomain takeover vulnerability detected (+{subdomain_takeover_w})")
            
        # 5. Open Database Port
        asset_ports = h.get("open_ports", [])
        matching_db_ports = [p for p in asset_ports if p in db_ports]
        if matching_db_ports:
            total_score += open_database_port_w
            reasons.append(f"Exposed database service port {matching_db_ports[0]} (+{open_database_port_w})")
            
        # 6. No HTTPS
        url = h.get("metadata", {}).get("url", "")
        is_live_http = h.get("status") == "live" or url.startswith("http")
        if is_live_http and not url.startswith("https://"):
            total_score += no_https_w
            reasons.append(f"Unencrypted HTTP service (No HTTPS) (+{no_https_w})")
            
        # 7. Outdated Technology
        technologies = h.get("metadata", {}).get("technologies", [])
        outdated_indicators = ["jquery-migrate", "php-5", "python-2", "iis-7", "apache-2.2", "nginx-1.12", "windows-server-2008"]
        has_outdated_tech = any(any(ind in t.lower() for ind in outdated_indicators) for t in technologies)
        nuclei_eol = any("eol" in f.get("metadata", {}).get("evidence", "").lower() or 
                        "outdated" in f.get("metadata", {}).get("evidence", "").lower() or
                        "deprecated" in f.get("metadata", {}).get("evidence", "").lower()
                        for f in nuclei_findings)
        if has_outdated_tech or nuclei_eol:
            total_score += outdated_technology_w
            reasons.append(f"Outdated or deprecated software/library EOL detected (+{outdated_technology_w})")
            
        # 8. Exposed Admin Panel
        title = h.get("metadata", {}).get("title", "").lower()
        url_lower = url.lower()
        has_admin_title_url = any(x in title or x in url_lower for x in ["admin", "login", "panel", "dashboard", "console", "interface"])
        has_admin_nuclei = any("admin" in f.get("metadata", {}).get("evidence", "").lower() or
                              "login" in f.get("metadata", {}).get("evidence", "").lower() or
                              "panel" in f.get("metadata", {}).get("evidence", "").lower()
                              for f in nuclei_findings)
        if has_admin_title_url or has_admin_nuclei:
            total_score += exposed_admin_panel_w
            reasons.append(f"Exposed administrator portal or login endpoint (+{exposed_admin_panel_w})")
            
        # 9. Sensitive File Leak
        has_leak_nuclei = any(any(kw in f.get("metadata", {}).get("evidence", "").lower() for kw in ["config", "backup", "git", "env", "key", "token", "credential", "secret", ".env", ".git", "passwd", "shadow"])
                              for f in nuclei_findings)
        if has_leak_nuclei:
            total_score += sensitive_file_leak_w
            reasons.append(f"Exposed sensitive file leak detected (+{sensitive_file_leak_w})")
            
        # Cap score at 100
        final_score = min(total_score, 100)
        
        # Risk Level mapping
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
            
        # Risk history (Keep latest 20 entries)
        history = h.get("risk_history", [])
        history.append({"score": final_score, "date": now})
        history = history[-20:]
        
        risk_data = {
            "score": final_score,
            "level": level,
            "reasons": reasons,
            "exposure_factors": exposure_factors,
            "recommended_priority": recommended_priority,
            "importance_score": importance_score,
            "exposure_score": exposure_score,
            "updated_at": now
        }
        
        results.append({
            "asset": h.get("domain"),
            "score": final_score,
            "level": level,
            "reasons": reasons,
            "exposure_factors": exposure_factors,
            "recommended_priority": recommended_priority,
            "importance_score": importance_score,
            "exposure_score": exposure_score,
            "updated_at": now
        })
        
        # Prepare bulk update
        update_doc = {
            "$set": {
                "risk": risk_data,
                "risk_history": history
            }
        }
        bulk_updates.append((h["_id"], update_doc))
        
    # Write updates
    if bulk_updates:
        is_mock = getattr(db, "is_mock", False)
        # Check if assets is a MockCollection (for safety)
        if is_mock or not hasattr(db.assets, "bulk_write"):
            # Update individually for Mock DB compatibility
            for aid, update in bulk_updates:
                await db.assets.update_one({"_id": aid}, update)
        else:
            # Pymongo UpdateOne bulk write for high performance
            requests = [UpdateOne({"_id": aid}, update) for aid, update in bulk_updates]
            await db.assets.bulk_write(requests)
            
    return results
