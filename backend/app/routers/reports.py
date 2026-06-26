from fastapi import APIRouter, HTTPException, Depends
from fastapi.responses import HTMLResponse
from bson import ObjectId
from app.database import get_database
from app.auth import get_current_user
from app.models import serialize_doc
from datetime import datetime

router = APIRouter(prefix="/reports", tags=["Reports"])

@router.get("/project/{project_id}/summary")
async def get_report_summary(project_id: str, current_user: dict = Depends(get_current_user)):
    db = get_database()
    if not ObjectId.is_valid(project_id):
        raise HTTPException(status_code=400, detail="Invalid project ID format")
        
    project = await db.projects.find_one({
        "_id": ObjectId(project_id),
        "owner_id": str(current_user["_id"])
    })
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    cursor = db.assets.find({"project_id": project_id})
    assets = await cursor.to_list(length=1000)
    
    # Analyze risk factors (exposed administrative ports, expired TLS certs, etc.)
    exposed_admin_services = []
    total_ports = set()
    live_count = 0
    subdomains = []
    
    for asset in assets:
        if asset.get("status") == "live":
            live_count += 1
            
        if asset.get("type") == "subdomain":
            subdomains.append(asset.get("domain"))
            
        ports = asset.get("open_ports", [])
        for p in ports:
            total_ports.add(p)
            # Port alerts
            if p in [22, 21, 23, 3389, 445, 139]:
                exposed_admin_services.append({
                    "domain": asset["domain"],
                    "port": p,
                    "service": "SSH" if p==22 else "FTP" if p==21 else "Telnet" if p==23 else "RDP" if p==3389 else "SMB"
                })
                
    # Compile summary
    summary = {
        "project_name": project["name"],
        "generated_at": datetime.utcnow().isoformat(),
        "total_assets": len(assets),
        "live_hosts": live_count,
        "unique_open_ports": list(total_ports),
        "exposed_admin_services": exposed_admin_services,
        "risk_score": 100 - (len(exposed_admin_services) * 10) if len(exposed_admin_services) <= 10 else 0
    }
    
    return summary

@router.get("/project/{project_id}/export/html", response_class=HTMLResponse)
async def export_html_report(project_id: str, current_user: dict = Depends(get_current_user)):
    db = get_database()
    if not ObjectId.is_valid(project_id):
        raise HTTPException(status_code=400, detail="Invalid project ID format")
        
    project = await db.projects.find_one({
        "_id": ObjectId(project_id),
        "owner_id": str(current_user["_id"])
    })
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    cursor = db.assets.find({"project_id": project_id})
    assets = await cursor.to_list(length=1000)
    
    # Organize assets
    subdomains_rows = ""
    exposed_rows = ""
    risk_score = 100
    
    for a in assets:
        ports_str = ", ".join(map(str, a.get("open_ports", []))) or "None"
        source = a.get("metadata", {}).get("source", a.get("discovered_by", "Unknown"))
        ip = a.get("metadata", {}).get("ip_address", "N/A")
        
        subdomains_rows += f"""
        <tr>
            <td style="padding: 10px; border-bottom: 1px solid #1E2638;">{a['domain']}</td>
            <td style="padding: 10px; border-bottom: 1px solid #1E2638;">{a['type'].capitalize()}</td>
            <td style="padding: 10px; border-bottom: 1px solid #1E2638;">{ip}</td>
            <td style="padding: 10px; border-bottom: 1px solid #1E2638;"><span style="color: {'#10B981' if a['status']=='live' else '#9CA3AF'}">{a['status'].upper()}</span></td>
            <td style="padding: 10px; border-bottom: 1px solid #1E2638;">{ports_str}</td>
            <td style="padding: 10px; border-bottom: 1px solid #1E2638;">{source}</td>
        </tr>
        """
        
        # Check alerts
        for p in a.get("open_ports", []):
            if p in [22, 21, 23, 3389, 445, 139]:
                risk_score -= 10
                service = "SSH" if p==22 else "FTP" if p==21 else "Telnet" if p==23 else "RDP" if p==3389 else "SMB"
                exposed_rows += f"""
                <tr>
                    <td style="padding: 10px; border-bottom: 1px solid #1E2638; color: #EF4444;">HIGH</td>
                    <td style="padding: 10px; border-bottom: 1px solid #1E2638;">{a['domain']}</td>
                    <td style="padding: 10px; border-bottom: 1px solid #1E2638;">Exposed Management Port ({service} on Port {p})</td>
                </tr>
                """
                
    risk_score = max(0, risk_score)
    risk_color = "#10B981" if risk_score >= 80 else "#F59E0B" if risk_score >= 50 else "#EF4444"
    
    html_content = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>ReconForge - Attack Surface Audit Report</title>
        <style>
            body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background-color: #0A0D14; color: #F3F4F6; margin: 0; padding: 40px; }}
            .container {{ max-width: 1000px; margin: 0 auto; background: #111622; border: 1px solid #1E2638; border-radius: 8px; padding: 30px; }}
            h1, h2 {{ color: #3B82F6; margin-top: 0; }}
            .stats-grid {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 15px; margin-bottom: 30px; }}
            .stat-card {{ background: #161D2E; border: 1px solid #1E2638; padding: 15px; border-radius: 6px; text-align: center; }}
            .stat-num {{ font-size: 24px; font-weight: bold; color: #F3F4F6; margin-top: 5px; }}
            .score-circle {{ display: inline-block; width: 80px; height: 80px; border-radius: 50%; border: 4px solid {risk_color}; text-align: center; line-height: 80px; font-size: 24px; font-weight: bold; color: {risk_color}; }}
            table {{ width: 100%; border-collapse: collapse; margin-top: 20px; }}
            th {{ background: #161D2E; text-align: left; padding: 10px; color: #9CA3AF; }}
        </style>
    </head>
    <body>
        <div class="container">
            <div style="display: flex; justify-content: space-between; align-items: center; border-bottom: 2px solid #1E2638; padding-bottom: 20px; margin-bottom: 30px;">
                <div>
                    <h1>ReconForge Attack Surface Report</h1>
                    <p style="color: #9CA3AF; margin: 0;">Project: <strong>{project['name']}</strong></p>
                    <p style="color: #6B7280; font-size: 12px; margin-top: 5px;">Generated on: {datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")}</p>
                </div>
                <div style="text-align: center;">
                    <div class="score-circle">{risk_score}</div>
                    <div style="font-size: 11px; margin-top: 5px; color: #9CA3AF; text-transform: uppercase;">Security Score</div>
                </div>
            </div>
            
            <h2>Executive Dashboard Summary</h2>
            <div class="stats-grid">
                <div class="stat-card">
                    <div style="color: #9CA3AF; font-size: 12px;">Total Discovered Assets</div>
                    <div class="stat-num">{len(assets)}</div>
                </div>
                <div class="stat-card">
                    <div style="color: #9CA3AF; font-size: 12px;">Active Live Hosts</div>
                    <div class="stat-num" style="color: #10B981;">{sum(1 for a in assets if a.get('status')=='live')}</div>
                </div>
                <div class="stat-card">
                    <div style="color: #9CA3AF; font-size: 12px;">Security Findings</div>
                    <div class="stat-num" style="color: #EF4444;">{risk_score // 10 if risk_score < 100 else 0}</div>
                </div>
                <div class="stat-card">
                    <div style="color: #9CA3AF; font-size: 12px;">Seed Targets</div>
                    <div class="stat-num" style="color: #3B82F6;">{len(project['seed_domains'])}</div>
                </div>
            </div>

            {f'''
            <h2 style="color: #EF4444; margin-top: 40px;">Critical Vulnerabilities / Open Management Ports</h2>
            <table>
                <thead>
                    <tr>
                        <th style="width: 15%;">Severity</th>
                        <th style="width: 35%;">Asset / Subdomain</th>
                        <th style="width: 50%;">Description</th>
                    </tr>
                </thead>
                <tbody>
                    {exposed_rows}
                </tbody>
            </table>
            ''' if exposed_rows else '<p style="color: #10B981; font-weight: bold; margin-top: 40px;">[✓] No critical open administrative ports detected.</p>'}

            <h2 style="margin-top: 40px;">Detailed Asset Inventory</h2>
            <table>
                <thead>
                    <tr>
                        <th>Asset Name</th>
                        <th>Type</th>
                        <th>IP Address</th>
                        <th>Status</th>
                        <th>Ports</th>
                        <th>Discovered Via</th>
                    </tr>
                </thead>
                <tbody>
                    {subdomains_rows or '<tr><td colspan="6" style="text-align: center; padding: 20px; color: #9CA3AF;">No assets discovered yet. Run a scan.</td></tr>'}
                </tbody>
            </table>
        </div>
    </body>
    </html>
    """
    return html_content
