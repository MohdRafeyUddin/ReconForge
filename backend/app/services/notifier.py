"""
Webhook Alert Notifier (Discord & Telegram)
===========================================
Dispatches batched alert notifications for recon scan diffs and findings.
Features:
  - Discord webhooks and Telegram Bot API support.
  - One batched summary per scan, truncated to Discord and Telegram character/field limits.
  - HTTP 429 backoff retry loop with exponential backoff.
  - No alerts for the initial baseline scan (suppressed cleanly).
  - Fingerprint alerts: only status_code, title, and technologies changes trigger alerts.
    (body_hash and content_length changes are low-priority and never trigger alerts).
  - Minimum-priority filter for vulnerability findings.
  - Mandatory secrets redaction on all outbound alert payloads.
  - Failures are logged but NEVER fail the scan.
"""

import asyncio
import json
import logging
import os
import aiohttp
from typing import Any, Dict, List, Optional
from app.core.redaction import redact_text

logger = logging.getLogger("reconforge.notifier")

SEVERITY_LEVELS = {
    "info": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


def _is_severity_sufficient(severity: str, min_priority: str) -> bool:
    sev_val = SEVERITY_LEVELS.get(severity.lower(), 1)
    min_val = SEVERITY_LEVELS.get(min_priority.lower(), 1)
    return sev_val >= min_val


def get_alert_config(project: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Resolves alert configuration from project document or environment."""
    project_alerts = (project or {}).get("alerts") or {}

    enabled = project_alerts.get("enabled")
    if enabled is None:
        enabled = os.getenv("ALERTS_ENABLED", "false").lower() in ("true", "1", "yes")

    discord_url = project_alerts.get("discord_webhook_url") or os.getenv("DISCORD_WEBHOOK_URL", "")
    telegram_token = project_alerts.get("telegram_bot_token") or os.getenv("TELEGRAM_BOT_TOKEN", "")
    telegram_chat = project_alerts.get("telegram_chat_id") or os.getenv("TELEGRAM_CHAT_ID", "")
    min_priority = project_alerts.get("min_priority") or os.getenv("ALERTS_MIN_PRIORITY", "medium")

    events = project_alerts.get("events") or {
        "new_subdomains": True,
        "new_live_hosts": True,
        "new_ports": True,
        "new_findings": True,
        "scan_completed": True,
    }

    return {
        "enabled": enabled,
        "discord_webhook_url": discord_url.strip(),
        "telegram_bot_token": telegram_token.strip(),
        "telegram_chat_id": telegram_chat.strip(),
        "min_priority": min_priority.lower(),
        "events": events,
    }


async def _send_discord(webhook_url: str, title: str, description: str, fields: List[Dict[str, Any]], color: int = 0x3B82F6):
    """
    Sends a rich embed message to a Discord webhook with 429 backoff and truncation limits.
    Discord Embed limits:
      - Title: <= 256 chars
      - Description: <= 2000 chars
      - Fields: <= 25 fields
      - Field name: <= 256 chars, value: <= 1024 chars
    """
    if not webhook_url:
        return

    safe_title = redact_text(title)[:250]
    safe_desc = redact_text(description)[:2000]
    safe_fields = []
    for f in fields[:25]:
        safe_fields.append({
            "name": redact_text(str(f.get("name", "")))[:250],
            "value": redact_text(str(f.get("value", "")))[:1000],
            "inline": bool(f.get("inline", False))
        })

    payload = {
        "embeds": [{
            "title": safe_title,
            "description": safe_desc,
            "color": color,
            "fields": safe_fields,
            "footer": {"text": "ReconForge Continuous Monitoring"}
        }]
    }

    max_attempts = 3
    for attempt in range(max_attempts):
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(webhook_url, json=payload, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                    if resp.status in (200, 204):
                        return
                    elif resp.status == 429:
                        retry_after = 1.0 * (attempt + 1)
                        try:
                            h_val = resp.headers.get("Retry-After")
                            if h_val:
                                retry_after = max(0.5, float(h_val))
                        except Exception:
                            pass
                        logger.warning(f"[notifier] Discord 429 rate limit hit. Backing off {retry_after}s (attempt {attempt + 1}/{max_attempts})...")
                        await asyncio.sleep(retry_after)
                        continue
                    else:
                        logger.warning(f"[notifier] Discord returned HTTP {resp.status}")
                        return
        except Exception as exc:
            logger.warning(f"[notifier] Discord notification failed (attempt {attempt + 1}/{max_attempts}): {exc}")
            if attempt < max_attempts - 1:
                await asyncio.sleep(1.0 * (attempt + 1))


async def _send_telegram(bot_token: str, chat_id: str, text: str):
    """
    Sends a message to Telegram using Bot API with 429 backoff and 4000 char truncation.
    """
    if not bot_token or not chat_id:
        return

    safe_text = redact_text(text)[:4000]
    api_url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
    payload = {
        "chat_id": chat_id,
        "text": safe_text,
        "parse_mode": "HTML",
        "disable_web_page_preview": True,
    }

    max_attempts = 3
    for attempt in range(max_attempts):
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(api_url, json=payload, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                    if resp.status == 200:
                        return
                    elif resp.status == 429:
                        retry_after = 1.0 * (attempt + 1)
                        try:
                            resp_json = await resp.json()
                            params = resp_json.get("parameters") or {}
                            if "retry_after" in params:
                                retry_after = max(0.5, float(params["retry_after"]))
                        except Exception:
                            pass
                        logger.warning(f"[notifier] Telegram 429 rate limit hit. Backing off {retry_after}s (attempt {attempt + 1}/{max_attempts})...")
                        await asyncio.sleep(retry_after)
                        continue
                    else:
                        logger.warning(f"[notifier] Telegram returned HTTP {resp.status}")
                        return
        except Exception as exc:
            logger.warning(f"[notifier] Telegram notification failed (attempt {attempt + 1}/{max_attempts}): {exc}")
            if attempt < max_attempts - 1:
                await asyncio.sleep(1.0 * (attempt + 1))


async def dispatch_scan_diff_alerts(
    project_name: Any,
    diff_doc: Dict[str, Any],
    project: Optional[Dict[str, Any]] = None
):
    """
    Evaluates scan diff results against configured alert rules and sends notifications
    to Discord and/or Telegram without leaking any credentials or secrets.
    
    Guards:
      1. Initial baseline scan: suppressed cleanly with no alert.
      2. Fingerprint alerts: only status_code, title, technologies trigger alerts.
      3. Batched summary per scan.
      4. Never raises exceptions (failures logged only).
    """
    try:
        if isinstance(project_name, dict) and project is None:
            project = project_name
            project_name = project.get("name", "Unknown Project")
        elif not project:
            project = {"name": str(project_name)}

        config = get_alert_config(project)
        if not config["enabled"]:
            return

        summary = diff_doc.get("summary", {})
        # Suppress alerts for initial baseline scan
        if summary.get("is_initial_scan") or not diff_doc.get("previous_job_id"):
            logger.info(f"[notifier] Initial baseline scan for project '{project_name}'. Suppressing alert dispatch.")
            return

        diff = diff_doc.get("diff", {})
        events_cfg = config.get("events", {})
        min_priority = config.get("min_priority", "medium")

        new_subs = diff.get("new_subdomains", [])
        stale_subs = diff.get("stale_subdomains", [])
        new_live = diff.get("new_live_hosts", [])
        is_rebaseline = bool(summary.get("is_liveness_rebaseline") or diff_doc.get("is_liveness_rebaseline"))
        if is_rebaseline:
            logger.info("[notifier] Scan was a liveness re-baseline. Suppressing 'new_live_hosts' alert dispatch.")
            new_live = []
        new_ports = diff.get("new_ports", [])
        closed_ports = diff.get("closed_ports", [])
        
        # Filter changed_hosts: ONLY status_code, title, technologies trigger alerts!
        # On a liveness-rebaseline scan, also suppress changed_hosts alerts caused by fingerprint fields that did not exist in v1 (body_hash, favicon, tech, tls)
        raw_changed_hosts = diff.get("changed_hosts", [])
        alert_changed_hosts = []
        v1_nonexistent_alert_fields = {"body_hash", "favicon", "favicon_hash", "tech", "technologies", "tls", "tls_info"}
        for ch in raw_changed_hosts:
            high_pri_changes = [
                c for c in ch.get("changes", [])
                if (c.get("priority") == "high" or c.get("field") in ("status_code", "title", "technologies", "tech"))
                and not (is_rebaseline and c.get("field") in v1_nonexistent_alert_fields)
            ]
            if high_pri_changes:
                alert_changed_hosts.append({
                    **ch,
                    "changes": high_pri_changes
                })

        new_findings = [
            f for f in diff.get("new_findings", [])
            if _is_severity_sufficient(f.get("severity", "medium"), min_priority)
        ]

        # Phase 4: Alert only for 200, 401, 403 content paths or API specs
        raw_content_paths = diff.get("new_content_paths", [])
        alert_content_paths = []
        for cp in raw_content_paths:
            if isinstance(cp, dict):
                sc = cp.get("status_code")
                if sc in (200, 401, 403):
                    alert_content_paths.append(cp)
            elif isinstance(cp, str):
                alert_content_paths.append({"url": cp, "status_code": 200})

        new_api_specs = diff.get("new_api_specs", [])

        has_diffs = bool(
            new_subs
            or stale_subs
            or new_live
            or new_ports
            or closed_ports
            or alert_changed_hosts
            or new_findings
            or alert_content_paths
            or new_api_specs
        )

        if not has_diffs and not events_cfg.get("scan_completed", True):
            return

        # Build one batched summary message
        fields = []
        lines = [f"<b>ReconForge Scan Completed: {project_name}</b>\n"]

        if events_cfg.get("new_subdomains", True) and new_subs:
            sample = ", ".join(new_subs[:5])
            if len(new_subs) > 5:
                sample += f" (+{len(new_subs) - 5} more)"
            fields.append({"name": f"New Subdomains ({len(new_subs)})", "value": sample, "inline": False})
            lines.append(f"• <b>New Subdomains ({len(new_subs)})</b>: {sample}")

        if stale_subs:
            sample_stale = ", ".join(stale_subs[:5])
            if len(stale_subs) > 5:
                sample_stale += f" (+{len(stale_subs) - 5} more)"
            fields.append({"name": f"Stale Subdomains ({len(stale_subs)})", "value": sample_stale, "inline": False})
            lines.append(f"• <b>Stale Subdomains ({len(stale_subs)})</b>: {sample_stale}")

        if events_cfg.get("new_live_hosts", True) and new_live:
            sample_live = ", ".join(new_live[:5])
            if len(new_live) > 5:
                sample_live += f" (+{len(new_live) - 5} more)"
            fields.append({"name": f"New Live Hosts ({len(new_live)})", "value": sample_live, "inline": False})
            lines.append(f"• <b>New Live Hosts ({len(new_live)})</b>: {sample_live}")

        if events_cfg.get("new_ports", True) and new_ports:
            port_samples = [f"{p['domain']}:{p['port']}" for p in new_ports[:5]]
            val = ", ".join(port_samples)
            if len(new_ports) > 5:
                val += f" (+{len(new_ports) - 5} more)"
            fields.append({"name": f"New Open Ports ({len(new_ports)})", "value": val, "inline": False})
            lines.append(f"• <b>New Open Ports ({len(new_ports)})</b>: {val}")

        if closed_ports:
            closed_samples = [f"{p['domain']}:{p['port']}" for p in closed_ports[:5]]
            val_c = ", ".join(closed_samples)
            if len(closed_ports) > 5:
                val_c += f" (+{len(closed_ports) - 5} more)"
            fields.append({"name": f"Closed Ports ({len(closed_ports)})", "value": val_c, "inline": False})
            lines.append(f"• <b>Closed Ports ({len(closed_ports)})</b>: {val_c}")

        if alert_changed_hosts:
            ch_samples = [f"{ch['domain']} ({len(ch['changes'])} alertable changes)" for ch in alert_changed_hosts[:4]]
            val_ch = ", ".join(ch_samples)
            fields.append({"name": f"Changed Host Responses ({len(alert_changed_hosts)})", "value": val_ch, "inline": False})
            lines.append(f"• <b>Changed Host Responses ({len(alert_changed_hosts)})</b>: {val_ch}")

        if events_cfg.get("new_findings", True) and new_findings:
            f_samples = [f"[{f.get('severity', '').upper()}] {f.get('matched_url', '')}" for f in new_findings[:4]]
            val_f = "\n".join(f_samples)
            if len(new_findings) > 4:
                val_f += f"\n(+{len(new_findings) - 4} more)"
            fields.append({"name": f"Vulnerability Findings ({len(new_findings)})", "value": val_f, "inline": False})
            lines.append(f"\n<b>Vulnerability Findings ({len(new_findings)}):</b>\n{val_f}")

        if events_cfg.get("new_content_paths", True) and alert_content_paths:
            cp_samples = [f"[{cp.get('status_code', 200)}] {cp.get('url', cp.get('value', ''))}" for cp in alert_content_paths[:5]]
            val_cp = "\n".join(cp_samples)
            if len(alert_content_paths) > 5:
                val_cp += f"\n(+{len(alert_content_paths) - 5} more)"
            fields.append({"name": f"New Content Paths ({len(alert_content_paths)})", "value": val_cp, "inline": False})
            lines.append(f"\n<b>New Content Paths ({len(alert_content_paths)}):</b>\n{val_cp}")

        if events_cfg.get("new_api_specs", True) and new_api_specs:
            spec_samples = [f"{s.get('url', s.get('value', ''))} ({s.get('endpoints_count', 0)} endpoints)" for s in new_api_specs[:4]]
            val_spec = ", ".join(spec_samples)
            if len(new_api_specs) > 4:
                val_spec += f" (+{len(new_api_specs) - 4} more)"
            fields.append({"name": f"New API Specs ({len(new_api_specs)})", "value": val_spec, "inline": False})
            lines.append(f"• <b>New API Specs ({len(new_api_specs)})</b>: {val_spec}")

        if not fields:
            fields.append({"name": "Status", "value": "Scan finished with no actionable changes from previous scan.", "inline": False})
            lines.append("No actionable changes detected from previous scan.")

        title = f"ReconForge Diff Alert: {project_name}"
        desc = f"Scan {str(diff_doc.get('scan_id', ''))[:8]} completed."
        embed_color = 0xEF4444 if new_findings else (0x10B981 if not has_diffs else 0x3B82F6)

        # 1. Send Discord
        if config["discord_webhook_url"]:
            await _send_discord(
                webhook_url=config["discord_webhook_url"],
                title=title,
                description=desc,
                fields=fields,
                color=embed_color,
            )

        # 2. Send Telegram
        if config["telegram_bot_token"] and config["telegram_chat_id"]:
            telegram_text = "\n".join(lines)
            await _send_telegram(
                bot_token=config["telegram_bot_token"],
                chat_id=config["telegram_chat_id"],
                text=telegram_text,
            )
    except Exception as exc:
        logger.error(f"[notifier] Error in dispatch_scan_diff_alerts (non-fatal): {exc}", exc_info=True)
