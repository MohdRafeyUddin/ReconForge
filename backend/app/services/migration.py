"""
Asset Migration & Backfill Service
===================================
Idempotent backfill migration for existing assets:
  1. Sets canonical `value` from domain/url/finding identifier for legacy assets.
  2. Sets `first_seen` and `last_seen` from `created_at` or `updated_at`.
  3. Merges duplicate assets keyed on (project_id, type, value) into a single document,
     preserving the earliest `first_seen`, latest `last_seen`, merged ports, and merged sources.
  4. Enforces a UNIQUE compound index on `(project_id, type, value)`.
"""

import logging
from collections import defaultdict
from datetime import datetime
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

logger = logging.getLogger("reconforge.migration")


def compute_canonical_value(doc: Dict[str, Any]) -> str:
    """Computes a stable canonical value for any asset document."""
    existing_val = doc.get("value")
    if existing_val and str(existing_val).strip():
        return str(existing_val).strip()

    asset_type = doc.get("type", "subdomain")
    meta = doc.get("metadata") or {}

    if asset_type == "finding":
        template_id = (
            meta.get("template_id")
            or meta.get("templateID")
            or meta.get("source")
            or doc.get("discovered_by")
            or "finding"
        )
        matched_at = meta.get("matched_url") or meta.get("url") or doc.get("domain") or ""
        host = meta.get("host") or ""
        if not host and matched_at:
            try:
                host = urlparse(matched_at).netloc or ""
            except Exception:
                host = ""
        return f"{template_id}:{matched_at}:{host}"

    if asset_type in ("historical_url", "uro_url", "gf_url", "js_file", "screenshot"):
        url_val = meta.get("url") or meta.get("matched_url") or doc.get("domain") or ""
        if url_val:
            return str(url_val).strip()

    # Default to domain
    return str(doc.get("domain") or "").strip()


async def run_asset_backfill_migration(db: Any) -> Dict[str, Any]:
    """
    Executes idempotent backfill and duplicate merger across all assets in MongoDB.
    Enforces unique index (project_id, type, value).
    """
    if db is None:
        logger.warning("[migration] Database unavailable. Skipping backfill.")
        return {"status": "skipped", "reason": "db_unavailable"}

    logger.info("[migration] Starting idempotent asset backfill and deduplication...")
    stats = {
        "scanned": 0,
        "values_backfilled": 0,
        "timestamps_backfilled": 0,
        "duplicates_merged": 0,
        "index_created": False,
    }

    try:
        # 1. Fetch all assets
        cursor = db.assets.find({})
        all_assets = await cursor.to_list(500000)
    except Exception as exc:
        logger.error(f"[migration] Failed to query assets: {exc}")
        return {"status": "error", "error": str(exc)}

    stats["scanned"] = len(all_assets)
    if not all_assets:
        logger.info("[migration] No assets found. Ensuring unique index...")
        await _ensure_unique_index(db, stats)
        return stats

    # 2. Backfill missing values and timestamps
    grouped_by_key = defaultdict(list)

    for doc in all_assets:
        doc_id = doc["_id"]
        pid = str(doc.get("project_id", ""))
        a_type = str(doc.get("type", "subdomain"))
        canonical_val = compute_canonical_value(doc)

        update_fields = {}
        if doc.get("value") != canonical_val:
            update_fields["value"] = canonical_val
            doc["value"] = canonical_val
            stats["values_backfilled"] += 1

        created = doc.get("created_at") or datetime.utcnow()
        if "first_seen" not in doc or doc["first_seen"] is None:
            update_fields["first_seen"] = created
            doc["first_seen"] = created
            stats["timestamps_backfilled"] += 1

        if "last_seen" not in doc or doc["last_seen"] is None:
            updated = doc.get("updated_at") or created
            update_fields["last_seen"] = updated
            doc["last_seen"] = updated
            stats["timestamps_backfilled"] += 1

        if update_fields:
            try:
                await db.assets.update_one({"_id": doc_id}, {"$set": update_fields})
            except Exception as e:
                logger.debug(f"[migration] Failed to update doc {doc_id}: {e}")

        group_key = (pid, a_type, canonical_val)
        grouped_by_key[group_key].append(doc)

    # 3. Merge duplicate documents sharing the same (project_id, type, value)
    for group_key, docs in grouped_by_key.items():
        if len(docs) <= 1:
            continue

        # Multiple docs with identical (project_id, type, value)
        primary = docs[0]
        duplicates = docs[1:]

        # Merge open_ports, sources, metadata
        merged_ports = set(primary.get("open_ports") or [])
        merged_sources = set(primary.get("sources") or [])
        primary_meta = primary.get("metadata") or {}

        earliest_first_seen = primary.get("first_seen") or datetime.max
        latest_last_seen = primary.get("last_seen") or datetime.min

        for dup in duplicates:
            merged_ports.update(dup.get("open_ports") or [])
            merged_sources.update(dup.get("sources") or [])
            dup_meta = dup.get("metadata") or {}
            primary_meta.update(dup_meta)

            fs = dup.get("first_seen")
            if fs and fs < earliest_first_seen:
                earliest_first_seen = fs

            ls = dup.get("last_seen")
            if ls and ls > latest_last_seen:
                latest_last_seen = ls

        merged_update = {
            "open_ports": sorted(list(merged_ports)),
            "sources": sorted(list(merged_sources)),
            "metadata": primary_meta,
            "first_seen": earliest_first_seen,
            "last_seen": latest_last_seen,
            "updated_at": datetime.utcnow(),
        }

        try:
            # Update primary doc
            await db.assets.update_one({"_id": primary["_id"]}, {"$set": merged_update})
            # Remove redundant duplicates
            for dup in duplicates:
                await db.assets.delete_one({"_id": dup["_id"]})
                stats["duplicates_merged"] += 1
        except Exception as dup_err:
            logger.error(f"[migration] Error merging duplicate group {group_key}: {dup_err}")

    # 4. Enforce UNIQUE compound index on (project_id, type, value)
    await _ensure_unique_index(db, stats)

    logger.info(
        f"[✓] Asset backfill migration finished: {stats['scanned']} scanned, "
        f"{stats['values_backfilled']} values backfilled, "
        f"{stats['duplicates_merged']} duplicates merged, "
        f"unique index created: {stats['index_created']}."
    )
    return stats


async def _ensure_unique_index(db: Any, stats: Dict[str, Any]):
    """Creates the unique index on assets(project_id, type, value), dropping old non-unique index if needed."""
    try:
        # Drop previous non-unique index if present
        try:
            await db.assets.drop_index("project_id_1_type_1_value_1")
        except Exception:
            pass

        # Create unique compound index
        await db.assets.create_index(
            [("project_id", 1), ("type", 1), ("value", 1)],
            unique=True,
            name="project_id_1_type_1_value_1_unique"
        )
        stats["index_created"] = True
    except Exception as e:
        logger.warning(f"[migration] Could not create unique index: {e}")
