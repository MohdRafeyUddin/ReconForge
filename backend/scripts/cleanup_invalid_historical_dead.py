#!/usr/bin/env python3
"""
Standalone CLI Script: Cleanup Invalid historical_dead Assets
=============================================================
Requirement 7: Delete assets of type historical_dead whose value does not
start with http:// or https://.

Usage:
    python scripts/cleanup_invalid_historical_dead.py
"""

import asyncio
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app.database import connect_to_mongo, close_mongo_connection, get_database


async def cleanup_invalid_historical_dead(db=None) -> int:
    """
    Deletes all assets in db.assets with type == 'historical_dead' whose
    'value' does not start with http:// or https:// (case-insensitive).
    Returns the count of deleted assets.
    """
    should_close = False
    if db is None:
        await connect_to_mongo()
        db = get_database()
        should_close = True

    query = {
        "type": "historical_dead",
        "$or": [
            {"value": {"$not": {"$regex": "^https?://", "$options": "i"}}},
            {"value": None},
            {"value": {"$exists": False}},
        ]
    }

    res = await db.assets.delete_many(query)
    deleted_count = res.deleted_count if hasattr(res, "deleted_count") else 0

    if should_close:
        await close_mongo_connection()

    return deleted_count


async def main():
    print("[*] Connecting to database for historical_dead cleanup...")
    deleted = await cleanup_invalid_historical_dead()
    print(f"[✓] Cleanup complete! Purged {deleted} invalid historical_dead assets.")


if __name__ == "__main__":
    asyncio.run(main())

