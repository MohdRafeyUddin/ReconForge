#!/usr/bin/env python3
"""
Standalone CLI Script: Backfill & Deduplicate Assets
====================================================
Usage:
    python scripts/backfill_assets.py
"""

import asyncio
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app.database import connect_to_mongo, close_mongo_connection, get_database
from app.services.migration import run_asset_backfill_migration


async def main():
    print("[*] Connecting to database...")
    await connect_to_mongo()
    db = get_database()
    if db is None:
        print("[-] Database connection failed.")
        sys.exit(1)

    print("[*] Running asset backfill migration...")
    results = await run_asset_backfill_migration(db)
    print(f"[✓] Migration complete! Summary: {results}")
    await close_mongo_connection()


if __name__ == "__main__":
    asyncio.run(main())
