#!/usr/bin/env python3
"""Local-only backup for ReconForge Mongo data and stored artifacts.

Usage (from the backend directory, with its venv active):
    python scripts/backup_local.py
    python scripts/backup_local.py --keep 5 --skip-storage

Creates ``backups/reconforge_<UTC timestamp>/`` containing:
  - one newline-delimited extended-JSON file per Mongo collection
  - storage.tar.gz with backend/storage (response bodies, JS, screenshots)
  - screenshots.tar.gz with backend/screenshots (if present)
  - manifest.json with collection counts and paths

The backup contains raw recon data and may include sensitive response bodies.
Keep the backups directory local and out of git.
"""

import argparse
import json
import os
import shutil
import tarfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

from bson import json_util
from pymongo import MongoClient


REPO_ROOT = Path(__file__).resolve().parents[2]
BACKEND_ROOT = REPO_ROOT / "backend"
DEFAULT_BACKUP_ROOT = REPO_ROOT / "backups"


def _dump_collection(db, name: str, target: Path) -> int:
    count = 0
    with target.open("w", encoding="utf-8") as handle:
        for doc in db[name].find({}):
            handle.write(json_util.dumps(doc, json_options=json_util.CANONICAL_JSON_OPTIONS))
            handle.write("\n")
            count += 1
    return count


def _archive_directory(source: Path, target: Path) -> bool:
    if not source.is_dir():
        return False
    with tarfile.open(target, "w:gz") as archive:
        archive.add(source, arcname=source.name)
    return True


def _prune_backups(root: Path, keep: int) -> List[str]:
    if keep <= 0:
        return []
    candidates = sorted(
        (path for path in root.glob("reconforge_*") if path.is_dir()),
        key=lambda path: path.name,
        reverse=True,
    )
    removed: List[str] = []
    for old in candidates[keep:]:
        shutil.rmtree(old, ignore_errors=True)
        removed.append(old.name)
    return removed


def main() -> int:
    parser = argparse.ArgumentParser(description="Back up ReconForge locally")
    parser.add_argument("--mongo", default=os.getenv("MONGODB_URL", "mongodb://127.0.0.1:27017"))
    parser.add_argument("--db", default=os.getenv("DATABASE_NAME", "reconforge"))
    parser.add_argument("--output", default=str(DEFAULT_BACKUP_ROOT))
    parser.add_argument("--keep", type=int, default=7, help="Keep the newest N backups (0 = keep all)")
    parser.add_argument("--skip-storage", action="store_true", help="Skip response/JS/screenshot archives")
    args = parser.parse_args()

    stamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    backup_root = Path(args.output).expanduser().resolve()
    target = backup_root / f"reconforge_{stamp}"
    target.mkdir(parents=True, exist_ok=False)

    manifest: Dict[str, Any] = {
        "created_at": datetime.now(timezone.utc).isoformat(),
        "mongodb": args.mongo,
        "database": args.db,
        "collections": {},
        "archives": [],
    }

    client = MongoClient(args.mongo, serverSelectionTimeoutMS=5000)
    try:
        client.admin.command("ping")
        db = client[args.db]
        for name in sorted(db.list_collection_names()):
            count = _dump_collection(db, name, target / f"{name}.jsonl")
            manifest["collections"][name] = count
    finally:
        client.close()

    if not args.skip_storage:
        storage_archive = target / "storage.tar.gz"
        if _archive_directory(BACKEND_ROOT / "storage", storage_archive):
            manifest["archives"].append(str(storage_archive.name))
        screenshots_archive = target / "screenshots.tar.gz"
        if _archive_directory(BACKEND_ROOT / "screenshots", screenshots_archive):
            manifest["archives"].append(str(screenshots_archive.name))

    with (target / "manifest.json").open("w", encoding="utf-8") as handle:
        json.dump(manifest, handle, indent=2, sort_keys=True)

    removed = _prune_backups(backup_root, args.keep)
    total_docs = sum(manifest["collections"].values())
    print(f"Backup created: {target}")
    print(f"Collections: {len(manifest['collections'])} | documents: {total_docs}")
    if manifest["archives"]:
        print(f"Archives: {', '.join(manifest['archives'])}")
    if removed:
        print(f"Pruned older backups: {', '.join(removed)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
