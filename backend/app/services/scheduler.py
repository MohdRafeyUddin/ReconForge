"""
In-Process Asyncio Scan Scheduler
=================================
Manages recurring scans entirely within the FastAPI process.
Features:
  - Interval configured per project in MongoDB (schedule.interval_hours).
  - Resumes on backend startup; stops cleanly on shutdown.
  - Startup recovery: marks jobs stuck in "running" without live process as "interrupted".
  - Single-instance lock in MongoDB (`system_locks`) guarding against double scheduler start.
  - Heartbeat and max-age check: recovers hanging jobs so scheduler is never blocked.
  - Strict concurrency control: prevents overlapping scans for the same project.
  - Respects job cancellation via job_control.py.
  - No external dependencies (no Celery, Redis, Cron, or Task Scheduler).
"""

import asyncio
import logging
import uuid
from datetime import datetime, timedelta
from typing import Any, Optional

from app.core.scan_options import FULL_SCAN_MODE
from bson import ObjectId

from app.database import get_database

logger = logging.getLogger("reconforge.scheduler")


async def recover_stuck_jobs(db: Any) -> int:
    """
    Startup recovery: finds all jobs left in 'running' or 'pending' state
    from previous crashed/stopped process instances and marks them 'interrupted'.
    This ensures the scheduler is never blocked by orphaned jobs.
    """
    if db is None:
        return 0

    recovered_count = 0
    now = datetime.utcnow()

    try:
        # Find all running or pending jobs
        cursor = db.jobs.find({"status": {"$in": ["running", "pending"]}})
        stuck_jobs = await cursor.to_list(1000)

        for job in stuck_jobs:
            jid = str(job["_id"])
            interrupted_log = (
                "[!] Startup Recovery: Job marked as 'interrupted' because the backend "
                "restarted or no live process exists for this job."
            )
            await db.jobs.update_one(
                {"_id": job["_id"]},
                {
                    "$set": {
                        "status": "interrupted",
                        "finished_at": now,
                    },
                    "$push": {"logs": interrupted_log}
                }
            )
            recovered_count += 1
            logger.info(f"[recovery] Marked orphaned job {jid} as 'interrupted'.")

        if recovered_count > 0:
            logger.info(f"[✓] Startup recovery completed: {recovered_count} stuck jobs marked as interrupted.")
    except Exception as exc:
        logger.error(f"[recovery] Error during startup job recovery: {exc}")

    return recovered_count


class AsyncioScanScheduler:
    def __init__(self):
        self.instance_id: str = str(uuid.uuid4())
        self._task: Optional[asyncio.Task] = None
        self._running: bool = False
        self._check_interval_seconds: int = 60
        self._has_lock: bool = False

    def start(self):
        """Starts the in-process scheduler loop in the background with double-start guard."""
        if self._running:
            logger.warning("[scheduler] Scheduler start() called but already running. Double start guarded.")
            return
        self._running = True
        self._task = asyncio.create_task(self._loop(), name="reconforge_scheduler_loop")
        logger.info(f"[scheduler] In-process recurring scan scheduler started (instance: {self.instance_id}).")

    async def stop(self):
        """Stops the scheduler cleanly and releases any MongoDB leader lock."""
        self._running = False
        if self._task and not self._task.done():
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass

        # Release distributed lock
        db = get_database()
        await self._release_lock(db)
        logger.info("[scheduler] In-process scheduler stopped.")

    async def _acquire_or_renew_lock(self, db: Any) -> bool:
        """
        Attempts to acquire or renew the single-instance scheduler lock in MongoDB.
        Guards against multiple FastAPI workers/instances running overlapping schedulers.
        """
        if db is None or getattr(db, "system_locks", None) is None:
            return True

        now = datetime.utcnow()
        lease_seconds = max(90, self._check_interval_seconds * 2 + 10)
        lease_expiry = now + timedelta(seconds=lease_seconds)

        try:
            lock = await db.system_locks.find_one({"_id": "scheduler_leader"})
            if not lock:
                try:
                    await db.system_locks.insert_one({
                        "_id": "scheduler_leader",
                        "locked_by": self.instance_id,
                        "locked_at": now,
                        "expires_at": lease_expiry,
                    })
                    self._has_lock = True
                    return True
                except Exception:
                    # Insert collision, fall through to re-check
                    pass

            lock = await db.system_locks.find_one({"_id": "scheduler_leader"})
            if lock:
                locked_by = lock.get("locked_by")
                expires_at = lock.get("expires_at") or datetime.min
                if locked_by == self.instance_id or expires_at <= now:
                    await db.system_locks.update_one(
                        {"_id": "scheduler_leader"},
                        {"$set": {
                            "locked_by": self.instance_id,
                            "locked_at": now,
                            "expires_at": lease_expiry,
                        }}
                    )
                    self._has_lock = True
                    return True
                else:
                    self._has_lock = False
                    logger.debug(
                        f"[scheduler] Another instance ({locked_by}) holds scheduler lock. "
                        f"Instance {self.instance_id} in standby."
                    )
                    return False

            return True
        except Exception as exc:
            logger.debug(f"[scheduler] Single-instance lock error: {exc}")
            return True

    async def _release_lock(self, db: Any):
        """Releases the leader lock on shutdown."""
        if db is not None and getattr(db, "system_locks", None) is not None:
            try:
                await db.system_locks.delete_one({
                    "_id": "scheduler_leader",
                    "locked_by": self.instance_id
                })
                logger.info("[scheduler] Leader scheduler lock released in MongoDB.")
            except Exception as exc:
                logger.debug(f"[scheduler] Error releasing lock: {exc}")
        self._has_lock = False

    async def _loop(self):
        """Periodic background evaluation loop."""
        while self._running:
            try:
                db = get_database()
                if db is not None:
                    has_lock = await self._acquire_or_renew_lock(db)
                    if has_lock:
                        await self.check_due_schedules()
            except Exception as e:
                logger.error(f"[scheduler] Error in scheduler loop iteration: {e}", exc_info=True)

            try:
                await asyncio.sleep(self._check_interval_seconds)
            except asyncio.CancelledError:
                break

    async def check_due_schedules(self):
        """Checks MongoDB for projects with scheduled scans that are due."""
        db = get_database()
        if db is None:
            return

        now = datetime.utcnow()

        try:
            # Query projects where schedule is enabled
            cursor = db.projects.find({"schedule.enabled": True})
            projects = await cursor.to_list(500)
        except Exception as e:
            logger.debug(f"[scheduler] Failed to query projects: {e}")
            return

        for project in projects:
            try:
                project_id = str(project["_id"])
                schedule = project.get("schedule") or {}
                if not schedule.get("enabled"):
                    continue

                interval_hours = max(1, int(schedule.get("interval_hours") or 24))
                next_run = schedule.get("next_run")
                # Legacy schedule.scan_mode is intentionally ignored; every
                # scheduled run uses the single full pipeline.
                scan_mode = FULL_SCAN_MODE
                seed_domains = project.get("seed_domains", [])

                if not seed_domains:
                    continue

                is_due = False
                if not next_run:
                    is_due = True
                elif isinstance(next_run, datetime):
                    is_due = (now >= next_run)
                elif isinstance(next_run, str):
                    try:
                        parsed_dt = datetime.fromisoformat(next_run.replace("Z", "+00:00")).replace(tzinfo=None)
                        is_due = (now >= parsed_dt)
                    except Exception:
                        is_due = True

                if not is_due:
                    continue

                # ==============================================================
                # CONCURRENCY GUARD & HEARTBEAT / MAX-AGE CHECK
                # ==============================================================
                running_job = await db.jobs.find_one({
                    "project_id": project_id,
                    "status": "running"
                })
                if running_job:
                    jid = str(running_job["_id"])
                    
                    started_at = running_job.get("started_at") or running_job.get("created_at") or now
                    heartbeat = running_job.get("heartbeat") or started_at

                    # Heartbeat (> 30 min) or max-age (> 2 hours) check
                    is_stuck = False
                    if (now - heartbeat).total_seconds() > 1800:
                        # No heartbeat for > 30 minutes
                        is_stuck = True
                    elif (now - started_at).total_seconds() > 7200:
                        # Max age > 2 hours
                        is_stuck = True

                    if is_stuck:
                        logger.warning(
                            f"[scheduler] Job {jid} for project {project_id} appears stuck "
                            f"(alive={alive}, last heartbeat={heartbeat}). Marking 'interrupted'."
                        )
                        stuck_msg = "[!] Job marked as interrupted by scheduler heartbeat/max-age monitor."
                        await db.jobs.update_one(
                            {"_id": running_job["_id"]},
                            {
                                "$set": {"status": "interrupted", "finished_at": now},
                                "$push": {"logs": stuck_msg}
                            }
                        )
                    else:
                        logger.info(
                            f"[scheduler] Project '{project.get('name')}' ({project_id}) has an active running job "
                            f"({jid}). Skipping scheduled run to prevent overlap."
                        )
                        continue

                # Schedule is due and no overlapping job is running
                next_schedule_time = now + timedelta(hours=interval_hours)
                await db.projects.update_one(
                    {"_id": project["_id"]},
                    {"$set": {
                        "schedule.last_run": now,
                        "schedule.next_run": next_schedule_time,
                    }}
                )

                # Create job entry in MongoDB
                job_doc = {
                    "project_id": project_id,
                    "provider_name": "Unified Discovery",
                    "scan_mode": scan_mode,
                    "job_kind": "full",
                    "status": "pending",
                    "phase_durations": [],
                    "created_at": now,
                    "heartbeat": now,
                    "logs": ["[+] Scheduled recurring full scan triggered."],
                }
                res = await db.jobs.insert_one(job_doc)
                job_id = str(res.inserted_id)

                logger.info(
                    f"[scheduler] Triggered scheduled recurring scan {job_id} for "
                    f"project '{project.get('name')}' ({project_id}). Next run: {next_schedule_time}."
                )

                # Import and run discovery job asynchronously in background
                from app.routers.jobs import run_discovery_job
                asyncio.create_task(
                    run_discovery_job(job_id, project_id, "Unified Discovery", seed_domains)
                )

            except Exception as proj_err:
                logger.error(f"[scheduler] Error evaluating project {project.get('_id')}: {proj_err}")


# Global scheduler instance
scheduler = AsyncioScanScheduler()
