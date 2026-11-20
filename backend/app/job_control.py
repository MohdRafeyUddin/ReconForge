import asyncio
import contextvars
import logging
import os
import platform
import signal
import subprocess
from collections import defaultdict
from typing import Dict, Optional
from bson import ObjectId

logger = logging.getLogger("reconforge.job_control")

# Context var to track active job ID in async tasks
current_job_id = contextvars.ContextVar("current_job_id", default=None)

# Context var identifying the phase that owns newly spawned subprocesses.
current_phase = contextvars.ContextVar("current_phase", default=None)

# Registry of active subprocesses: job_id -> list of subprocess.Popen
active_processes = defaultdict(list)
# Maps id(proc) -> phase label so a phase time cap can kill only its own tree.
active_process_phases: dict = {}
# Registry of the asyncio task currently running each job, so /stop can
# cancel the whole runner instead of only flipping the database status.
active_job_tasks: Dict[str, asyncio.Task] = {}
# Jobs explicitly stopped by the user. Providers consult this before starting
# new work and before registering new subprocesses.
stopped_jobs: set = set()
# Jobs paused by the user, with an event that is set again on resume/stop.
paused_jobs: set = set()
_resume_events: Dict[str, asyncio.Event] = {}


def mark_job_stopped(job_id: str) -> None:
    key = str(job_id)
    stopped_jobs.add(key)
    paused_jobs.discard(key)
    event = _resume_events.pop(key, None)
    if event is not None:
        event.set()


def clear_job_stopped(job_id: str) -> None:
    stopped_jobs.discard(str(job_id))


def mark_job_paused(job_id: str) -> None:
    key = str(job_id)
    if key in stopped_jobs:
        return
    paused_jobs.add(key)
    event = _resume_events.get(key)
    if event is None or event.is_set():
        _resume_events[key] = asyncio.Event()


def resume_job_flag(job_id: str) -> None:
    key = str(job_id)
    paused_jobs.discard(key)
    event = _resume_events.pop(key, None)
    if event is not None:
        event.set()


async def wait_if_paused(job_id: str) -> None:
    """Blocks while a job is paused; wakes on resume or stop."""
    key = str(job_id)
    while key in paused_jobs:
        if key in stopped_jobs:
            break
        event = _resume_events.get(key)
        if event is None:
            await asyncio.sleep(0.5)
        else:
            await event.wait()
    if key in stopped_jobs:
        raise Exception("Job stopped")

def register_process(proc):
    jid = current_job_id.get()
    if jid:
        if str(jid) in stopped_jobs:
            logger.info(f"Refusing to register process {proc.pid}: job {jid} is stopped")
            kill_process_tree(proc)
            return
        active_processes[jid].append(proc)
        active_process_phases[id(proc)] = current_phase.get()
        logger.info(f"Registered process {proc.pid} for job {jid}")

def unregister_process(proc):
    jid = current_job_id.get()
    if jid and jid in active_processes:
        try:
            active_processes[jid].remove(proc)
            logger.info(f"Unregistered process {proc.pid} for job {jid}")
        except ValueError:
            pass
    active_process_phases.pop(id(proc), None)


def kill_phase_processes(phase: Optional[str]) -> int:
    """Hard-kills every registered process owned by ``phase``. Returns the count."""
    if not phase:
        return 0
    killed = 0
    for procs in list(active_processes.values()):
        for proc in list(procs):
            if active_process_phases.get(id(proc)) == phase:
                kill_process_tree(proc)
                killed += 1
    return killed


def kill_process_tree(proc: subprocess.Popen, tool_name: Optional[str] = None) -> None:
    """
    Enforces a hard kill of the whole process tree at deadline.
    On Windows:
      1. taskkill /F /T /PID <pid> to forcefully kill the Windows process and its entire child tree.
      2. If tool_name provided, run wsl -e pkill -9 -f <tool_name> to terminate any orphaned Linux processes.
    On Linux/Unix:
      1. Send SIGKILL to the process group.
      2. If tool_name provided, run pkill -9 -f <tool_name>.
    """
    if proc is None:
        return

    pid = getattr(proc, "pid", None)
    is_windows = platform.system().lower() == "windows"

    if pid:
        if is_windows:
            try:
                subprocess.run(["taskkill", "/F", "/T", "/PID", str(pid)], capture_output=True, timeout=5)
            except Exception as exc:
                logger.debug(f"taskkill failed for pid {pid}: {exc}")
            try:
                if proc.poll() is None:
                    proc.kill()
            except Exception:
                pass
            if tool_name:
                try:
                    subprocess.run(["wsl", "-e", "pkill", "-9", "-f", tool_name], capture_output=True, timeout=5)
                except Exception:
                    pass
        else:
            try:
                pgid = os.getpgid(pid)
                os.killpg(pgid, signal.SIGKILL)
            except Exception:
                try:
                    proc.kill()
                except Exception:
                    pass
            if tool_name:
                try:
                    subprocess.run(["pkill", "-9", "-f", tool_name], capture_output=True, timeout=5)
                except Exception:
                    pass

    try:
        if proc.poll() is None:
            proc.kill()
    except Exception:
        pass

async def check_job_status():
    jid = current_job_id.get()
    if not jid:
        return
    if str(jid) in stopped_jobs:
        raise Exception("Job stopped")
    await wait_if_paused(jid)

    from app.database import get_database
    db = get_database()
    if db is None:
        return

    while True:
        job = await db.jobs.find_one({"_id": ObjectId(jid)})
        if not job:
            break

        status = job.get("status")
        if status == "stopped":
            logger.info(f"Job {jid} is STOPPED. Raising exception.")
            raise Exception("Job stopped")

        if status == "paused":
            await wait_if_paused(jid)
            continue

        break
