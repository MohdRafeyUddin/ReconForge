import asyncio
import contextvars
import logging
import os
import platform
import signal
import subprocess
from collections import defaultdict
from typing import Optional
from bson import ObjectId

logger = logging.getLogger("reconforge.job_control")

# Context var to track active job ID in async tasks
current_job_id = contextvars.ContextVar("current_job_id", default=None)

# Registry of active subprocesses: job_id -> list of subprocess.Popen
active_processes = defaultdict(list)

def register_process(proc):
    jid = current_job_id.get()
    if jid:
        active_processes[jid].append(proc)
        logger.info(f"Registered process {proc.pid} for job {jid}")

def unregister_process(proc):
    jid = current_job_id.get()
    if jid and jid in active_processes:
        try:
            active_processes[jid].remove(proc)
            logger.info(f"Unregistered process {proc.pid} for job {jid}")
        except ValueError:
            pass


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
            # Loop and wait
            await asyncio.sleep(1)
            continue
            
        break
