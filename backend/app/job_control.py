import asyncio
import contextvars
import logging
from collections import defaultdict
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
