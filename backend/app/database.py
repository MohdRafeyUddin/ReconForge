import logging
import asyncio
from datetime import datetime
from bson import ObjectId
from motor.motor_asyncio import AsyncIOMotorClient
from app.config import settings

logger = logging.getLogger("reconforge.database")

# In-Memory database storage simulation when MongoDB is offline
class MockCursor:
    def __init__(self, documents):
        self.documents = list(documents)
        self.sort_key = None
        self.sort_direction = 1
        self._skip = 0
        self._limit = None

    def sort(self, key, direction=-1):
        if isinstance(key, list):
            self.sort_key = key[0][0]
            self.sort_direction = key[0][1]
        else:
            self.sort_key = key
            self.sort_direction = direction
        return self

    def skip(self, n):
        self._skip = max(0, int(n))
        return self

    def limit(self, n):
        self._limit = max(0, int(n))
        return self

    async def to_list(self, length=100):
        # Apply sorting if configured
        docs = list(self.documents)
        if self.sort_key:
            rev = (self.sort_direction == -1)
            # handle nested keys or basic keys
            docs.sort(
                key=lambda x: x.get(self.sort_key, datetime.min) if isinstance(x.get(self.sort_key), datetime) else x.get(self.sort_key, ""), 
                reverse=rev
            )
        if self._skip:
            docs = docs[self._skip:]
        lim = self._limit if self._limit is not None else length
        if lim is not None:
            docs = docs[:lim]
        return docs


class MockCollection:
    def __init__(self, name):
        self.name = name
        self.docs = []

    async def create_index(self, *args, **kwargs):
        pass

    async def drop_index(self, *args, **kwargs):
        pass

    def _get_val(self, doc, path):
        curr = doc
        for part in path.split("."):
            if isinstance(curr, dict):
                curr = curr.get(part)
            else:
                return None
        return curr

    def _set_val(self, doc, path, val):
        parts = path.split(".")
        curr = doc
        for part in parts[:-1]:
            if part not in curr or not isinstance(curr[part], dict):
                curr[part] = {}
            curr = curr[part]
        curr[parts[-1]] = val

    def _match(self, doc, query):
        for k, v in query.items():
            if k == "$or" and isinstance(v, list):
                if not any(self._match(doc, subq) for subq in v):
                    return False
                continue
            val = self._get_val(doc, k)
            if isinstance(v, dict):
                if "$ne" in v:
                    if val == v["$ne"]:
                        return False
                    continue
                if "$in" in v:
                    if val not in v["$in"]:
                        return False
                    continue
                if "$nin" in v:
                    if val in v["$nin"]:
                        return False
                    continue
                if "$gte" in v:
                    if val is None or val < v["$gte"]:
                        return False
                    continue
                if "$lte" in v:
                    if val is None or val > v["$lte"]:
                        return False
                    continue
                if "$gt" in v:
                    if val is None or val <= v["$gt"]:
                        return False
                    continue
                if "$lt" in v:
                    if val is None or val >= v["$lt"]:
                        return False
                    continue
            elif val != v:
                return False
        return True

    async def find_one(self, query, sort=None):
        await asyncio.sleep(0.01)
        # Parse query
        for d in self.docs:
            if self._match(d, query):
                return d
        return None

    def find(self, query=None):
        query = query or {}
        matched = []
        for d in self.docs:
            if self._match(d, query):
                matched.append(d)
        return MockCursor(matched)

    async def insert_one(self, doc):
        await asyncio.sleep(0.01)
        if "_id" not in doc:
            doc["_id"] = ObjectId()
        # Create a copy to prevent mutation issues
        self.docs.append(doc)
        
        class InsertResult:
            inserted_id = doc["_id"]
        return InsertResult()

    async def update_one(self, query, update, upsert=False):
        await asyncio.sleep(0.01)
        doc = await self.find_one(query)
        if not doc:
            if upsert:
                new_doc = {"_id": ObjectId()}
                for qk, qv in query.items():
                    if not qk.startswith("$") and not isinstance(qv, dict):
                        self._set_val(new_doc, qk, qv)
                if "$setOnInsert" in update:
                    for k, v in update["$setOnInsert"].items():
                        self._set_val(new_doc, k, v)
                if "$set" in update:
                    for k, v in update["$set"].items():
                        self._set_val(new_doc, k, v)
                if "$push" in update:
                    for k, v in update["$push"].items():
                        new_doc[k] = [v]
                if "$addToSet" in update:
                    for k, v in update["$addToSet"].items():
                        if isinstance(v, dict) and "$each" in v:
                            new_doc[k] = list(set(v["$each"]))
                        else:
                            new_doc[k] = [v]
                self.docs.append(new_doc)
                class UpsertResult:
                    matched_count = 0
                    modified_count = 0
                    upserted_id = new_doc["_id"]
                return UpsertResult()
            return
            
        if "$set" in update:
            for k, v in update["$set"].items():
                self._set_val(doc, k, v)
        if "$push" in update:
            for k, v in update["$push"].items():
                if k not in doc:
                    doc[k] = []
                doc[k].append(v)
        if "$addToSet" in update:
            for k, v in update["$addToSet"].items():
                if k not in doc or not isinstance(doc[k], list):
                    doc[k] = []
                if isinstance(v, dict) and "$each" in v:
                    for item in v["$each"]:
                        if item not in doc[k]:
                            doc[k].append(item)
                else:
                    if v not in doc[k]:
                        doc[k].append(v)
        if "$inc" in update:
            for k, v in update["$inc"].items():
                cur = self._get_val(doc, k) or 0
                self._set_val(doc, k, cur + v)
        return doc

    async def delete_one(self, query):
        await asyncio.sleep(0.01)
        doc = await self.find_one(query)
        if doc in self.docs:
            self.docs.remove(doc)

    async def delete_many(self, query):
        await asyncio.sleep(0.01)
        to_delete = []
        for d in self.docs:
            if self._match(d, query):
                to_delete.append(d)
        for d in to_delete:
            self.docs.remove(d)

    async def count_documents(self, query):
        await asyncio.sleep(0.01)
        count = 0
        for d in self.docs:
            if self._match(d, query):
                count += 1
        return count

    def aggregate(self, pipeline):
        # We need to simulate the project aggregation pipelines used in assets router:
        # 1. Ports frequency pipeline:
        #    [ {"$match": {"project_id": project_id}}, {"$unwind": "$open_ports"}, {"$group": {"_id": "$open_ports", "count": {"$sum": 1}}}, {"$sort": {"count": -1}} ]
        # 2. Discovery source pipeline:
        #    [ {"$match": {"project_id": project_id}}, {"$group": {"_id": "$discovered_by", "count": {"$sum": 1}}} ]
        
        # Extract project_id match filter
        project_id = None
        for step in pipeline:
            if "$match" in step:
                project_id = step["$match"].get("project_id")
                
        matched_docs = [d for d in self.docs if d.get("project_id") == project_id]
        
        is_ports_pipeline = any("$unwind" in step for step in pipeline)
        
        if is_ports_pipeline:
            # Count frequency of each port
            port_counts = {}
            for doc in matched_docs:
                ports = doc.get("open_ports", [])
                for p in ports:
                    port_counts[p] = port_counts.get(p, 0) + 1
            
            res = [{"_id": port, "count": count} for port, count in port_counts.items()]
            res.sort(key=lambda x: x["count"], reverse=True)
            return MockCursor(res)
        else:
            # Count discovery sources (discovered_by)
            source_counts = {}
            for doc in matched_docs:
                src = doc.get("discovered_by", "Unknown")
                source_counts[src] = source_counts.get(src, 0) + 1
            
            res = [{"_id": src, "count": count} for src, count in source_counts.items()]
            return MockCursor(res)


class MockDb:
    def __init__(self):
        self.users = MockCollection("users")
        self.projects = MockCollection("projects")
        self.assets = MockCollection("assets")
        self.jobs = MockCollection("jobs")
        self.scan_diffs = MockCollection("scan_diffs")
        self.system_locks = MockCollection("system_locks")
        self.scan_runs = MockCollection("scan_runs")
        self.run_assets = MockCollection("run_assets")


class Database:
    client = None
    db = None
    is_mock = False

db_helper = Database()

async def connect_to_mongo():
    logger.info(f"Connecting to MongoDB at {settings.MONGODB_URL}...")
    db_helper.client = AsyncIOMotorClient(
        settings.MONGODB_URL,
        serverSelectionTimeoutMS=2000
    )
    db_helper.db = db_helper.client[settings.DATABASE_NAME]
    try:
        # Test connection
        await db_helper.client.admin.command('ping')
        db_helper.is_mock = False
        logger.info("[✓] Connected to MongoDB database successfully!")
    except Exception as e:
        loud_warning = (
            "\n"
            "********************************************************************************\n"
            " [!] CRITICAL WARNING: MONGODB IS UNAVAILABLE!\n"
            f"     Connection error: {e}\n"
            "     RUNNING ON IN-MEMORY DATABASE (MOCK). ALL DATA WILL BE LOST ON RESTART!\n"
            "********************************************************************************\n"
        )
        logger.warning(loud_warning)
        print(loud_warning, flush=True)
        db_helper.is_mock = True
        db_helper.db = MockDb()
        return

    # Initialize database indexes safely
    try:
        # Initialize unique indexes for users
        await db_helper.db.users.create_index("username", unique=True)
        await db_helper.db.users.create_index("email", unique=True)
        # Initialize compound indexes for assets
        await db_helper.db.assets.create_index([("project_id", 1), ("type", 1), ("domain", 1)])
        
        # Check and resolve any conflicting index on assets (project_id, type, value)
        try:
            info = await db_helper.db.assets.index_information()
            target_key = [("project_id", 1), ("type", 1), ("value", 1)]
            for iname, idata in info.items():
                if idata.get("key") == target_key and iname != "project_id_1_type_1_value_1_unique":
                    try:
                        logger.info(f"Dropping conflicting assets index {iname}...")
                        await db_helper.db.assets.drop_index(iname)
                    except Exception as drop_err:
                        logger.warning(f"Could not drop conflicting index {iname}: {drop_err}")
        except Exception as info_err:
            logger.warning(f"Could not inspect assets indexes: {info_err}")

        await db_helper.db.assets.create_index(
            [("project_id", 1), ("type", 1), ("value", 1)],
            unique=True,
            name="project_id_1_type_1_value_1_unique"
        )
        # Initialize index for scan diffs
        await db_helper.db.scan_diffs.create_index([("project_id", 1), ("created_at", -1)])
        # Initialize indexes for Phase 6 Run History
        await db_helper.db.scan_runs.create_index("job_id", unique=True)
        await db_helper.db.scan_runs.create_index([("project_id", 1), ("started_at", -1)])
        await db_helper.db.run_assets.create_index(
            [("project_id", 1), ("job_id", 1), ("type", 1), ("value", 1)],
            unique=True,
            name="run_assets_proj_job_type_val_unique"
        )
        logger.info("[✓] Database indexes initialized successfully.")
    except Exception as idx_err:
        logger.warning(f"Warning during database index initialization: {idx_err}")

async def close_mongo_connection():
    if db_helper.client and not db_helper.is_mock:
        logger.info("Closing MongoDB connection...")
        db_helper.client.close()
        logger.info("MongoDB connection closed.")

def get_database():
    return db_helper.db
