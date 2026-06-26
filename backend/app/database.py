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
        self.documents = documents
        self.sort_key = None
        self.sort_direction = 1

    def sort(self, key, direction=-1):
        self.sort_key = key
        self.sort_direction = direction
        return self

    async def to_list(self, length=100):
        # Apply sorting if configured
        if self.sort_key:
            rev = (self.sort_direction == -1)
            # handle nested keys or basic keys
            self.documents.sort(
                key=lambda x: x.get(self.sort_key, datetime.min) if isinstance(x.get(self.sort_key), datetime) else x.get(self.sort_key, ""), 
                reverse=rev
            )
        return self.documents[:length]


class MockCollection:
    def __init__(self, name):
        self.name = name
        self.docs = []

    def _match(self, doc, query):
        for k, v in query.items():
            if k == "_id":
                if doc.get("_id") != v:
                    return False
            elif isinstance(v, dict):
                # Simple handling of nested operations if needed
                pass
            else:
                if doc.get(k) != v:
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

    async def update_one(self, query, update):
        await asyncio.sleep(0.01)
        doc = await self.find_one(query)
        if not doc:
            return
            
        if "$set" in update:
            for k, v in update["$set"].items():
                doc[k] = v
        if "$push" in update:
            for k, v in update["$push"].items():
                if k not in doc:
                    doc[k] = []
                doc[k].append(v)
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
        logger.warning(f"[!] MongoDB is unavailable ({e}). Falling back to IN-MEMORY DATABASE for this session.")
        db_helper.is_mock = True
        db_helper.db = MockDb()

async def close_mongo_connection():
    if db_helper.client and not db_helper.is_mock:
        logger.info("Closing MongoDB connection...")
        db_helper.client.close()
        logger.info("MongoDB connection closed.")

def get_database():
    return db_helper.db
