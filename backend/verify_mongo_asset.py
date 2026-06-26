import asyncio
import motor.motor_asyncio as ma

async def main():
    client = ma.AsyncIOMotorClient('mongodb://127.0.0.1:27017', serverSelectionTimeoutMS=2000)
    try:
        pong = await client.admin.command('ping')
        print('mongo pong', pong)
        db = client.reconforge
        doc = await db.assets.find_one({'domain': 'api.hackerone.com'})
        print('doc_found', bool(doc))
        if doc:
            print(doc)
    except Exception as e:
        print('error', repr(e))
    finally:
        client.close()

asyncio.run(main())
