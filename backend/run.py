# import uvicorn

# if __name__ == "__main__":
#     uvicorn.run("app.main:app", host="127.0.0.1", port=8000, reload=True)

import asyncio
import uvicorn

asyncio.set_event_loop_policy(
    asyncio.WindowsProactorEventLoopPolicy()
)

if __name__ == "__main__":
    uvicorn.run(
        "app.main:app",
        host="127.0.0.1",
        port=8000,
        reload=True
    )