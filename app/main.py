import sys
import logging
from fastapi import FastAPI
from contextlib import asynccontextmanager
import app.models
from app.database import init_db
from app.routers import router
from app.config import settings

# Logging uncaught exceptions, https://stackoverflow.com/a/16993115
def handle_exception(exc_type, exc_value, exc_traceback):
    if issubclass(exc_type, KeyboardInterrupt):
        sys.__excepthook__(exc_type, exc_value, exc_traceback)
        return
    logging.critical("Uncaught exception", exc_info=(exc_type, exc_value, exc_traceback))

sys.excepthook = handle_exception

@asynccontextmanager
async def lifespan(app: FastAPI):
    try:
        await startup()
        yield
    finally:
        await shutdown()

app = FastAPI(
    lifespan=lifespan
)

app.include_router(router)

async def startup():
    logging.info("Starting up server")
    # Not needed if you setup a migration system like Alembic
    # await init_db([AuthBase, UsersBase])
    await init_db()

async def shutdown():
    logging.info("Shutting down server")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", reload=True, port=8000)
