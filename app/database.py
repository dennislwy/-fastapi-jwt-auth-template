from typing import AsyncGenerator
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase
from app.config import settings

DATABASE_URL = settings.DATABASE_URL

class Base(DeclarativeBase):
    pass

engine = create_async_engine(DATABASE_URL, connect_args={"check_same_thread": False})
async_session_maker = async_sessionmaker(engine, expire_on_commit=False)

async def init_db():
    """
    Initializes the database by creating all the tables defined in the Base metadata.

    Args:
        None

    Returns:
        None
    """
    async with engine.begin() as conn:
        # Create all tables defined in the Base metadata
        await conn.run_sync(Base.metadata.create_all)

async def get_async_session() -> AsyncGenerator[AsyncSession, None]:
    """
    Returns an asynchronous session generator.

    Yields:
        AsyncSession: An asynchronous session object.

    """
    # Create an asynchronous session using async_session_maker
    async with async_session_maker() as session:
        yield session