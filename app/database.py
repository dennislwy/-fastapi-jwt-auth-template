import logging
from typing import AsyncGenerator, List
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase
from app.config import settings

DATABASE_URL = settings.DATABASE_URL

class Base(DeclarativeBase):
    pass

engine = create_async_engine(DATABASE_URL)
async_session_maker = async_sessionmaker(engine, expire_on_commit=False)


async def init_db(base: Base | List[Base]):
    async with engine.begin() as conn:
        # Create all the tables defined in the Base metadata
        if isinstance(base, list):
            for b in base:
                await conn.run_sync(b.metadata.create_all)
        else:
            await conn.run_sync(base.metadata.create_all)

async def get_async_session() -> AsyncGenerator[AsyncSession, None]:
    async with async_session_maker() as session:
        yield session