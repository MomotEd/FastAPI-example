import os

from sqlmodel.ext.asyncio.session import AsyncSession
from sqlalchemy.ext.asyncio import create_async_engine


DB_USER = os.getenv("DB_USER", "user")
DB_PASS = os.getenv("DB_PASS", "123")
DB_HOST = os.getenv("DB_HOST", "localhost")
DB_PORT = os.getenv("DB_PORT", "5432")

db_url = "postgresql+asyncpg://{}:{}@{}:{}/main".format(
    DB_USER, DB_PASS, DB_HOST, DB_PORT
)

engine = create_async_engine(db_url, echo=True, future=True)


async def get_session() -> AsyncSession:
    async with AsyncSession(engine) as session:
        yield session
