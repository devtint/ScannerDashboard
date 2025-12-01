"""Database configuration and session management"""
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from config import settings
from app.models import Base

# Convert sqlite URL to async version
DATABASE_URL = settings.database_url
if DATABASE_URL.startswith("sqlite"):
    DATABASE_URL = DATABASE_URL.replace("sqlite://", "sqlite+aiosqlite://")

# Create async engine
engine = create_async_engine(
    DATABASE_URL,
    echo=settings.debug,
    future=True
)

# Create async session factory
AsyncSessionLocal = sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False
)


async def init_db():
    """Initialize database tables"""
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


async def get_db():
    """Dependency for getting database session"""
    async with AsyncSessionLocal() as session:
        try:
            yield session
        finally:
            await session.close()
