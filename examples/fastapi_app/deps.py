"""FastAPI dependencies for the example app."""

from collections.abc import AsyncGenerator
from dataclasses import dataclass

from fastapi import Header, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from binauth import create_permission_dependency

from .permissions import manager

# Database setup (using SQLite for example)
DATABASE_URL = "sqlite+aiosqlite:///./example.db"

engine = create_async_engine(DATABASE_URL, echo=True)
async_session_maker = async_sessionmaker(engine, expire_on_commit=False)


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """Dependency to get database session."""
    async with async_session_maker() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise


# Option 1: Using get_current_user_id (returns ID directly)
async def get_current_user_id(x_user_id: int = Header(...)) -> int:
    """
    Dependency to get the current user ID.

    In a real application, this would validate a JWT token or session.
    For this example, we just use a header.
    """
    if x_user_id <= 0:
        raise HTTPException(status_code=401, detail="Invalid user ID")
    return x_user_id


# Option 2: Using get_current_user (returns user object with .id)
# This is useful when you already have a user getter from JWT auth
@dataclass
class User:
    """Example user model."""

    id: int
    name: str


async def get_current_user(x_user_id: int = Header(...)) -> User:
    """
    Dependency to get the current user.

    In a real application, this would validate a JWT token and
    return the full user object from the database.
    """
    if x_user_id <= 0:
        raise HTTPException(status_code=401, detail="Invalid user ID")
    return User(id=x_user_id, name=f"User {x_user_id}")


# Create the permission dependency
# You can use either get_current_user_id OR get_current_user (not both)
permission = create_permission_dependency(
    manager=manager,
    get_db=get_db,
    # Option 1: Pass user ID directly
    get_current_user_id=get_current_user_id,
    # Option 2: Pass user object with .id attribute (uncomment to use)
    # get_current_user=get_current_user,
    cache_ttl=60,
)
