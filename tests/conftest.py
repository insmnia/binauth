"""Pytest fixtures for binauth tests."""

from enum import IntEnum
from typing import ClassVar

import pytest
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker

from binauth import PermissionActionRegistry, PermissionsManager
from binauth.models import Base


class TaskPermissions(PermissionActionRegistry):
    """Test permission registry for tasks."""

    scope_name = "tasks"
    category = "Content"
    description = "Task management"

    class Actions(IntEnum):
        CREATE = 1 << 0  # 1
        READ = 1 << 1  # 2
        UPDATE = 1 << 2  # 4
        DELETE = 1 << 3  # 8

    action_descriptions: ClassVar[dict[str, str]] = {
        "CREATE": "Create new tasks",
        "READ": "View tasks",
        "UPDATE": "Edit tasks",
        "DELETE": "Remove tasks",
    }


class ReportPermissions(PermissionActionRegistry):
    """Test permission registry for reports."""

    scope_name = "reports"
    category = "Content"
    description = "Report management"

    class Actions(IntEnum):
        VIEW = 1 << 0  # 1
        EXPORT = 1 << 1  # 2

    action_descriptions: ClassVar[dict[str, str]] = {
        "VIEW": "View reports",
        "EXPORT": "Export reports",
    }


@pytest.fixture
def task_permissions():
    """Return TaskPermissions registry."""
    return TaskPermissions


@pytest.fixture
def report_permissions():
    """Return ReportPermissions registry."""
    return ReportPermissions


@pytest.fixture
def manager(task_permissions, report_permissions):
    """Create a PermissionsManager with test registries."""
    return PermissionsManager([task_permissions, report_permissions])


@pytest.fixture
async def async_engine():
    """Create an async SQLite in-memory engine."""
    engine = create_async_engine(
        "sqlite+aiosqlite:///:memory:",
        echo=False,
    )
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    yield engine

    await engine.dispose()


@pytest.fixture
async def async_session(async_engine):
    """Create an async session for testing."""
    async_session_maker = sessionmaker(
        async_engine,
        class_=AsyncSession,
        expire_on_commit=False,
    )

    async with async_session_maker() as session:
        yield session
        await session.rollback()
