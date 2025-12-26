"""Tests for AsyncPermissionRepository."""

from uuid import uuid4

import pytest
from sqlalchemy import Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from binauth import AsyncPermissionRepository, UndefinedScopeError
from binauth.models import Base


class TestAsyncPermissionRepository:
    """Tests for AsyncPermissionRepository."""

    async def test_get_user_permission_empty(self, async_session, manager):
        """Test getting permission for user with no permissions."""
        repo: AsyncPermissionRepository[int] = AsyncPermissionRepository(async_session, manager)

        result = await repo.get_user_permission(1, "tasks")
        assert result is None

    async def test_set_and_get_permission(self, async_session, manager):
        """Test setting and getting a permission."""
        repo: AsyncPermissionRepository[int] = AsyncPermissionRepository(async_session, manager)

        await repo.set_permission(1, "tasks", 3)
        await async_session.commit()

        result = await repo.get_user_permission(1, "tasks")
        assert result == 3

    async def test_set_permission_overwrites(self, async_session, manager):
        """Test that set_permission overwrites existing value."""
        repo: AsyncPermissionRepository[int] = AsyncPermissionRepository(async_session, manager)

        await repo.set_permission(1, "tasks", 3)
        await repo.set_permission(1, "tasks", 15)
        await async_session.commit()

        result = await repo.get_user_permission(1, "tasks")
        assert result == 15

    async def test_get_all_user_permissions(self, async_session, manager):
        """Test getting all permissions for a user."""
        repo: AsyncPermissionRepository[int] = AsyncPermissionRepository(async_session, manager)

        await repo.set_permission(1, "tasks", 3)
        await repo.set_permission(1, "reports", 1)
        await async_session.commit()

        result = await repo.get_all_user_permissions(1)
        assert result == {"tasks": 3, "reports": 1}

    async def test_grant_actions(self, async_session, manager, task_permissions):
        """Test granting actions to a user."""
        repo: AsyncPermissionRepository[int] = AsyncPermissionRepository(async_session, manager)
        Actions = task_permissions.Actions

        await repo.grant_actions(1, "tasks", Actions.CREATE)
        await repo.grant_actions(1, "tasks", Actions.READ)
        await async_session.commit()

        result = await repo.get_user_permission(1, "tasks")
        assert result == 3  # 1 | 2 = 3

    async def test_revoke_actions(self, async_session, manager, task_permissions):
        """Test revoking actions from a user."""
        repo: AsyncPermissionRepository[int] = AsyncPermissionRepository(async_session, manager)
        Actions = task_permissions.Actions

        await repo.set_permission(1, "tasks", 15)  # All actions
        await repo.revoke_actions(1, "tasks", Actions.DELETE)
        await async_session.commit()

        result = await repo.get_user_permission(1, "tasks")
        assert result == 7  # 15 & ~8 = 7

    async def test_delete_permission(self, async_session, manager):
        """Test deleting a permission."""
        repo: AsyncPermissionRepository[int] = AsyncPermissionRepository(async_session, manager)

        await repo.set_permission(1, "tasks", 3)
        await async_session.commit()

        deleted = await repo.delete_permission(1, "tasks")
        await async_session.commit()

        assert deleted is True

        result = await repo.get_user_permission(1, "tasks")
        assert result is None

    async def test_delete_permission_nonexistent(self, async_session, manager):
        """Test deleting a permission that doesn't exist."""
        repo: AsyncPermissionRepository[int] = AsyncPermissionRepository(async_session, manager)

        deleted = await repo.delete_permission(1, "tasks")
        assert deleted is False

    async def test_delete_all_permissions(self, async_session, manager):
        """Test deleting all permissions for a user."""
        repo: AsyncPermissionRepository[int] = AsyncPermissionRepository(async_session, manager)

        await repo.set_permission(1, "tasks", 3)
        await repo.set_permission(1, "reports", 1)
        await async_session.commit()

        count = await repo.delete_all_permissions(1)
        await async_session.commit()

        assert count == 2

        result = await repo.get_all_user_permissions(1)
        assert result == {}

    async def test_has_permission(self, async_session, manager, task_permissions):
        """Test checking if user has a permission."""
        repo: AsyncPermissionRepository[int] = AsyncPermissionRepository(async_session, manager)
        Actions = task_permissions.Actions

        await repo.set_permission(1, "tasks", 3)  # CREATE + READ
        await async_session.commit()

        assert await repo.has_permission(1, "tasks", Actions.CREATE) is True
        assert await repo.has_permission(1, "tasks", Actions.READ) is True
        assert await repo.has_permission(1, "tasks", Actions.UPDATE) is False

    async def test_has_all_permissions(self, async_session, manager, task_permissions):
        """Test checking if user has all specified permissions."""
        repo: AsyncPermissionRepository[int] = AsyncPermissionRepository(async_session, manager)
        Actions = task_permissions.Actions

        await repo.set_permission(1, "tasks", 7)  # CREATE + READ + UPDATE
        await async_session.commit()

        assert await repo.has_all_permissions(1, "tasks", [Actions.CREATE, Actions.READ]) is True
        assert await repo.has_all_permissions(1, "tasks", [Actions.CREATE, Actions.DELETE]) is False

    async def test_has_any_permission(self, async_session, manager, task_permissions):
        """Test checking if user has any of the specified permissions."""
        repo: AsyncPermissionRepository[int] = AsyncPermissionRepository(async_session, manager)
        Actions = task_permissions.Actions

        await repo.set_permission(1, "tasks", 1)  # Only CREATE
        await async_session.commit()

        assert await repo.has_any_permission(1, "tasks", [Actions.CREATE, Actions.DELETE]) is True
        assert await repo.has_any_permission(1, "tasks", [Actions.UPDATE, Actions.DELETE]) is False

    async def test_undefined_scope_error(self, async_session, manager):
        """Test that undefined scope raises error."""
        repo: AsyncPermissionRepository[int] = AsyncPermissionRepository(async_session, manager)

        with pytest.raises(UndefinedScopeError):
            await repo.get_user_permission(1, "nonexistent")

    async def test_multiple_users(self, async_session, manager, task_permissions):
        """Test permissions for multiple users are independent."""
        repo: AsyncPermissionRepository[int] = AsyncPermissionRepository(async_session, manager)
        Actions = task_permissions.Actions

        await repo.set_permission(1, "tasks", 1)  # User 1: CREATE
        await repo.set_permission(2, "tasks", 2)  # User 2: READ
        await async_session.commit()

        assert await repo.has_permission(1, "tasks", Actions.CREATE) is True
        assert await repo.has_permission(1, "tasks", Actions.READ) is False
        assert await repo.has_permission(2, "tasks", Actions.CREATE) is False
        assert await repo.has_permission(2, "tasks", Actions.READ) is True


# Custom permission model for testing generic model support
class CustomPermission(Base):
    """Custom permission model with additional fields."""

    __tablename__ = "custom_permissions"

    user_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    scope_name: Mapped[str] = mapped_column(String(100), primary_key=True)
    level: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    tenant_id: Mapped[int] = mapped_column(Integer, nullable=False, default=1)

    def __repr__(self) -> str:
        return "CustomPermission"


class TestCustomModelRepository:
    """Tests for AsyncPermissionRepository with custom model."""

    @pytest.fixture
    async def custom_session(self, async_engine):
        """Create tables for custom model and return session."""
        from sqlalchemy.ext.asyncio import AsyncSession
        from sqlalchemy.orm import sessionmaker

        # Create custom model table
        async with async_engine.begin() as conn:
            await conn.run_sync(CustomPermission.__table__.create, checkfirst=True)

        async_session_maker = sessionmaker(
            async_engine,
            class_=AsyncSession,
            expire_on_commit=False,
        )

        async with async_session_maker() as session:
            yield session
            await session.rollback()

    async def test_custom_model_conforms_to_protocol(self):
        """Test that custom model conforms to PermissionModelProtocol."""
        assert hasattr(CustomPermission, "user_id")
        assert hasattr(CustomPermission, "scope_name")
        assert hasattr(CustomPermission, "level")

    async def test_set_and_get_permission_custom_model(self, custom_session, manager):
        """Test setting and getting permission with custom model."""
        repo: AsyncPermissionRepository[str, CustomPermission] = AsyncPermissionRepository(
            custom_session, manager, model=CustomPermission
        )
        user_id = str(uuid4())

        await repo.set_permission(user_id, "tasks", 3)
        await custom_session.commit()

        result = await repo.get_user_permission(user_id, "tasks")
        assert result == 3

    async def test_get_all_permissions_custom_model(self, custom_session, manager):
        """Test getting all permissions with custom model."""
        repo: AsyncPermissionRepository[str, CustomPermission] = AsyncPermissionRepository(
            custom_session, manager, model=CustomPermission
        )
        user_id = str(uuid4())

        await repo.set_permission(user_id, "tasks", 3)
        await repo.set_permission(user_id, "reports", 1)
        await custom_session.commit()

        result = await repo.get_all_user_permissions(user_id)
        assert result == {"tasks": 3, "reports": 1}

    async def test_grant_actions_custom_model(self, custom_session, manager, task_permissions):
        """Test granting actions with custom model."""
        repo: AsyncPermissionRepository[str, CustomPermission] = AsyncPermissionRepository(
            custom_session, manager, model=CustomPermission
        )
        Actions = task_permissions.Actions
        user_id = str(uuid4())

        await repo.grant_actions(user_id, "tasks", Actions.CREATE)
        await repo.grant_actions(user_id, "tasks", Actions.READ)
        await custom_session.commit()

        result = await repo.get_user_permission(user_id, "tasks")
        assert result == 3  # 1 | 2 = 3

    async def test_revoke_actions_custom_model(self, custom_session, manager, task_permissions):
        """Test revoking actions with custom model."""
        repo: AsyncPermissionRepository[str, CustomPermission] = AsyncPermissionRepository(
            custom_session, manager, model=CustomPermission
        )
        Actions = task_permissions.Actions
        user_id = str(uuid4())

        await repo.set_permission(user_id, "tasks", 15)  # All actions
        await repo.revoke_actions(user_id, "tasks", Actions.DELETE)
        await custom_session.commit()

        result = await repo.get_user_permission(user_id, "tasks")
        assert result == 7  # 15 & ~8 = 7

    async def test_delete_permission_custom_model(self, custom_session, manager):
        """Test deleting permission with custom model."""
        repo: AsyncPermissionRepository[str, CustomPermission] = AsyncPermissionRepository(
            custom_session, manager, model=CustomPermission
        )
        user_id = str(uuid4())

        await repo.set_permission(user_id, "tasks", 3)
        await custom_session.commit()

        deleted = await repo.delete_permission(user_id, "tasks")
        await custom_session.commit()

        assert deleted is True
        result = await repo.get_user_permission(user_id, "tasks")
        assert result is None

    async def test_delete_all_permissions_custom_model(self, custom_session, manager):
        """Test deleting all permissions with custom model."""
        repo: AsyncPermissionRepository[str, CustomPermission] = AsyncPermissionRepository(
            custom_session, manager, model=CustomPermission
        )
        user_id = str(uuid4())

        await repo.set_permission(user_id, "tasks", 3)
        await repo.set_permission(user_id, "reports", 1)
        await custom_session.commit()

        count = await repo.delete_all_permissions(user_id)
        await custom_session.commit()

        assert count == 2
        result = await repo.get_all_user_permissions(user_id)
        assert result == {}

    async def test_has_permission_custom_model(self, custom_session, manager, task_permissions):
        """Test checking permission with custom model."""
        repo: AsyncPermissionRepository[str, CustomPermission] = AsyncPermissionRepository(
            custom_session, manager, model=CustomPermission
        )
        Actions = task_permissions.Actions
        user_id = str(uuid4())

        await repo.set_permission(user_id, "tasks", 3)  # CREATE + READ
        await custom_session.commit()

        assert await repo.has_permission(user_id, "tasks", Actions.CREATE) is True
        assert await repo.has_permission(user_id, "tasks", Actions.READ) is True
        assert await repo.has_permission(user_id, "tasks", Actions.UPDATE) is False

    async def test_set_permission_returns_custom_model_instance(self, custom_session, manager):
        """Test that set_permission returns instance of custom model."""
        repo: AsyncPermissionRepository[str, CustomPermission] = AsyncPermissionRepository(
            custom_session, manager, model=CustomPermission
        )
        user_id = str(uuid4())

        permission = await repo.set_permission(user_id, "tasks", 3)
        await custom_session.commit()

        assert isinstance(permission, CustomPermission)
        assert permission.user_id == user_id
        assert permission.scope_name == "tasks"
        assert permission.level == 3
        assert permission.tenant_id == 1  # Custom field with default value
