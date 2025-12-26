"""Tests for AsyncPermissionRepository."""

import pytest

from binauth import AsyncPermissionRepository, UndefinedScopeError


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
