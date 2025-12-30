"""
Async repository for managing user permissions in the database.

Requires: pip install binauth[db]
"""

from typing import Generic

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from .exceptions import UndefinedActionError, UndefinedScopeError
from .manager import PermissionsManager
from .models import UserPermission
from .types import (
    ModelT,
    PermissionAction,
    PermissionBinLevel,
    Permissions,
    PermissionScope,
    UserIdT,
)


class AsyncPermissionRepository(Generic[UserIdT, ModelT]):
    """
    Asynchronous repository for managing user permissions.

    Generic over:
    - UserIdT: The user ID type (int, UUID, or str)
    - ModelT: The permission model type (must implement PermissionModelProtocol)

    Args:
        session: SQLAlchemy async session
        manager: PermissionsManager instance for scope/action validation
        model: Permission model class (default: UserPermission)
        autocommit: If True, commit after each write operation.
                   If False (default), only flush changes.

    The autocommit setting can be overridden on individual method calls
    by passing the `autocommit` parameter to write methods.

    Example with default UserPermission model:
        repo: AsyncPermissionRepository[int, UserPermission] = AsyncPermissionRepository(
            session, manager
        )

    Example with autocommit enabled:
        repo = AsyncPermissionRepository(session, manager, autocommit=True)

    Example with per-method autocommit override:
        repo = AsyncPermissionRepository(session, manager, autocommit=False)
        await repo.set_permission(user_id, scope, level, autocommit=True)

    Example with custom model:
        class MyPermission(Base):
            __tablename__ = "my_permissions"
            user_id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), primary_key=True)
            scope_name: Mapped[str] = mapped_column(String(100), primary_key=True)
            level: Mapped[int] = mapped_column(Integer, default=0)

        repo: AsyncPermissionRepository[UUID, MyPermission] = AsyncPermissionRepository(
            session, manager, model=MyPermission
        )
    """

    def __init__(
        self,
        session: AsyncSession,
        manager: PermissionsManager,
        model: type[ModelT] = UserPermission,  # type: ignore[assignment]
        autocommit: bool = False,
    ):
        self._session = session
        self._manager = manager
        self._model: type[ModelT] = model
        self._autocommit = autocommit

    async def _persist_changes(self, autocommit: bool | None = None) -> None:
        """
        Flush or commit changes based on autocommit setting.

        Args:
            autocommit: Override the repository-level autocommit setting.
                       If None, uses the repository default.
        """
        should_commit = autocommit if autocommit is not None else self._autocommit
        if should_commit:
            await self._session.commit()
        else:
            await self._session.flush()

    def _validate_scope(self, scope: PermissionScope) -> None:
        """Validate that the scope exists in the manager."""
        if scope not in self._manager.scopes:
            raise UndefinedScopeError(f"Undefined scope: {scope}")

    def _validate_action(self, scope: PermissionScope, action: PermissionAction) -> None:
        """Validate that the action belongs to the scope."""
        registry = self._manager.get_registry(scope)
        if not isinstance(action, registry.Actions):
            raise UndefinedActionError(
                f"Action {action} is not valid for scope '{scope}'. " f"Expected one of: {list(registry.Actions)}"
            )

    # ========== Read Operations ==========

    async def get_user_permission(self, user_id: UserIdT, scope: PermissionScope) -> PermissionBinLevel | None:
        """
        Get a user's permission level for a specific scope.

        Returns None if the user has no permissions for this scope.
        """
        self._validate_scope(scope)

        result = await self._session.execute(
            select(self._model.level).where(
                self._model.user_id == user_id,
                self._model.scope_name == scope,
            )
        )
        row = result.scalar_one_or_none()
        return row

    async def get_all_user_permissions(self, user_id: UserIdT) -> Permissions:
        """
        Get all permission levels for a user across all scopes.

        Returns a dict mapping scope names to permission levels.
        """
        result = await self._session.execute(select(self._model).where(self._model.user_id == user_id))
        permissions = result.scalars().all()
        return {p.scope_name: p.level for p in permissions}

    # ========== Write Operations ==========

    async def set_permission(
        self,
        user_id: UserIdT,
        scope: PermissionScope,
        level: PermissionBinLevel,
        autocommit: bool | None = None,
    ) -> ModelT:
        """
        Set a user's permission level for a scope (overwrites existing).

        Args:
            user_id: The user's ID
            scope: The permission scope name
            level: The bitwise permission level
            autocommit: Override the repository-level autocommit setting.
                       If None, uses the repository default.

        Returns:
            The created/updated permission model record
        """
        self._validate_scope(scope)

        result = await self._session.execute(
            select(self._model).where(
                self._model.user_id == user_id,
                self._model.scope_name == scope,
            )
        )
        existing = result.scalar_one_or_none()

        if existing:
            existing.level = level
            permission = existing
        else:
            permission = self._model(
                user_id=user_id,
                scope_name=scope,
                level=level,
            )
            self._session.add(permission)

        await self._persist_changes(autocommit)
        return permission

    async def grant_actions(
        self,
        user_id: UserIdT,
        scope: PermissionScope,
        *actions: PermissionAction,
        autocommit: bool | None = None,
    ) -> ModelT:
        """
        Grant additional actions to a user for a scope.

        Uses bitwise OR to add permissions without removing existing ones.

        Args:
            user_id: The user's ID
            scope: The permission scope name
            actions: One or more action enum values to grant
            autocommit: Override the repository-level autocommit setting.
                       If None, uses the repository default.

        Returns:
            The updated permission model record
        """
        self._validate_scope(scope)
        for action in actions:
            self._validate_action(scope, action)

        current_level = await self.get_user_permission(user_id, scope) or 0
        additional_level = sum(action.value for action in actions)
        new_level = current_level | additional_level

        return await self.set_permission(user_id, scope, new_level, autocommit=autocommit)

    async def revoke_actions(
        self,
        user_id: UserIdT,
        scope: PermissionScope,
        *actions: PermissionAction,
        autocommit: bool | None = None,
    ) -> ModelT:
        """
        Revoke specific actions from a user for a scope.

        Uses bitwise AND with NOT to remove permissions.

        Args:
            user_id: The user's ID
            scope: The permission scope name
            actions: One or more action enum values to revoke
            autocommit: Override the repository-level autocommit setting.
                       If None, uses the repository default.

        Returns:
            The updated permission model record
        """
        self._validate_scope(scope)
        for action in actions:
            self._validate_action(scope, action)

        current_level = await self.get_user_permission(user_id, scope) or 0
        revoke_mask = sum(action.value for action in actions)
        new_level = current_level & ~revoke_mask

        return await self.set_permission(user_id, scope, new_level, autocommit=autocommit)

    async def delete_permission(
        self,
        user_id: UserIdT,
        scope: PermissionScope,
        autocommit: bool | None = None,
    ) -> bool:
        """
        Delete a user's permission for a specific scope.

        Args:
            user_id: The user's ID
            scope: The permission scope name
            autocommit: Override the repository-level autocommit setting.
                       If None, uses the repository default.

        Returns:
            True if a permission was deleted, False if none existed.
        """
        self._validate_scope(scope)

        result = await self._session.execute(
            delete(self._model).where(
                self._model.user_id == user_id,
                self._model.scope_name == scope,
            )
        )
        await self._persist_changes(autocommit)
        return result.rowcount > 0

    async def delete_all_permissions(
        self,
        user_id: UserIdT,
        autocommit: bool | None = None,
    ) -> int:
        """
        Delete all permissions for a user.

        Args:
            user_id: The user's ID
            autocommit: Override the repository-level autocommit setting.
                       If None, uses the repository default.

        Returns:
            The number of permission records deleted.
        """
        result = await self._session.execute(delete(self._model).where(self._model.user_id == user_id))
        await self._persist_changes(autocommit)
        return result.rowcount

    # ========== Check Operations ==========

    async def has_permission(self, user_id: UserIdT, scope: PermissionScope, action: PermissionAction) -> bool:
        """
        Check if a user has a specific permission.

        Args:
            user_id: The user's ID
            scope: The permission scope name
            action: The action to check

        Returns:
            True if the user has the permission, False otherwise
        """
        self._validate_scope(scope)
        self._validate_action(scope, action)

        level = await self.get_user_permission(user_id, scope)
        if level is None:
            return False

        return (level & action.value) != 0

    async def has_all_permissions(
        self, user_id: UserIdT, scope: PermissionScope, actions: list[PermissionAction]
    ) -> bool:
        """
        Check if a user has ALL of the specified permissions.

        Args:
            user_id: The user's ID
            scope: The permission scope name
            actions: List of actions to check

        Returns:
            True if the user has all permissions, False otherwise
        """
        for action in actions:
            if not await self.has_permission(user_id, scope, action):
                return False
        return True

    async def has_any_permission(
        self, user_id: UserIdT, scope: PermissionScope, actions: list[PermissionAction]
    ) -> bool:
        """
        Check if a user has ANY of the specified permissions.

        Args:
            user_id: The user's ID
            scope: The permission scope name
            actions: List of actions to check

        Returns:
            True if the user has at least one permission, False otherwise
        """
        for action in actions:
            if await self.has_permission(user_id, scope, action):
                return True
        return False
