"""
FastAPI integration for binauth permission system.

Requires: pip install binauth[fastapi]
"""

import time
from collections.abc import Awaitable, Callable
from typing import Generic, Protocol, runtime_checkable

from fastapi import APIRouter, Depends, FastAPI, Request
from fastapi.responses import JSONResponse
from sqlalchemy.ext.asyncio import AsyncSession

from .exceptions import PermissionDenied
from .manager import CategorySchema, PermissionsManager
from .models import UserPermission
from .repository import AsyncPermissionRepository
from .types import (
    ModelT,
    PermissionAction,
    Permissions,
    PermissionScope,
    UserIdT,
)


@runtime_checkable
class UserWithId(Protocol[UserIdT]):
    """Protocol for user objects with an id attribute."""

    @property
    def id(self) -> UserIdT: ...


class PermissionCache(Generic[UserIdT]):
    """
    In-memory cache for user permissions with TTL expiration.

    Generic over the user ID type (int, UUID, or str).

    Thread-safe for read operations. Write operations should be
    synchronized externally if used in a multi-threaded context.
    """

    def __init__(self, ttl_seconds: int = 60):
        """
        Initialize the cache.

        Args:
            ttl_seconds: Time-to-live for cached entries in seconds.
                        Set to 0 to disable caching.
        """
        self._cache: dict[UserIdT, tuple[float, Permissions]] = {}
        self._ttl = ttl_seconds

    def get(self, user_id: UserIdT) -> Permissions | None:
        """
        Get cached permissions for a user.

        Returns None if not cached or expired.
        """
        if self._ttl <= 0:
            return None

        entry = self._cache.get(user_id)
        if entry is None:
            return None

        timestamp, permissions = entry
        if time.time() - timestamp > self._ttl:
            del self._cache[user_id]
            return None

        return permissions

    def set(self, user_id: UserIdT, permissions: Permissions) -> None:
        """Cache permissions for a user."""
        if self._ttl <= 0:
            return

        self._cache[user_id] = (time.time(), permissions)

    def invalidate(self, user_id: UserIdT) -> None:
        """Remove cached permissions for a user."""
        self._cache.pop(user_id, None)

    def clear(self) -> None:
        """Clear all cached permissions."""
        self._cache.clear()


class PermissionDependency(Generic[UserIdT, ModelT]):
    """
    FastAPI dependency factory for permission checks.

    Generic over:
    - UserIdT: The user ID type (int, UUID, or str)
    - ModelT: The permission model type (must implement PermissionModelProtocol)

    Usage:
        permission = create_permission_dependency(manager, get_user_id, get_db)

        @router.get("/tasks")
        async def list_tasks(_ = Depends(permission.require("tasks", Actions.READ))):
            ...

    Usage with custom model:
        permission = create_permission_dependency(
            manager, get_user_id, get_db, model=MyPermissionModel
        )
    """

    def __init__(
        self,
        manager: PermissionsManager,
        get_db: Callable[..., Awaitable[AsyncSession]],
        cache: PermissionCache[UserIdT],
        get_current_user_id: Callable[..., Awaitable[UserIdT]] | None = None,
        get_current_user: Callable[..., Awaitable[UserWithId[UserIdT]]] | None = None,
        model: type[ModelT] = UserPermission,  # type: ignore[assignment]
    ):
        if get_current_user_id is None and get_current_user is None:
            raise ValueError("Either get_current_user_id or get_current_user must be provided")
        if get_current_user_id is not None and get_current_user is not None:
            raise ValueError("Only one of get_current_user_id or get_current_user can be provided")

        self._manager = manager
        self._get_current_user_id = get_current_user_id
        self._get_current_user = get_current_user
        self._get_db = get_db
        self._cache = cache
        self._model = model

    def require(
        self,
        scope: PermissionScope,
        action: PermissionAction,
    ) -> Callable[..., Awaitable[UserIdT]]:
        """
        Create a dependency that requires a specific permission.

        Args:
            scope: The permission scope to check
            action: The action required

        Returns:
            A FastAPI dependency that returns the user_id if authorized,
            or raises PermissionDenied if not.

        Example:
            @router.get("/tasks")
            async def list_tasks(
                user_id: int = Depends(permission.require("tasks", Actions.READ))
            ):
                # user_id is available here
                ...
        """
        return self._create_dependency(scope, [action], require_all=True)

    def require_all(
        self,
        scope: PermissionScope,
        actions: list[PermissionAction],
    ) -> Callable[..., Awaitable[UserIdT]]:
        """
        Create a dependency that requires ALL specified permissions.

        Args:
            scope: The permission scope to check
            actions: List of actions, ALL of which are required

        Returns:
            A FastAPI dependency that returns the user_id if authorized.
        """
        return self._create_dependency(scope, actions, require_all=True)

    def require_any(
        self,
        scope: PermissionScope,
        actions: list[PermissionAction],
    ) -> Callable[..., Awaitable[UserIdT]]:
        """
        Create a dependency that requires ANY of the specified permissions.

        Args:
            scope: The permission scope to check
            actions: List of actions, at least ONE of which is required

        Returns:
            A FastAPI dependency that returns the user_id if authorized.
        """
        return self._create_dependency(scope, actions, require_all=False)

    def _create_dependency(
        self,
        scope: PermissionScope,
        actions: list[PermissionAction],
        require_all: bool,
    ) -> Callable[..., Awaitable[UserIdT]]:
        """Internal method to create the actual FastAPI dependency."""
        manager = self._manager
        get_current_user_id = self._get_current_user_id
        get_current_user = self._get_current_user
        get_db = self._get_db
        cache = self._cache
        model = self._model

        async def check_permission_dependency(
            user_id: UserIdT,
            db: AsyncSession,
        ) -> UserIdT:
            """The actual permission check logic."""
            cached = cache.get(user_id)
            if cached is not None:
                permissions = cached
            else:
                repo: AsyncPermissionRepository[UserIdT, ModelT] = AsyncPermissionRepository(db, manager, model=model)
                permissions = await repo.get_all_user_permissions(user_id)
                cache.set(user_id, permissions)

            level = permissions.get(scope, 0)

            if require_all:
                for action in actions:
                    if (level & action.value) == 0:
                        raise PermissionDenied(scope, action, user_id)
            else:
                has_any = any((level & action.value) != 0 for action in actions)
                if not has_any:
                    raise PermissionDenied(scope, actions[0], user_id)

            return user_id

        if get_current_user_id is not None:

            async def dependency_wrapper_id(
                user_id: UserIdT = Depends(get_current_user_id),
                db: AsyncSession = Depends(get_db),
            ) -> UserIdT:
                return await check_permission_dependency(user_id, db)

            return dependency_wrapper_id
        else:

            async def dependency_wrapper_user(
                user: UserWithId[UserIdT] = Depends(get_current_user),
                db: AsyncSession = Depends(get_db),
            ) -> UserIdT:
                return await check_permission_dependency(user.id, db)

            return dependency_wrapper_user

    @property
    def cache(self) -> PermissionCache[UserIdT]:
        """Access the permission cache for manual invalidation."""
        return self._cache


def create_permission_dependency(
    manager: PermissionsManager,
    get_db: Callable[..., Awaitable[AsyncSession]],
    get_current_user_id: Callable[..., Awaitable[UserIdT]] | None = None,
    get_current_user: Callable[..., Awaitable[UserWithId[UserIdT]]] | None = None,
    cache_ttl: int = 60,
    model: type[ModelT] = UserPermission,  # type: ignore[assignment]
) -> PermissionDependency[UserIdT, ModelT]:
    """
    Create a PermissionDependency instance for use in FastAPI.

    Generic over the user ID type - inferred from get_current_user_id or
    get_current_user return type.

    Args:
        manager: The PermissionsManager with registered permission scopes
        get_db: A FastAPI dependency that yields an AsyncSession.
               This should be your database session dependency.
        get_current_user_id: A FastAPI dependency that returns the current user's ID.
                            Mutually exclusive with get_current_user.
        get_current_user: A FastAPI dependency that returns a user object with an `id`
                         attribute. Mutually exclusive with get_current_user_id.
        cache_ttl: Time-to-live for cached permissions in seconds.
                  Set to 0 to disable caching. Default: 60 seconds.
        model: The permission model class to use for database queries.
               Defaults to UserPermission. Use a custom model for UUID user IDs
               or different table names.

    Returns:
        A PermissionDependency instance with require(), require_all(),
        and require_any() methods.

    Example with get_current_user_id (returns ID directly):
        async def get_current_user_id() -> int:
            return 123

        permission = create_permission_dependency(
            manager, get_db, get_current_user_id=get_current_user_id
        )

    Example with get_current_user (returns user object with .id):
        async def get_current_user(token: str = Header(...)) -> User:
            return await verify_token(token)

        permission = create_permission_dependency(
            manager, get_db, get_current_user=get_current_user
        )

    Example with custom model:
        class MyPermission(Base):
            __tablename__ = "my_permissions"
            user_id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), primary_key=True)
            scope_name: Mapped[str] = mapped_column(String(100), primary_key=True)
            level: Mapped[int] = mapped_column(Integer, default=0)

        permission = create_permission_dependency(
            manager, get_db, get_current_user_id=get_current_user_id, model=MyPermission
        )
    """
    cache: PermissionCache[UserIdT] = PermissionCache(ttl_seconds=cache_ttl)

    return PermissionDependency(
        manager=manager,
        get_db=get_db,
        cache=cache,
        get_current_user_id=get_current_user_id,
        get_current_user=get_current_user,
        model=model,
    )


def setup_permission_exception_handler(app: FastAPI) -> None:
    """
    Register an exception handler for PermissionDenied with FastAPI.

    This converts PermissionDenied exceptions into HTTP 403 responses.

    Args:
        app: The FastAPI application instance

    Example:
        from fastapi import FastAPI
        from binauth import setup_permission_exception_handler

        app = FastAPI()
        setup_permission_exception_handler(app)
    """

    async def permission_denied_handler(request: Request, exc: PermissionDenied) -> JSONResponse:
        return JSONResponse(
            status_code=403,
            content={
                "detail": str(exc),
                "scope": exc.scope,
                "action": exc.action_name,
            },
        )

    app.add_exception_handler(PermissionDenied, permission_denied_handler)  # type: ignore


def get_permissions_router(
    manager: PermissionsManager,
    get_current_user: Callable[..., Awaitable[object]],
    path: str = "/permissions",
    tags: list[str] | None = None,
) -> APIRouter:
    """
    Create a FastAPI router with an endpoint to retrieve all available permissions.

    Returns permissions grouped by category with descriptions, useful for admin UIs
    that need to display available permissions for granting to users.

    Args:
        manager: The PermissionsManager with registered permission scopes
        get_current_user: A FastAPI dependency for authentication. The endpoint
            will require this dependency to be satisfied before returning permissions.
        path: URL path for the endpoint (default: "/permissions")
        tags: OpenAPI tags for the endpoint (default: ["permissions"])

    Returns:
        APIRouter with GET endpoint returning permissions schema

    Example:
        from binauth import get_permissions_router, PermissionsManager

        async def get_current_user(token: str = Header(...)) -> User:
            return await verify_token(token)

        app = FastAPI()
        manager = PermissionsManager([TaskPermissions, UserPermissions])

        # Add protected permissions discovery endpoint
        app.include_router(get_permissions_router(manager, get_current_user))

        # GET /permissions returns categorized schema (requires auth)
    """
    router = APIRouter(tags=tags or ["permissions"])  # type: ignore

    async def get_available_permissions(
        _: object = Depends(get_current_user),
    ) -> list[CategorySchema]:
        """Get all available permission scopes and actions grouped by category."""
        return manager.get_permissions_schema()

    router.add_api_route(path, get_available_permissions, methods=["GET"])

    return router
