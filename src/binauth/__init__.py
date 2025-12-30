"""
binauth - Bitwise permission system for Python with SQLAlchemy and FastAPI integration.

Basic usage:
    from enum import IntEnum
    from binauth import PermissionActionRegistry, PermissionsManager

    class TaskPermissions(PermissionActionRegistry):
        scope_name = "tasks"

        class Actions(IntEnum):
            CREATE = 1 << 0
            READ = 1 << 1
            UPDATE = 1 << 2
            DELETE = 1 << 3

    manager = PermissionsManager([TaskPermissions])
"""

__version__ = "0.3.1"

from .exceptions import (
    InvalidActionValueError,
    PermissionDenied,
    PermissionError,
    ScopeError,
    TooManyActionsError,
    UndefinedActionError,
    UndefinedScopeError,
)
from .manager import (
    ActionSchema,
    CategorySchema,
    PermissionsManager,
    ScopeSchema,
)
from .registry import (
    MAX_ACTIONS_PER_SCOPE,
    PermissionActionRegistry,
)
from .types import (
    ModelT,
    PermissionAction,
    PermissionBinLevel,
    PermissionModelProtocol,
    Permissions,
    PermissionScope,
    UserIdT,
)

__all__ = [
    # Version
    "__version__",
    # Types
    "PermissionScope",
    "PermissionAction",
    "PermissionBinLevel",
    "Permissions",
    "UserIdT",
    "ModelT",
    "PermissionModelProtocol",
    # Exceptions
    "PermissionError",
    "PermissionDenied",
    "ScopeError",
    "UndefinedScopeError",
    "UndefinedActionError",
    "TooManyActionsError",
    "InvalidActionValueError",
    # Core classes
    "PermissionActionRegistry",
    "PermissionsManager",
    "MAX_ACTIONS_PER_SCOPE",
    # Schema types
    "ActionSchema",
    "ScopeSchema",
    "CategorySchema",
]

# Optional SQLAlchemy imports
try:
    from .models import Base, UserPermission
    from .repository import AsyncPermissionRepository

    __all__ += ["Base", "UserPermission", "AsyncPermissionRepository"]
except ImportError:
    pass

# Optional FastAPI imports
try:
    from .fastapi import (
        PermissionCache,
        PermissionDependency,
        UserWithId,
        create_permission_dependency,
        get_permissions_router,
        setup_permission_exception_handler,
    )

    __all__ += [
        "PermissionCache",
        "PermissionDependency",
        "UserWithId",
        "create_permission_dependency",
        "get_permissions_router",
        "setup_permission_exception_handler",
    ]
except ImportError:
    pass
