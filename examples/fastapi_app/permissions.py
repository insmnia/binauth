"""Permission definitions for the FastAPI example app."""

from enum import IntEnum
from typing import ClassVar

from binauth import PermissionActionRegistry, PermissionsManager


class TaskPermissions(PermissionActionRegistry):
    """Permissions for task operations."""

    scope_name = "tasks"
    category = "Content Management"
    description = "Manage tasks and todo items"

    class Actions(IntEnum):
        CREATE = 1 << 0
        READ = 1 << 1
        UPDATE = 1 << 2
        DELETE = 1 << 3

    action_descriptions: ClassVar[dict[str, str]] = {
        "CREATE": "Create new tasks",
        "READ": "View task details and list",
        "UPDATE": "Edit existing tasks",
        "DELETE": "Remove tasks permanently",
    }


class UserPermissions(PermissionActionRegistry):
    """Permissions for user management operations."""

    scope_name = "users"
    category = "Administration"
    description = "Manage user accounts"

    class Actions(IntEnum):
        READ = 1 << 0
        UPDATE = 1 << 1
        DELETE = 1 << 2
        MANAGE_PERMISSIONS = 1 << 3

    action_descriptions: ClassVar[dict[str, str]] = {
        "READ": "View user profiles",
        "UPDATE": "Edit user information",
        "DELETE": "Delete user accounts",
        "MANAGE_PERMISSIONS": "Grant or revoke user permissions",
    }


# Create the global permissions manager
manager = PermissionsManager([TaskPermissions, UserPermissions])
