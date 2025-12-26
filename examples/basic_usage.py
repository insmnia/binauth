"""
Basic usage example for binauth.

This example shows how to use the core permission system without a database.
"""

import json
from enum import IntEnum
from typing import ClassVar

from binauth import PermissionActionRegistry, PermissionsManager


# Define permission scopes with metadata
class TaskPermissions(PermissionActionRegistry):
    """Permissions for task operations."""

    scope_name = "tasks"
    category = "Content Management"
    description = "Manage tasks and todo items"

    class Actions(IntEnum):
        CREATE = 1 << 0  # 1
        READ = 1 << 1  # 2
        UPDATE = 1 << 2  # 4
        DELETE = 1 << 3  # 8

    action_descriptions: ClassVar[dict[str, str]] = {
        "CREATE": "Create new tasks",
        "READ": "View task details",
        "UPDATE": "Edit existing tasks",
        "DELETE": "Remove tasks",
    }


class ReportPermissions(PermissionActionRegistry):
    """Permissions for report operations."""

    scope_name = "reports"
    category = "Content Management"
    description = "Manage reports"

    class Actions(IntEnum):
        VIEW = 1 << 0  # 1
        EXPORT = 1 << 1  # 2
        CREATE = 1 << 2  # 4

    action_descriptions: ClassVar[dict[str, str]] = {
        "VIEW": "View reports",
        "EXPORT": "Export reports to file",
        "CREATE": "Create new reports",
    }


# Create a user class with permissions
class User:
    def __init__(self, name: str, permissions: dict[str, int]):
        self.name = name
        self.permissions = permissions


def main():
    # Create the permissions manager
    manager = PermissionsManager([TaskPermissions, ReportPermissions])

    # Create users with different permission levels
    admin = User(
        name="Admin",
        permissions={
            "tasks": TaskPermissions.all_permissions(),  # All task permissions
            "reports": ReportPermissions.all_permissions(),  # All report permissions
        },
    )

    editor = User(
        name="Editor",
        permissions={
            "tasks": TaskPermissions.combine(
                TaskPermissions.Actions.CREATE,
                TaskPermissions.Actions.READ,
                TaskPermissions.Actions.UPDATE,
            ),
            "reports": ReportPermissions.Actions.VIEW,  # Only view
        },
    )

    viewer = User(
        name="Viewer",
        permissions={
            "tasks": TaskPermissions.Actions.READ,
            "reports": ReportPermissions.Actions.VIEW,
        },
    )

    # Check permissions
    print("=== Permission Checks ===\n")

    for user in [admin, editor, viewer]:
        print(f"{user.name}:")

        # Task permissions
        for action in TaskPermissions.Actions:
            has_perm = manager.check_permission(user, "tasks", action)
            status = "✓" if has_perm else "✗"
            print(f"  tasks:{action.name}: {status}")

        # Report permissions
        for action in ReportPermissions.Actions:
            has_perm = manager.check_permission(user, "reports", action)
            status = "✓" if has_perm else "✗"
            print(f"  reports:{action.name}: {status}")

        print()

    # Check multiple permissions at once
    print("=== Batch Permission Checks ===\n")

    # Check if editor can both create and delete tasks
    can_create_and_delete = manager.check_permissions(
        editor,
        "tasks",
        [TaskPermissions.Actions.CREATE, TaskPermissions.Actions.DELETE],
        require_all=True,
    )
    print(f"Editor can CREATE and DELETE tasks: {can_create_and_delete}")

    # Check if editor can create OR delete tasks
    can_create_or_delete = manager.check_permissions(
        editor,
        "tasks",
        [TaskPermissions.Actions.CREATE, TaskPermissions.Actions.DELETE],
        require_all=False,
    )
    print(f"Editor can CREATE or DELETE tasks: {can_create_or_delete}")

    # Get permissions schema (useful for admin UIs)
    print("\n=== Permissions Schema (for Admin UI) ===\n")
    schema = manager.get_permissions_schema()
    print(json.dumps(schema, indent=2))


if __name__ == "__main__":
    main()
