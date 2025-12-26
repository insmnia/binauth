"""Example routes with permission checks."""

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from binauth import AsyncPermissionRepository

from .deps import get_db, permission
from .permissions import TaskPermissions, UserPermissions, manager

router = APIRouter()


# Task routes with permission checks
@router.get("/tasks")
async def list_tasks(
    user_id: int = Depends(permission.require("tasks", TaskPermissions.Actions.READ)),
):
    """List all tasks. Requires tasks:READ permission."""
    return {
        "message": f"User {user_id} can list tasks",
        "tasks": [
            {"id": 1, "title": "Task 1"},
            {"id": 2, "title": "Task 2"},
        ],
    }


@router.post("/tasks")
async def create_task(
    user_id: int = Depends(permission.require("tasks", TaskPermissions.Actions.CREATE)),
):
    """Create a new task. Requires tasks:CREATE permission."""
    return {"message": f"User {user_id} created a task", "task": {"id": 3, "title": "New Task"}}


@router.delete("/tasks/{task_id}")
async def delete_task(
    task_id: int,
    user_id: int = Depends(permission.require("tasks", TaskPermissions.Actions.DELETE)),
):
    """Delete a task. Requires tasks:DELETE permission."""
    return {"message": f"User {user_id} deleted task {task_id}"}


# Route requiring multiple permissions
@router.put("/tasks/{task_id}")
async def update_task(
    task_id: int,
    user_id: int = Depends(
        permission.require_all(
            "tasks",
            [TaskPermissions.Actions.READ, TaskPermissions.Actions.UPDATE],
        )
    ),
):
    """Update a task. Requires both tasks:READ and tasks:UPDATE permissions."""
    return {"message": f"User {user_id} updated task {task_id}"}


# Permission management routes
@router.post("/users/{target_user_id}/permissions/grant")
async def grant_user_permission(
    target_user_id: int,
    scope: str,
    actions: list[str],
    user_id: int = Depends(permission.require("users", UserPermissions.Actions.MANAGE_PERMISSIONS)),
    db: AsyncSession = Depends(get_db),
):
    """
    Grant permissions to a user.
    Requires users:MANAGE_PERMISSIONS permission.
    """
    repo: AsyncPermissionRepository[int] = AsyncPermissionRepository(db, manager)

    # Get the registry for the scope
    registry = manager.get_registry(scope)

    # Convert action names to enum values
    action_enums = []
    for action_name in actions:
        action = getattr(registry.Actions, action_name, None)
        if action is None:
            return {"error": f"Unknown action: {action_name}"}
        action_enums.append(action)

    await repo.grant_actions(target_user_id, scope, *action_enums)

    # Invalidate cache for the target user
    permission.cache.invalidate(target_user_id)

    return {"message": f"User {user_id} granted {actions} on {scope} to user {target_user_id}"}


@router.get("/users/{target_user_id}/permissions")
async def get_user_permissions(
    target_user_id: int,
    user_id: int = Depends(permission.require("users", UserPermissions.Actions.READ)),
    db: AsyncSession = Depends(get_db),
):
    """
    Get all permissions for a user.
    Requires users:READ permission.
    """
    repo: AsyncPermissionRepository[int] = AsyncPermissionRepository(db, manager)
    permissions = await repo.get_all_user_permissions(target_user_id)

    # Decode permissions to human-readable format
    decoded = {}
    for scope, level in permissions.items():
        try:
            registry = manager.get_registry(scope)
            actions = [action.name for action in registry.Actions if (level & action.value) != 0]
            decoded[scope] = actions
        except Exception:
            decoded[scope] = f"level={level}"

    return {"user_id": target_user_id, "permissions": decoded}
