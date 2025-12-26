"""
Permissions manager for checking permissions against objects.
"""

from enum import IntEnum
from typing import Protocol, TypedDict

from .exceptions import UndefinedActionError, UndefinedScopeError
from .registry import PermissionActionRegistry
from .types import Permissions, PermissionScope


class ActionSchema(TypedDict):
    """Schema for a single action in the permissions schema."""

    name: str
    value: int
    description: str


class ScopeSchema(TypedDict):
    """Schema for a permission scope."""

    name: str
    description: str
    actions: list[ActionSchema]


class CategorySchema(TypedDict):
    """Schema for a category of permission scopes."""

    name: str
    scopes: list[ScopeSchema]


class ObjectWithPermissionField(Protocol):
    """Protocol for objects that have a permissions field."""

    permissions: Permissions


class PermissionsManager:
    """
    Manager for checking permissions against multiple scopes.

    Example:
        manager = PermissionsManager([TaskPermissions, ReportPermissions])

        # Check if user has CREATE permission on tasks
        if manager.check_permission(user, "tasks", TaskPermissions.Actions.CREATE):
            ...
    """

    def __init__(self, registries: list[type[PermissionActionRegistry]]):
        self._registries: dict[PermissionScope, type[PermissionActionRegistry]] = {
            registry.scope_name: registry for registry in registries
        }

    def get_registry(self, scope: PermissionScope) -> type[PermissionActionRegistry]:
        """Get the registry for a scope."""
        registry = self._registries.get(scope)
        if registry is None:
            raise UndefinedScopeError(f"Undefined scope: {scope}")
        return registry

    def get_actions(self, scope: PermissionScope) -> list[IntEnum]:
        """Get all actions for a scope."""
        return self.get_registry(scope).get_actions()

    def check_permission(
        self,
        obj: ObjectWithPermissionField,
        scope: PermissionScope,
        action: IntEnum,
    ) -> bool:
        """Check if an object has a specific permission."""
        registry = self.get_registry(scope)

        if not isinstance(action, registry.Actions):
            raise UndefinedActionError(
                f"Action {action} is not valid for scope '{scope}'. " f"Expected one of: {list(registry.Actions)}"
            )

        obj_permission_level = obj.permissions.get(scope)
        if obj_permission_level is None:
            raise UndefinedScopeError(f"Object does not have permissions for scope: {scope}")

        return (obj_permission_level & action.value) != 0

    def check_permissions(
        self,
        obj: ObjectWithPermissionField,
        scope: PermissionScope,
        actions: list[IntEnum],
        require_all: bool = True,
    ) -> bool:
        """
        Check multiple permissions at once.

        Args:
            obj: Object with permissions field
            scope: Permission scope to check
            actions: List of actions to check
            require_all: If True, all actions must be present. If False, any action suffices.
        """
        if require_all:
            return all(self.check_permission(obj, scope, action) for action in actions)
        return any(self.check_permission(obj, scope, action) for action in actions)

    @property
    def scopes(self) -> list[PermissionScope]:
        """List all registered scopes."""
        return list(self._registries.keys())

    def get_permissions_schema(self) -> list[CategorySchema]:
        """
        Get all registered permissions grouped by category.

        Returns a JSON-serializable schema with categories, scopes, and actions
        including their descriptions. Useful for admin UIs that need to display
        available permissions for granting to users.

        Returns:
            List of categories, each containing scopes with their actions.

        Example:
            [
                {
                    "name": "Content Management",
                    "scopes": [
                        {
                            "name": "tasks",
                            "description": "Task management",
                            "actions": [
                                {"name": "CREATE", "value": 1, "description": "Create new tasks"},
                                {"name": "READ", "value": 2, "description": "View tasks"}
                            ]
                        }
                    ]
                }
            ]
        """
        categories: dict[str, list[ScopeSchema]] = {}

        for scope, registry in self._registries.items():
            category = getattr(registry, "category", "General")
            scope_desc = getattr(registry, "description", "")

            if category not in categories:
                categories[category] = []

            actions: list[ActionSchema] = []
            for action in registry.get_actions():
                actions.append(
                    {
                        "name": action.name,
                        "value": action.value,
                        "description": registry.get_action_description(action.name),
                    }
                )

            categories[category].append(
                {
                    "name": scope,
                    "description": scope_desc,
                    "actions": actions,
                }
            )

        return [{"name": name, "scopes": scopes} for name, scopes in categories.items()]
