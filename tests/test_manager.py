"""Tests for PermissionsManager."""

from enum import IntEnum

import pytest

from binauth import (
    PermissionsManager,
    UndefinedActionError,
    UndefinedScopeError,
)


class UserWithPermissions:
    """Test class that implements ObjectWithPermissionField protocol."""

    def __init__(self, permissions: dict[str, int]):
        self.permissions = permissions


class TestPermissionsManager:
    """Tests for PermissionsManager."""

    def test_manager_creation(self, manager, task_permissions, report_permissions):
        """Test manager is created with registries."""
        assert "tasks" in manager.scopes
        assert "reports" in manager.scopes
        assert len(manager.scopes) == 2

    def test_get_registry(self, manager, task_permissions):
        """Test getting a registry by scope name."""
        registry = manager.get_registry("tasks")
        assert registry == task_permissions

    def test_get_registry_undefined_scope(self, manager):
        """Test that undefined scope raises UndefinedScopeError."""
        with pytest.raises(UndefinedScopeError, match="Undefined scope"):
            manager.get_registry("nonexistent")

    def test_get_actions(self, manager, task_permissions):
        """Test getting actions for a scope."""
        actions = manager.get_actions("tasks")
        assert len(actions) == 4
        assert task_permissions.Actions.CREATE in actions

    def test_check_permission_granted(self, manager, task_permissions):
        """Test checking a permission that is granted."""
        user = UserWithPermissions({"tasks": 3})  # CREATE + READ
        Actions = task_permissions.Actions

        assert manager.check_permission(user, "tasks", Actions.CREATE) is True
        assert manager.check_permission(user, "tasks", Actions.READ) is True

    def test_check_permission_denied(self, manager, task_permissions):
        """Test checking a permission that is not granted."""
        user = UserWithPermissions({"tasks": 3})  # CREATE + READ only
        Actions = task_permissions.Actions

        assert manager.check_permission(user, "tasks", Actions.UPDATE) is False
        assert manager.check_permission(user, "tasks", Actions.DELETE) is False

    def test_check_permission_undefined_scope(self, manager, task_permissions):
        """Test that checking permission on undefined scope raises error."""
        user = UserWithPermissions({"tasks": 3})
        Actions = task_permissions.Actions

        with pytest.raises(UndefinedScopeError):
            manager.check_permission(user, "nonexistent", Actions.CREATE)

    def test_check_permission_wrong_action_type(self, manager, task_permissions, report_permissions):
        """Test that using action from wrong scope raises error."""
        user = UserWithPermissions({"tasks": 3, "reports": 1})
        TaskActions = task_permissions.Actions
        ReportActions = report_permissions.Actions

        # Using report action on tasks scope should fail
        with pytest.raises(UndefinedActionError, match="not valid for scope"):
            manager.check_permission(user, "tasks", ReportActions.VIEW)

    def test_check_permission_object_missing_scope(self, manager, task_permissions):
        """Test that object without scope permissions raises error."""
        user = UserWithPermissions({})  # No permissions at all
        Actions = task_permissions.Actions

        with pytest.raises(UndefinedScopeError, match="does not have permissions"):
            manager.check_permission(user, "tasks", Actions.CREATE)

    def test_check_permissions_require_all(self, manager, task_permissions):
        """Test checking multiple permissions with require_all=True."""
        user = UserWithPermissions({"tasks": 7})  # CREATE + READ + UPDATE
        Actions = task_permissions.Actions

        # User has all of CREATE, READ, UPDATE
        assert manager.check_permissions(
            user, "tasks", [Actions.CREATE, Actions.READ], require_all=True
        ) is True

        # User doesn't have DELETE
        assert manager.check_permissions(
            user, "tasks", [Actions.CREATE, Actions.DELETE], require_all=True
        ) is False

    def test_check_permissions_require_any(self, manager, task_permissions):
        """Test checking multiple permissions with require_all=False."""
        user = UserWithPermissions({"tasks": 1})  # Only CREATE
        Actions = task_permissions.Actions

        # User has CREATE
        assert manager.check_permissions(
            user, "tasks", [Actions.CREATE, Actions.DELETE], require_all=False
        ) is True

        # User has neither UPDATE nor DELETE
        assert manager.check_permissions(
            user, "tasks", [Actions.UPDATE, Actions.DELETE], require_all=False
        ) is False

    def test_empty_registries(self):
        """Test manager with no registries."""
        manager = PermissionsManager([])
        assert manager.scopes == []

    def test_all_permissions_value(self, manager, task_permissions):
        """Test that all permissions value works correctly."""
        user = UserWithPermissions({"tasks": task_permissions.all_permissions()})
        Actions = task_permissions.Actions

        for action in Actions:
            assert manager.check_permission(user, "tasks", action) is True

    def test_get_permissions_schema(self, manager):
        """Test getting permissions schema."""
        schema = manager.get_permissions_schema()

        # Should return a list of categories
        assert isinstance(schema, list)
        assert len(schema) >= 1

        # Find the Content category (both tasks and reports are in Content)
        content_category = next((c for c in schema if c["name"] == "Content"), None)
        assert content_category is not None

        # Should have scopes as a list
        assert isinstance(content_category["scopes"], list)
        assert len(content_category["scopes"]) == 2

        # Find tasks scope
        tasks_scope = next((s for s in content_category["scopes"] if s["name"] == "tasks"), None)
        assert tasks_scope is not None
        assert tasks_scope["description"] == "Task management"

        # Check actions are a list with correct structure
        assert isinstance(tasks_scope["actions"], list)
        assert len(tasks_scope["actions"]) == 4

        # Find CREATE action
        create_action = next((a for a in tasks_scope["actions"] if a["name"] == "CREATE"), None)
        assert create_action is not None
        assert create_action["value"] == 1
        assert create_action["description"] == "Create new tasks"

    def test_get_permissions_schema_empty(self):
        """Test getting permissions schema with no registries."""
        manager = PermissionsManager([])
        schema = manager.get_permissions_schema()
        assert schema == []

    def test_get_permissions_schema_default_category(self):
        """Test that scopes without category go to 'General'."""
        from binauth import PermissionActionRegistry

        class NoCategoryPermissions(PermissionActionRegistry):
            scope_name = "nocategory"

            class Actions(IntEnum):
                READ = 1 << 0

        manager = PermissionsManager([NoCategoryPermissions])
        schema = manager.get_permissions_schema()

        assert len(schema) == 1
        assert schema[0]["name"] == "General"
        assert schema[0]["scopes"][0]["name"] == "nocategory"

    def test_get_permissions_schema_missing_description(self):
        """Test that missing action descriptions return empty string."""
        from binauth import PermissionActionRegistry

        class NoDescPermissions(PermissionActionRegistry):
            scope_name = "nodesc"

            class Actions(IntEnum):
                READ = 1 << 0
            # No action_descriptions defined

        manager = PermissionsManager([NoDescPermissions])
        schema = manager.get_permissions_schema()

        action = schema[0]["scopes"][0]["actions"][0]
        assert action["description"] == ""
