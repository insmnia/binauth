"""Tests for PermissionActionRegistry."""

from enum import IntEnum

import pytest

from binauth import (
    InvalidActionValueError,
    PermissionActionRegistry,
    TooManyActionsError,
    MAX_ACTIONS_PER_SCOPE,
)


class TestPermissionActionRegistry:
    """Tests for PermissionActionRegistry validation and methods."""

    def test_valid_registry_creation(self, task_permissions):
        """Test that a valid registry is created successfully."""
        assert task_permissions.scope_name == "tasks"
        assert len(list(task_permissions.Actions)) == 4

    def test_actions_must_be_intenum(self):
        """Test that Actions must be an IntEnum subclass."""
        with pytest.raises(TypeError, match="must be an IntEnum subclass"):

            class InvalidPermissions(PermissionActionRegistry):
                scope_name = "invalid"

                class Actions:  # Not an IntEnum!
                    READ = 1

    def test_too_many_actions_error(self):
        """Test that more than 32 actions raises TooManyActionsError."""
        with pytest.raises(TooManyActionsError) as exc_info:
            # Create a class with 33 actions dynamically
            actions_dict = {f"ACTION_{i}": 1 << i for i in range(33)}
            actions_enum = IntEnum("Actions", actions_dict)

            class TooManyPermissions(PermissionActionRegistry):
                scope_name = "toomany"
                Actions = actions_enum

        assert "33 actions" in str(exc_info.value)
        assert f"maximum is {MAX_ACTIONS_PER_SCOPE}" in str(exc_info.value)

    def test_action_value_too_high(self):
        """Test that action values beyond bit 31 raise InvalidActionValueError."""
        with pytest.raises(InvalidActionValueError) as exc_info:

            class HighBitPermissions(PermissionActionRegistry):
                scope_name = "highbit"

                class Actions(IntEnum):
                    VALID = 1 << 0
                    INVALID = 1 << 32  # bit 32 is too high

        assert "bit position 32" in str(exc_info.value)
        assert "bit position 31" in str(exc_info.value)

    def test_action_value_zero(self):
        """Test that zero action values raise InvalidActionValueError."""
        with pytest.raises(InvalidActionValueError) as exc_info:

            class ZeroPermissions(PermissionActionRegistry):
                scope_name = "zero"

                class Actions(IntEnum):
                    ZERO = 0

        assert "value 0" in str(exc_info.value)
        assert "positive powers of 2" in str(exc_info.value)

    def test_action_value_negative(self):
        """Test that negative action values raise InvalidActionValueError."""
        with pytest.raises(InvalidActionValueError) as exc_info:

            class NegativePermissions(PermissionActionRegistry):
                scope_name = "negative"

                class Actions(IntEnum):
                    NEGATIVE = -1

        assert "value -1" in str(exc_info.value)

    def test_all_permissions(self, task_permissions):
        """Test all_permissions returns sum of all action values."""
        expected = 1 + 2 + 4 + 8  # CREATE + READ + UPDATE + DELETE
        assert task_permissions.all_permissions() == expected

    def test_combine(self, task_permissions):
        """Test combine method combines action values with OR."""
        Actions = task_permissions.Actions
        combined = task_permissions.combine(Actions.CREATE, Actions.READ)
        assert combined == 3  # 1 | 2 = 3

    def test_get_actions(self, task_permissions):
        """Test get_actions returns list of all actions."""
        actions = task_permissions.get_actions()
        assert len(actions) == 4
        assert task_permissions.Actions.CREATE in actions
        assert task_permissions.Actions.DELETE in actions

    def test_max_valid_actions(self):
        """Test that exactly 32 actions is allowed."""
        actions_dict = {f"ACTION_{i}": 1 << i for i in range(32)}
        actions_enum = IntEnum("Actions", actions_dict)

        class MaxPermissions(PermissionActionRegistry):
            scope_name = "max"
            Actions = actions_enum

        assert len(list(MaxPermissions.Actions)) == 32
        assert MaxPermissions.all_permissions() == (1 << 32) - 1
