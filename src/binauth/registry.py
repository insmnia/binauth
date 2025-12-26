"""
Permission registry for defining permission scopes and actions.
"""

from enum import IntEnum
from typing import ClassVar

from .exceptions import InvalidActionValueError, TooManyActionsError

# Maximum number of actions per scope (limited by PostgreSQL INTEGER = 32 bits)
MAX_ACTIONS_PER_SCOPE = 32
MAX_ACTION_BIT_VALUE = 1 << (MAX_ACTIONS_PER_SCOPE - 1)  # 2^31


class PermissionActionRegistry:
    """
    Base class for defining permission scopes with explicit bit positions.

    Subclasses should define:
    - scope_name: str - unique identifier for this permission scope
    - Actions: IntEnum - enum with explicit power-of-2 values for each action

    Optional metadata for admin UI:
    - category: str - category for grouping scopes (default: "General")
    - description: str - human-readable description of the scope
    - action_descriptions: dict[str, str] - descriptions for each action

    Note: Maximum 32 actions per scope (limited by PostgreSQL INTEGER storage).

    Example:
        class TaskPermissions(PermissionActionRegistry):
            scope_name = "tasks"
            category = "Content Management"
            description = "Task management permissions"

            class Actions(IntEnum):
                CREATE = 1 << 0  # 1
                READ   = 1 << 1  # 2
                UPDATE = 1 << 2  # 4
                DELETE = 1 << 3  # 8

            action_descriptions: ClassVar[dict[str, str]] = {
                "CREATE": "Create new tasks",
                "READ": "View task details",
                "UPDATE": "Edit existing tasks",
                "DELETE": "Remove tasks",
            }
    """

    scope_name: str
    Actions: type[IntEnum]
    category: ClassVar[str] = "General"
    description: ClassVar[str] = ""
    action_descriptions: ClassVar[dict[str, str]] = {}

    def __init_subclass__(cls, **kwargs):
        super().__init_subclass__(**kwargs)

        if not hasattr(cls, "Actions"):
            return

        if not issubclass(cls.Actions, IntEnum):
            raise TypeError(f"{cls.__name__}.Actions must be an IntEnum subclass")

        actions = list(cls.Actions)
        action_count = len(actions)

        if action_count > MAX_ACTIONS_PER_SCOPE:
            raise TooManyActionsError(
                f"{cls.__name__} has {action_count} actions, "
                f"but maximum is {MAX_ACTIONS_PER_SCOPE}. "
                f"Consider splitting into multiple scopes."
            )

        for action in actions:
            if action.value > MAX_ACTION_BIT_VALUE:
                raise InvalidActionValueError(
                    f"{cls.__name__}.Actions.{action.name} has value {action.value} "
                    f"(bit position {action.value.bit_length() - 1}), "
                    f"but maximum allowed is {MAX_ACTION_BIT_VALUE} (bit position 31). "
                    f"Use bit positions 0-31 only."
                )
            if action.value <= 0:
                raise InvalidActionValueError(
                    f"{cls.__name__}.Actions.{action.name} has value {action.value}. "
                    f"Action values must be positive powers of 2 (1 << n where n >= 0)."
                )

    @classmethod
    def all_permissions(cls) -> int:
        """Returns a permission level with all actions enabled."""
        return sum(action.value for action in cls.Actions)

    @classmethod
    def combine(cls, *actions: IntEnum) -> int:
        """Combine multiple actions into a single permission level."""
        return sum(action.value for action in actions)

    @classmethod
    def get_actions(cls) -> list[IntEnum]:
        """Returns all actions in this registry."""
        return list(cls.Actions)

    @classmethod
    def get_action_description(cls, action_name: str) -> str:
        """Get description for an action, or empty string if not defined."""
        return cls.action_descriptions.get(action_name, "")
