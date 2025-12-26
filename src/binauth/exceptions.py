"""
Exception classes for the binauth permission system.
"""

from uuid import UUID

from .types import PermissionAction, PermissionScope


class PermissionError(Exception):
    """Base exception for permission-related errors."""

    pass


class PermissionDenied(PermissionError):
    """Raised when a user lacks the required permission."""

    def __init__(
        self,
        scope: PermissionScope,
        action: PermissionAction,
        user_id: int | UUID | str | None = None,
    ):
        self.scope = scope
        self.action = action
        self.action_name = action.name
        self.user_id = user_id

        message = f"Permission denied: {scope}:{action.name}"
        if user_id is not None:
            message += f" for user {user_id}"

        super().__init__(message)


class ScopeError(PermissionError):
    """Base exception for scope-related errors."""

    pass


class UndefinedScopeError(ScopeError):
    """Raised when referencing an undefined permission scope."""

    pass


class UndefinedActionError(ScopeError):
    """Raised when referencing an undefined action for a scope."""

    pass


class TooManyActionsError(PermissionError):
    """Raised when a permission scope has more than MAX_ACTIONS_PER_SCOPE actions."""

    pass


class InvalidActionValueError(PermissionError):
    """Raised when an action value exceeds the allowed bit range."""

    pass
