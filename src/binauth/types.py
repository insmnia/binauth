"""
Type definitions for the binauth permission system.

This module contains all type aliases used throughout the library.
It has no dependencies to avoid circular imports.
"""

from enum import IntEnum
from typing import Any, Protocol, TypeVar
from uuid import UUID

type PermissionScope = str
type PermissionAction = IntEnum
type PermissionBinLevel = int
type Permissions = dict[PermissionScope, PermissionBinLevel]

# Generic user ID type - can be int, UUID, or str depending on your application
UserIdT = TypeVar("UserIdT", int, UUID, str)


class PermissionModelProtocol(Protocol):
    """
    Protocol that defines the required interface for permission models.

    Custom permission models must have these attributes:
    - user_id: The user identifier (int, UUID, or str)
    - scope_name: The permission scope name
    - level: The bitwise permission level

    Example custom model:
        class MyPermission(Base):
            __tablename__ = "my_permissions"

            user_id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), primary_key=True)
            scope_name: Mapped[str] = mapped_column(String(100), primary_key=True)
            level: Mapped[int] = mapped_column(Integer, default=0)
            # Additional custom fields...
            tenant_id: Mapped[int] = mapped_column(Integer, nullable=False)
    """

    user_id: Any
    scope_name: PermissionScope
    level: PermissionBinLevel


# Generic model type for permission repositories
ModelT = TypeVar("ModelT", bound=PermissionModelProtocol)
