"""
SQLAlchemy models for storing user permissions.

Requires: pip install binauth[db]
"""

from datetime import datetime
from typing import Any

from sqlalchemy import Integer, String
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from .types import PermissionBinLevel, PermissionScope


class Base(DeclarativeBase):
    """
    Base class for SQLAlchemy models.

    If you already have a Base in your application, you can either:
    1. Use this Base for permission models
    2. Create UserPermission using your own Base (copy the model definition)
    """

    pass


class UserPermission(Base):
    """
    Stores permission levels for users by scope.

    Each row represents a user's permission level for a specific scope.
    The level is a bitwise integer where each bit represents an action.

    Note: This model uses Integer for user_id by default. If you need UUID,
    create your own model with the appropriate column type:

        from sqlalchemy.dialects.postgresql import UUID as PG_UUID

        class UserPermission(YourBase):
            __tablename__ = "user_permissions"
            user_id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), primary_key=True)
            scope_name: Mapped[str] = mapped_column(String(100), primary_key=True)
            level: Mapped[int] = mapped_column(Integer, default=0, nullable=False)

    Example:
        user_id=1, scope_name="tasks", level=3  # Binary: 0011 = CREATE + READ
    """

    __tablename__ = "user_permissions"

    user_id: Mapped[Any] = mapped_column(Integer, primary_key=True)
    scope_name: Mapped[PermissionScope] = mapped_column(String(100), primary_key=True)
    level: Mapped[PermissionBinLevel] = mapped_column(Integer, default=0, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        default=datetime.utcnow,
        onupdate=datetime.utcnow,
    )

    def __repr__(self) -> str:
        return f"UserPermission(user_id={self.user_id}, " f"scope_name={self.scope_name!r}, level={self.level})"
