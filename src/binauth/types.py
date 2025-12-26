"""
Type definitions for the binauth permission system.

This module contains all type aliases used throughout the library.
It has no dependencies to avoid circular imports.
"""

from enum import IntEnum
from typing import TypeVar
from uuid import UUID

type PermissionScope = str
type PermissionAction = IntEnum
type PermissionBinLevel = int
type Permissions = dict[PermissionScope, PermissionBinLevel]

# Generic user ID type - can be int, UUID, or str depending on your application
UserIdT = TypeVar("UserIdT", int, UUID, str)
