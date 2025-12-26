# binauth

[![CI](https://github.com/insmnia/binauth/actions/workflows/ci.yml/badge.svg)](https://github.com/insmnia/binauth/actions/workflows/ci.yml)
[![PyPI version](https://badge.fury.io/py/binauth.svg)](https://pypi.org/project/binauth/)

A bitwise permission system for Python with SQLAlchemy and FastAPI integration.

## Features

- Bitwise permission storage (up to 32 actions per scope)
- Type-safe permission definitions using `IntEnum`
- Async SQLAlchemy repository
- FastAPI integration with dependency injection
- Permission discovery endpoint for admin UIs
- TTL-based permission caching
- Generic user ID support (int, UUID, str)

## Installation

### From GitHub

```bash
# Core only
pip install git+https://github.com/insmnia/binauth.git

# With SQLAlchemy support
pip install "binauth[db] @ git+https://github.com/insmnia/binauth.git"

# With FastAPI support
pip install "binauth[fastapi] @ git+https://github.com/insmnia/binauth.git"

# All dependencies
pip install "binauth[all] @ git+https://github.com/insmnia/binauth.git"
```

### From PyPI (when published)

```bash
pip install binauth
pip install binauth[db]       # With SQLAlchemy
pip install binauth[fastapi]  # With FastAPI
pip install binauth[all]      # All dependencies
```

## Quick Start

### Define Permissions

```python
from enum import IntEnum
from typing import ClassVar
from binauth import PermissionActionRegistry, PermissionsManager

class TaskPermissions(PermissionActionRegistry):
    scope_name = "tasks"
    category = "Content Management"  # For grouping in admin UI
    description = "Task management permissions"

    class Actions(IntEnum):
        CREATE = 1 << 0  # 1
        READ = 1 << 1    # 2
        UPDATE = 1 << 2  # 4
        DELETE = 1 << 3  # 8

    # Optional: descriptions for admin UI
    action_descriptions: ClassVar[dict[str, str]] = {
        "CREATE": "Create new tasks",
        "READ": "View tasks",
        "UPDATE": "Edit tasks",
        "DELETE": "Remove tasks",
    }

manager = PermissionsManager([TaskPermissions])
```

### Check Permissions

```python
class User:
    def __init__(self, permissions: dict[PermissionScope, PermissionBinLevel]):
        self.permissions = permissions

# User has CREATE and READ permissions (level = 3)
user = User(permissions={"tasks": 3})

# Check single permission
has_read = manager.check_permission(user, "tasks", TaskPermissions.Actions.READ)

# Check multiple permissions (all required)
has_all = manager.check_permissions(
    user,
    "tasks",
    [TaskPermissions.Actions.READ, TaskPermissions.Actions.UPDATE],
    require_all=True,
)

# Check multiple permissions (any required)
has_any = manager.check_permissions(
    user,
    "tasks",
    [TaskPermissions.Actions.CREATE, TaskPermissions.Actions.DELETE],
    require_all=False,
)
```

### FastAPI Integration

```python
from fastapi import FastAPI, Depends
from binauth import (
    create_permission_dependency,
    get_permissions_router,
    setup_permission_exception_handler,
)

app = FastAPI()
setup_permission_exception_handler(app)

# Option 1: Pass user ID directly
permission = create_permission_dependency(
    manager=manager,
    get_db=get_db,
    get_current_user_id=get_current_user_id,  # Returns int/UUID/str
    cache_ttl=60,
)

# Option 2: Pass user object with .id attribute
permission = create_permission_dependency(
    manager=manager,
    get_db=get_db,
    get_current_user=get_current_user,  # Returns User with .id
    cache_ttl=60,
)

# Protected endpoint
@app.get("/tasks")
async def list_tasks(
    user_id: int = Depends(permission.require("tasks", TaskPermissions.Actions.READ))
):
    return {"tasks": [...]}

# Permission discovery endpoint (for admin UI)
app.include_router(get_permissions_router(manager, get_current_user))
# GET /permissions returns all available permissions grouped by category
```

### Database Storage

```python
from binauth import AsyncPermissionRepository, Base

# Create tables
async with engine.begin() as conn:
    await conn.run_sync(Base.metadata.create_all)

# Use repository
async with async_session() as session:
    repo = AsyncPermissionRepository(session, manager)

    # Grant permissions
    await repo.grant_actions(user_id, "tasks", TaskPermissions.Actions.READ)

    # Check permissions
    has_perm = await repo.has_permission(
        user_id, "tasks", TaskPermissions.Actions.READ
    )

    # Get all user permissions
    perms = await repo.get_all_user_permissions(user_id)
```

### Permission Discovery

Get all available permissions for admin UIs:

```python
schema = manager.get_permissions_schema()
# Returns:
# [
#     {
#         "name": "Content Management",
#         "scopes": [
#             {
#                 "name": "tasks",
#                 "description": "Task management permissions",
#                 "actions": [
#                     {"name": "CREATE", "value": 1, "description": "Create new tasks"},
#                     {"name": "READ", "value": 2, "description": "View tasks"},
#                     ...
#                 ]
#             }
#         ]
#     }
# ]
```

## Limitations

- Maximum 32 actions per scope (uses PostgreSQL INTEGER for storage)
- Action values must be powers of 2 (`1 << n` where `0 <= n <= 31`)
