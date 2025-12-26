"""Tests for FastAPI integration."""

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from binauth import PermissionDenied
from binauth.fastapi import PermissionCache, get_permissions_router


class TestPermissionCache:
    """Tests for PermissionCache."""

    def test_cache_set_and_get(self):
        """Test setting and getting cached permissions."""
        cache: PermissionCache[int] = PermissionCache(ttl_seconds=60)

        cache.set(1, {"tasks": 3, "reports": 1})
        result = cache.get(1)

        assert result == {"tasks": 3, "reports": 1}

    def test_cache_get_nonexistent(self):
        """Test getting non-existent cache entry."""
        cache: PermissionCache[int] = PermissionCache(ttl_seconds=60)

        result = cache.get(999)
        assert result is None

    def test_cache_invalidate(self):
        """Test invalidating a cache entry."""
        cache: PermissionCache[int] = PermissionCache(ttl_seconds=60)

        cache.set(1, {"tasks": 3})
        cache.invalidate(1)

        result = cache.get(1)
        assert result is None

    def test_cache_clear(self):
        """Test clearing all cache entries."""
        cache: PermissionCache[int] = PermissionCache(ttl_seconds=60)

        cache.set(1, {"tasks": 3})
        cache.set(2, {"tasks": 7})
        cache.clear()

        assert cache.get(1) is None
        assert cache.get(2) is None

    def test_cache_disabled_when_ttl_zero(self):
        """Test that caching is disabled when ttl is 0."""
        cache: PermissionCache[int] = PermissionCache(ttl_seconds=0)

        cache.set(1, {"tasks": 3})
        result = cache.get(1)

        assert result is None

    def test_cache_invalidate_nonexistent(self):
        """Test invalidating non-existent entry doesn't raise."""
        cache: PermissionCache[int] = PermissionCache(ttl_seconds=60)
        cache.invalidate(999)  # Should not raise


class TestPermissionDeniedException:
    """Tests for PermissionDenied exception."""

    def test_permission_denied_message(self, task_permissions):
        """Test PermissionDenied exception message."""
        Actions = task_permissions.Actions
        exc = PermissionDenied("tasks", Actions.CREATE, user_id=123)

        assert exc.scope == "tasks"
        assert exc.action == Actions.CREATE
        assert exc.action_name == "CREATE"
        assert exc.user_id == 123
        assert "Permission denied: tasks:CREATE for user 123" in str(exc)

    def test_permission_denied_without_user_id(self, task_permissions):
        """Test PermissionDenied exception without user_id."""
        Actions = task_permissions.Actions
        exc = PermissionDenied("tasks", Actions.CREATE)

        assert exc.user_id is None
        assert "Permission denied: tasks:CREATE" in str(exc)
        assert "for user" not in str(exc)


class TestGetPermissionsRouter:
    """Tests for get_permissions_router function."""

    @staticmethod
    async def mock_get_current_user() -> dict:
        """Mock user dependency for testing."""
        return {"id": 1, "name": "Test User"}

    def test_router_returns_permissions_schema(self, manager):
        """Test that the router endpoint returns permissions schema."""
        app = FastAPI()
        router = get_permissions_router(manager, self.mock_get_current_user)
        app.include_router(router)

        client = TestClient(app)
        response = client.get("/permissions")

        assert response.status_code == 200
        data = response.json()

        # Should be a list of categories
        assert isinstance(data, list)
        assert len(data) >= 1

        # Find Content category
        content = next((c for c in data if c["name"] == "Content"), None)
        assert content is not None
        assert "scopes" in content

    def test_router_custom_path(self, manager):
        """Test router with custom path."""
        app = FastAPI()
        router = get_permissions_router(
            manager, self.mock_get_current_user, path="/api/v1/permissions"
        )
        app.include_router(router)

        client = TestClient(app)

        # Default path should not work
        response = client.get("/permissions")
        assert response.status_code == 404

        # Custom path should work
        response = client.get("/api/v1/permissions")
        assert response.status_code == 200

    def test_router_custom_tags(self, manager):
        """Test router with custom tags."""
        app = FastAPI()
        router = get_permissions_router(
            manager, self.mock_get_current_user, tags=["admin", "permissions"]
        )
        app.include_router(router)

        # Verify router has custom tags
        assert router.tags == ["admin", "permissions"]

    def test_router_schema_structure(self, manager):
        """Test the complete structure of the schema response."""
        app = FastAPI()
        router = get_permissions_router(manager, self.mock_get_current_user)
        app.include_router(router)

        client = TestClient(app)
        response = client.get("/permissions")
        data = response.json()

        # Find tasks scope
        content = next((c for c in data if c["name"] == "Content"), None)
        tasks = next((s for s in content["scopes"] if s["name"] == "tasks"), None)

        assert tasks is not None
        assert tasks["description"] == "Task management"
        assert isinstance(tasks["actions"], list)

        # Verify action structure
        create_action = next((a for a in tasks["actions"] if a["name"] == "CREATE"), None)
        assert create_action is not None
        assert "name" in create_action
        assert "value" in create_action
        assert "description" in create_action
        assert create_action["value"] == 1
        assert create_action["description"] == "Create new tasks"

    def test_router_requires_authentication(self, manager):
        """Test that router requires authentication dependency."""
        from fastapi import Header, HTTPException

        async def get_user_from_header(x_user_id: int = Header(...)) -> dict:
            if x_user_id <= 0:
                raise HTTPException(status_code=401, detail="Invalid user")
            return {"id": x_user_id}

        app = FastAPI()
        router = get_permissions_router(manager, get_user_from_header)
        app.include_router(router)

        client = TestClient(app)

        # Request without header should fail
        response = client.get("/permissions")
        assert response.status_code == 422  # Missing required header

        # Request with valid header should succeed
        response = client.get("/permissions", headers={"X-User-ID": "1"})
        assert response.status_code == 200
