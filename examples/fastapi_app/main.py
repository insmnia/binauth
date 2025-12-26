"""
FastAPI example application using binauth.

Run with:
    cd examples/fastapi_app
    uvicorn main:app --reload

Test with:
    # Get all available permissions (requires auth)
    curl -H "X-User-ID: 1" http://localhost:8000/permissions

    # List tasks (requires READ permission)
    curl -H "X-User-ID: 1" http://localhost:8000/tasks

    # Create task (requires CREATE permission - will fail without permission)
    curl -X POST -H "X-User-ID: 1" http://localhost:8000/tasks

    # Grant CREATE permission to user 1
    curl -X POST -H "X-User-ID: 1" \
         -H "Content-Type: application/json" \
         -d '{"scope": "tasks", "actions": ["CREATE"]}' \
         http://localhost:8000/users/1/permissions/grant
"""

from contextlib import asynccontextmanager

from fastapi import FastAPI

from binauth import get_permissions_router, setup_permission_exception_handler
from binauth.models import Base

from .deps import engine, get_current_user
from .permissions import manager
from .routes import router


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Create database tables on startup."""
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield
    await engine.dispose()


app = FastAPI(
    title="binauth Example API",
    description="Example FastAPI application demonstrating binauth permission system",
    version="0.1.0",
    lifespan=lifespan,
)

# Register the permission denied exception handler
setup_permission_exception_handler(app)

# Include permissions discovery endpoint (protected)
app.include_router(get_permissions_router(manager, get_current_user))

# Include routes
app.include_router(router)


@app.get("/")
async def root():
    """Root endpoint."""
    return {
        "message": "binauth Example API",
        "docs": "/docs",
        "usage": "Include X-User-ID header with user ID",
    }
