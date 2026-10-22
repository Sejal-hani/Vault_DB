"""
Modular API Router Package
Aggregates domain-specific APIRouters: auth, query, audit, approvals, and alerts.
"""

from fastapi import APIRouter

from src.vault_db.api.dependencies import get_engine, set_engine, close_engine, serialize_item
from .auth import router as auth_router
from .query import router as query_router
from .audit import router as audit_router
from .approvals import router as approvals_router
from .alerts import router as alerts_router

api_router = APIRouter(prefix="/api")

# Include all modular domain routers
for sub_router in (auth_router, query_router, audit_router, approvals_router, alerts_router):
    api_router.include_router(sub_router)

# Backwards compatibility aliases
router = api_router
engine = None

__all__ = [
    "api_router",
    "router",
    "get_engine",
    "engine",
    "auth_router",
    "query_router",
    "audit_router",
    "approvals_router",
    "alerts_router",
]
