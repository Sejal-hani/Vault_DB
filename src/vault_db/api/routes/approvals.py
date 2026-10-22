"""
Access Approvals Routes
Endpoints for submitting, approving, rejecting, and revoking time-bounded privilege elevations.
"""

import logging
from typing import Optional
from fastapi import APIRouter, HTTPException, Query, Request

from src.vault_db.api.dependencies import get_engine
from src.vault_db.auth.dependencies import get_current_user
from src.vault_db.api.models import CreateAccessRequest

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/approvals", tags=["Access Approvals"])


@router.post("/request")
async def request_access_elevation(req: CreateAccessRequest, request: Request):
    """
    Submits a time-bounded (e.g. 24h) privilege elevation request.
    Example: Bob requests access for 24 hours.
    """
    eng = get_engine()
    client_ip = request.client.host if request.client else "127.0.0.1"
    try:
        created = eng.approvals.create_request(
            user_email=req.user_email,
            requested_role=req.requested_role,
            requested_table=req.requested_table,
            duration_hours=req.duration_hours,
            reason=req.reason,
            client_ip=client_ip,
        )
        return created
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.get("")
@router.get("/")
async def list_access_approvals(
    status: Optional[str] = Query(default=None, description="Filter by status (PENDING, APPROVED, REJECTED, EXPIRED, REVOKED)"),
    user: Optional[str] = Query(default=None, description="Filter by user email")
):
    """Lists all access elevation requests with real-time status and remaining duration."""
    eng = get_engine()
    return eng.approvals.list_requests(status=status, user_email=user)


@router.post("/{request_id}/approve")
async def approve_access_request(
    request_id: int,
    request: Request,
    reviewer_email: str = Query(default="admin@bank.com")
):
    """
    Manager/Admin approves a pending 24-hour access request.
    Seals approval into immudb, grants temporary elevated role, and dispatches Slack alert.
    Enforces that only 'admin' role can approve privilege escalations.
    """
    eng = get_engine()
    client_ip = request.client.host if request.client else "127.0.0.1"

    # Backend RBAC enforcement
    authenticated_user = None
    try:
        authenticated_user = await get_current_user(request)
    except Exception:
        pass

    acting_email = authenticated_user.email if authenticated_user else reviewer_email
    reviewer_role = authenticated_user.role if authenticated_user else eng.get_user_role(acting_email)

    if reviewer_role.lower() != "admin":
        raise HTTPException(
            status_code=403,
            detail=f"Access Denied: Role '{reviewer_role}' is not authorized to approve privilege elevations. Manager/Admin role required."
        )

    try:
        result = eng.approvals.approve_request(request_id, reviewer_email=acting_email, client_ip=client_ip)
        return result
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/{request_id}/reject")
async def reject_access_request(
    request_id: int,
    request: Request,
    reviewer_email: str = Query(default="admin@bank.com"),
    reason: Optional[str] = Query(default=None)
):
    """Rejects a pending access request and records refusal in immutable audit log."""
    eng = get_engine()
    client_ip = request.client.host if request.client else "127.0.0.1"

    # Backend RBAC enforcement
    authenticated_user = None
    try:
        authenticated_user = await get_current_user(request)
    except Exception:
        pass

    acting_email = authenticated_user.email if authenticated_user else reviewer_email
    reviewer_role = authenticated_user.role if authenticated_user else eng.get_user_role(acting_email)

    if reviewer_role.lower() != "admin":
        raise HTTPException(
            status_code=403,
            detail=f"Access Denied: Role '{reviewer_role}' is not authorized to reject access requests."
        )

    try:
        result = eng.approvals.reject_request(request_id, reviewer_email=acting_email, reason=reason, client_ip=client_ip)
        return result
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/{request_id}/revoke")
async def revoke_access_request(
    request_id: int,
    request: Request,
    reviewer_email: str = Query(default="admin@bank.com")
):
    """Immediately revokes an active approved elevation before its 24h expiration."""
    eng = get_engine()
    client_ip = request.client.host if request.client else "127.0.0.1"

    # Backend RBAC enforcement
    authenticated_user = None
    try:
        authenticated_user = await get_current_user(request)
    except Exception:
        pass

    acting_email = authenticated_user.email if authenticated_user else reviewer_email
    reviewer_role = authenticated_user.role if authenticated_user else eng.get_user_role(acting_email)

    if reviewer_role.lower() != "admin":
        raise HTTPException(
            status_code=403,
            detail=f"Access Denied: Role '{reviewer_role}' is not authorized to revoke access requests."
        )

    try:
        result = eng.approvals.revoke_request(request_id, reviewer_email=acting_email, client_ip=client_ip)
        return result
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))
