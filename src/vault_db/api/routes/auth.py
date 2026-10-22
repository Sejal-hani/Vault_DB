"""
Authentication Routes
Endpoints for user login, 1-click persona demo authentication, logout, and session inspection.
"""

import logging
from typing import Optional
from fastapi import APIRouter, HTTPException, Request, Response, Depends

from src.vault_db.auth.security import verify_password
from src.vault_db.auth.jwt_handler import create_access_token
from src.vault_db.auth.dependencies import get_current_user, AuthenticatedUser
from src.vault_db.api.dependencies import get_engine
from src.vault_db.api.models import LoginRequest, LoginResponse

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/auth", tags=["Authentication"])


@router.post("/login", response_model=LoginResponse)
async def login(req: LoginRequest, response: Response, request: Request):
    """
    Authenticates email and password. Returns signed HS256 JWT and sets secure cookie.
    """
    eng = get_engine()
    user = eng.postgres.get_user_by_email(req.email)

    if not user or not verify_password(req.password, user.get("password_hash", "")):
        raise HTTPException(status_code=401, detail="Invalid email or password.")

    token = create_access_token({
        "sub": user["email"],
        "role": user["role"],
        "name": user.get("full_name", user["email"]),
    })

    response.set_cookie(
        key="vault_session",
        value=token,
        httponly=True,
        samesite="lax",
        max_age=3600,
    )

    return LoginResponse(
        access_token=token,
        email=user["email"],
        role=user["role"],
        full_name=user.get("full_name", user["email"]),
        api_key=user.get("api_key"),
        department=user.get("department", "General"),
    )


@router.post("/demo-login/{persona}", response_model=LoginResponse)
async def demo_login(persona: str, response: Response, request: Request):
    """
    1-Click demo authentication for evaluation.
    Personas: admin, auditor, employee, customer, customer_bob, bob, writer, reader.
    """
    credentials_map = {
        "admin": ("admin@bank.com", "AdminPass123!"),
        "auditor": ("compliance.lead@bank.com", "AuditorPass123!"),
        "employee": ("john@bank.com", "EmployeePass123!"),
        "customer": ("alice@bank.com", "CustomerPass123!"),
        "customer_bob": ("bob@bank.com", "CustomerPass123!"),
        "bob": ("bob@bank.com", "CustomerPass123!"),
        "writer": ("sarah.writer@bank.com", "WriterPass123!"),
        "reader": ("bob.reader@bank.com", "ReaderPass123!"),
        "customer_john": ("john.customer@bank.com", "CustomerPass123!"),
        "customer_sarah": ("sarah.customer@bank.com", "CustomerPass123!"),
    }
    clean_p = persona.lower().strip()
    if clean_p not in credentials_map:
        raise HTTPException(status_code=400, detail=f"Unknown persona '{persona}'. Choose: admin, auditor, employee, customer, customer_bob, bob, writer, reader.")

    email, password = credentials_map[clean_p]
    return await login(LoginRequest(email=email, password=password), response, request)


@router.post("/logout")
async def logout(response: Response, request: Request):
    """Clears authentication session cookie."""
    response.delete_cookie(key="vault_session")
    return {"status": "LOGGED_OUT", "message": "Session invalidated."}


@router.get("/me")
async def get_me(request: Request):
    """Returns currently authenticated user profile or unauthenticated status."""
    try:
        user = await get_current_user(request)
        return {
            "authenticated": True,
            "email": user.email,
            "role": user.role,
            "full_name": user.full_name,
            "api_key": user.api_key,
            "department": user.department,
        }
    except Exception:
        return {"authenticated": False}
